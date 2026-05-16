import { ProxyClient } from "./proxy_client";
import { scriptRef, scriptSource } from "./types";
import type { HTTPCloakSpec, ScriptEntry, SessionInfo, SessionMeta, SessionParams } from "./types";

/**
 * Fluent builder for a single proxy-gateway proxy configuration. From it
 * you can:
 *
 *   - `buildUsername`    — base64 username only
 *   - `buildUrl`         — full http://user:x@host:port URL
 *   - `buildFetch`       — `fetch`-like function that routes through the proxy
 *   - `rotate`           — re-roll the rotation via the admin API
 *   - `retry` / `retryN` — see retry helpers below
 *
 * Calling `buildUsername()` with identical configuration always produces the
 * same base64 username — building the same configuration twice does not change
 * any rotation state, which keeps sessions stable across processes.
 */
export class ProxyConfiguration {
    private params: {
        set: string;
        minutes: number;
        sessionParams: SessionParams;
        sessionMeta: SessionMeta;
        httpcloak?: HTTPCloakSpec;
        scripts: ScriptEntry[];
    };
    private client: ProxyClient | null = null;

    constructor(set: string) {
        this.params = { set, minutes: 0, sessionParams: {}, sessionMeta: {}, scripts: [] };
    }

    /**
     * Returns a deep copy of this configuration. The session_params,
     * session_meta, and scripts collections are copied so further mutations on
     * the clone do not affect the original. The bound `ProxyClient` reference
     * is shared.
     */
    clone(): ProxyConfiguration {
        const cp = new ProxyConfiguration(this.params.set);
        cp.params = {
            set: this.params.set,
            minutes: this.params.minutes,
            sessionParams: { ...this.params.sessionParams },
            sessionMeta: { ...this.params.sessionMeta },
            httpcloak: this.params.httpcloak,
            scripts: [...this.params.scripts],
        };
        cp.client = this.client;
        return cp;
    }

    minutes(n: number): this {
        this.params.minutes = n;
        return this;
    }

    /**
     * Add a key/value to session_params. Two configurations with the same
     * set + same session_params share an upstream IP on the gateway.
     */
    sessionParams(key: string, value: string): this {
        this.params.sessionParams[key] = value;
        return this;
    }

    /**
     * Add a key/value to session_meta. Informational only — never affects
     * session identity or IP selection; carried through to the analytics
     * service for filtering/grouping.
     */
    sessionMeta(key: string, value: string): this {
        this.params.sessionMeta[key] = value;
        return this;
    }

    httpcloak(spec: HTTPCloakSpec): this {
        this.params.httpcloak = spec;
        return this;
    }

    /**
     * Append entries to the ordered chain of Starlark scripts evaluated
     * server-side on the MITM'd response. Bare strings are treated as
     * `{ ref: name }`. Requires `httpcloak` to be set.
     *
     * @example
     * cfg.scripts("antibot", { source: "def response_bailing(r): return None" });
     */
    scripts(...entries: (string | ScriptEntry)[]): this {
        for (const e of entries) {
            this.params.scripts.push(typeof e === "string" ? scriptRef(e) : e);
        }
        return this;
    }

    /** Convenience for `cfg.scripts(scriptRef(name))`. */
    scriptRef(name: string): this {
        this.params.scripts.push(scriptRef(name));
        return this;
    }

    /** Convenience for `cfg.scripts(scriptSource(src))`. */
    scriptSource(src: string): this {
        this.params.scripts.push(scriptSource(src));
        return this;
    }

    /**
     * Remove any previously appended scripts. Useful when cloning a base
     * configuration that already has scripts but wanting an explicit "no
     * scripts" override (which suppresses the per-set default on the gateway).
     */
    clearScripts(): this {
        this.params.scripts = [];
        return this;
    }

    /**
     * Attach the gateway connection (proxy endpoint + admin API). Required
     * for `buildUrl`, `buildFetch`, `rotate`, and the retry primitives.
     */
    withProxyClient(c: ProxyClient): this {
        this.client = c;
        return this;
    }

    buildUsername(): string {
        const payload: Record<string, unknown> = {
            set: this.params.set,
            minutes: this.params.minutes,
            session_params: this.params.sessionParams,
        };
        if (Object.keys(this.params.sessionMeta).length > 0) {
            payload.session_meta = this.params.sessionMeta;
        }
        if (this.params.httpcloak !== undefined) {
            payload.httpcloak = this.params.httpcloak;
        }
        if (this.params.scripts.length > 0) {
            payload.scripts = this.params.scripts;
        }
        return btoa(JSON.stringify(payload));
    }

    /** Full proxy URL: `http://<username>:x@<host>:<port>`. */
    buildUrl(): string {
        if (!this.client) {
            throw new Error("ProxyConfiguration.buildUrl requires withProxyClient");
        }
        const host = this.client.proxyHost();
        const port = this.client.proxyPort();
        if (!host || !port) {
            throw new Error("ProxyConfiguration: ProxyClient is missing proxy host:port");
        }
        return `http://${this.buildUsername()}:x@${host}:${port}`;
    }

    /**
     * Returns a `fetch`-like function that routes requests through this
     * configuration's proxy URL. Uses Bun's `fetch` `proxy` option; on
     * runtimes without it the `proxy` option is ignored and the request
     * goes directly.
     */
    buildFetch(): (input: string | URL | Request, init?: RequestInit) => Promise<Response> {
        const url = this.buildUrl();
        return (input, init) => fetch(input, { ...init, proxy: url } as RequestInit & { proxy: string });
    }

    /** Alias for `buildFetch` — kept to mirror the Go SDK's `BuildHTTPClient`. */
    buildHttpClient(): (input: string | URL | Request, init?: RequestInit) => Promise<Response> {
        return this.buildFetch();
    }

    /**
     * Call the gateway admin API to re-roll the rotation for the current
     * username. The username itself does not change. Requires a `ProxyClient`
     * with admin endpoint configured.
     */
    async rotate(): Promise<SessionInfo | null> {
        if (!this.client) {
            throw new Error("ProxyConfiguration.rotate requires withProxyClient");
        }
        const admin = this.client.adminClient();
        if (!admin) {
            throw new Error("ProxyConfiguration.rotate requires admin endpoint configured on ProxyClient");
        }
        return admin.rotateNow(this.buildUsername());
    }

    /**
     * Run `fn` repeatedly, calling `.rotate()` between attempts that return
     * `null`/`undefined`. Closure tracks its own give-up logic — return a
     * value to stop the loop. Use `retryN` for a bounded loop.
     */
    async retry<T>(fn: (attempt: number) => Promise<T | null | undefined>): Promise<T> {
        for (let attempt = 0; ; attempt++) {
            const v = await fn(attempt);
            if (v != null) return v;
            await this.rotate();
        }
    }

    /**
     * `retry` with a built-in attempt cap. `fn` is called with `i` in
     * `[0, maxRetries)`. Between attempts that return null/undefined,
     * `.rotate()` is called. The loop ends when `fn` returns a value (early
     * exit) or when `i` has reached `maxRetries`.
     */
    async retryN<T>(
        maxRetries: number,
        fn: (i: number) => Promise<T | null | undefined>,
    ): Promise<T | null | undefined> {
        let last: T | null | undefined = null;
        for (let i = 0; i < maxRetries; i++) {
            const v = await fn(i);
            last = v;
            if (v != null) return v;
            if (i + 1 >= maxRetries) break;
            await this.rotate();
        }
        return last;
    }
}
