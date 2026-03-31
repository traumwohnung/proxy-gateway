import type { SessionInfo, UsageFilter, UsageResponse, VerifyResult } from "./types";

export interface ProxyGatewayClientOptions {
    /** Base URL of the proxy-gateway, e.g. "http://proxy-gateway:8100" */
    baseUrl: string;
    /** Static API key for authentication (Bearer token) */
    apiKey?: string;
    /** Getter for auth token. Called on every request. Takes precedence over apiKey. */
    getToken?: () => string | null;
    /** Request timeout in ms (default: 10000) */
    timeout?: number;
}

export class ProxyGatewayClient {
    private baseUrl: string;
    private getToken: () => string | null;
    private timeout: number;

    constructor(opts: ProxyGatewayClientOptions) {
        this.baseUrl = opts.baseUrl.replace(/\/$/, "");
        this.getToken = opts.getToken ?? (opts.apiKey ? () => opts.apiKey! : () => null);
        this.timeout = opts.timeout ?? 10_000;
    }

    private async fetch<T>(path: string, opts?: { method?: string }): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeout);

        const headers: Record<string, string> = {};
        const token = this.getToken();
        if (token) {
            headers.Authorization = `Bearer ${token}`;
        }

        try {
            const res = await fetch(url, {
                method: opts?.method ?? "GET",
                signal: controller.signal,
                headers,
            });
            if (!res.ok) {
                const body = await res.text().catch(() => "");
                throw new Error(`proxy-gateway ${res.status}: ${body}`);
            }
            return (await res.json()) as T;
        } finally {
            clearTimeout(timer);
        }
    }

    /**
     * Verify a proxy username before a session is created.
     * Checks that the username is parseable, the proxy set exists, and the
     * upstream proxy is reachable and returns a valid outbound IP.
     * Does not create any affinity entry.
     */
    async verifyUsername(username: string): Promise<VerifyResult> {
        return this.fetch<VerifyResult>(`/api/verify/${encodeURIComponent(username)}`);
    }

    /**
     * Force-rotate the upstream proxy for an existing session.
     *
     * Immediately reassigns the upstream proxy via least-used selection and
     * resets the session TTL. The session ID, metadata, and duration are
     * preserved. Use this to escape a bad or slow proxy without losing session
     * continuity.
     *
     * Returns null if no active session exists for this username.
     */
    async forceRotate(username: string): Promise<SessionInfo | null> {
        try {
            return await this.fetch<SessionInfo>(`/api/sessions/${encodeURIComponent(username)}/rotate`, {
                method: "POST",
            });
        } catch (err) {
            if (err instanceof Error && err.message.includes("404")) return null;
            throw err;
        }
    }

    /**
     * List all active sticky sessions across all proxy sets.
     * Sessions with 0 minutes (no affinity) are not tracked.
     */
    async listSessions(): Promise<SessionInfo[]> {
        return this.fetch<SessionInfo[]>("/api/sessions");
    }

    /**
     * Get a specific active session by its username.
     * Returns null if no active session exists for that username.
     */
    async getSession(username: string): Promise<SessionInfo | null> {
        try {
            return await this.fetch<SessionInfo>(`/api/sessions/${encodeURIComponent(username)}`);
        } catch (err) {
            if (err instanceof Error && err.message.includes("404")) return null;
            throw err;
        }
    }

    /**
     * Query aggregated bandwidth usage with optional filtering and pagination.
     *
     * @example
     * // Total bytes per proxy set for January 2026
     * const result = await client.queryUsage({
     *   from: "2026-01-01T00:00:00Z",
     *   to:   "2026-01-31T23:59:59Z",
     *   granularity: "proxyset",
     * });
     *
     * @example
     * // Hourly usage for a specific user
     * const result = await client.queryUsage({
     *   meta: JSON.stringify({ user: "alice" }),
     *   granularity: "hour",
     *   pageSize: 48,
     * });
     */
    async queryUsage(filter: UsageFilter = {}): Promise<UsageResponse> {
        const params = new URLSearchParams();
        if (filter.from) params.set("from", filter.from);
        if (filter.to) params.set("to", filter.to);
        if (filter.proxyset) params.set("proxyset", filter.proxyset);
        if (filter.meta) params.set("meta", filter.meta);
        if (filter.granularity) params.set("granularity", filter.granularity);
        if (filter.page != null) params.set("page", String(filter.page));
        if (filter.pageSize != null) params.set("page_size", String(filter.pageSize));

        const qs = params.size > 0 ? `?${params.toString()}` : "";
        return this.fetch<UsageResponse>(`/api/usage${qs}`);
    }
}
