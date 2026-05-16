import { z } from "zod";

/**
 * Flat JSON object that forms the session identity key. Two requests with
 * the same set + same session_params share an upstream IP / session on the
 * gateway. All values are strings.
 */
export const sessionParamsSchema = z.record(z.string(), z.string());
export type SessionParams = Record<string, string>;

/**
 * Flat JSON object carrying informational metadata. Does NOT affect session
 * identity or IP selection — same session_params + different session_meta =
 * same upstream IP. Carried through to the analytics service for filtering
 * and grouping (tenant, campaign, request_id, …). All values are strings.
 */
export const sessionMetaSchema = z.record(z.string(), z.string());
export type SessionMeta = Record<string, string>;

export const sessionInfoSchema = z.object({
    /** Internal session ID, assigned at creation (starts at 0, increments per session). */
    session_id: z.number().int().nonnegative(),
    /** The raw base64 username string used as the affinity key. */
    username: z.string(),
    /** The proxy set name. */
    proxy_set: z.string(),
    /** The upstream proxy address (host:port). */
    upstream: z.string(),
    /** Session creation time — never changes (ISO 8601 UTC). */
    created_at: z.string(),
    /** When the current proxy assignment expires (ISO 8601 UTC). Reset on rotate_now. */
    next_rotation_at: z.string(),
    /** When the proxy was last assigned — equals created_at unless rotate_now was called (ISO 8601 UTC). */
    last_rotation_at: z.string(),
    /** The decoded metadata object from the username JSON. Values are coerced to string. */
    metadata: z.record(z.string(), z.union([z.string(), z.number()]).transform(String)),
});

export type SessionInfo = z.infer<typeof sessionInfoSchema>;

export const apiErrorSchema = z.object({
    error: z.string(),
});

export type ApiError = z.infer<typeof apiErrorSchema>;

export const verifyResultSchema = z.object({
    /** Whether all checks passed. */
    ok: z.boolean(),
    /** The proxy set name parsed from the username. */
    proxy_set: z.string(),
    /** Affinity minutes parsed from the username. */
    minutes: z.number().int().nonnegative(),
    /** The decoded metadata object. */
    metadata: z.record(z.string(), z.union([z.string(), z.number()]).transform(String)),
    /** The upstream proxy that would be used (host:port). */
    upstream: z.string(),
    /** The outbound IP address fetched through the proxy. Empty string when ok=false. */
    ip: z.string(),
    /** Error message if any check failed, absent when ok=true. */
    error: z.string().optional(),
});

export type VerifyResult = z.infer<typeof verifyResultSchema>;

// ---------------------------------------------------------------------------
// HTTPCloak types
// ---------------------------------------------------------------------------

/**
 * Configures TLS fingerprint spoofing via MITM.
 * For simple cases, pass a preset name string (e.g. "chrome-latest") instead.
 */
export interface HTTPCloakSpec {
    /** Browser fingerprint preset (e.g. "chrome-latest", "firefox-latest"). */
    preset: string;
    /** User-Agent handling: "ignore" (default), "preset", or "check". */
    user_agent?: "ignore" | "preset" | "check";
    /** Override the preset's TLS fingerprint (advanced). */
    ja3?: string;
    /** Override the preset's HTTP/2 fingerprint (advanced). */
    akamai?: string;
    /**
     * Encrypted Client Hello (hides SNI from network observers):
     *   true (default) — auto-fetch ECH config from DNS
     *   false — disable ECH
     *   "domain" — fetch ECH config from this domain instead of target
     */
    ech?: boolean | string;
}

// ---------------------------------------------------------------------------
// Username construction helpers
// ---------------------------------------------------------------------------

export interface BuildProxyUsernameOptions {
    proxySet: string;
    /** Session duration (0 = new proxy per request, 1–1440 = sticky). */
    minutes: number;
    /** Session identity. Same set + same sessionParams = same upstream IP. */
    sessionParams: SessionParams;
    /** Informational metadata. Does NOT affect IP selection. */
    sessionMeta?: SessionMeta;
    /** Enable TLS fingerprint spoofing. */
    httpcloak?: HTTPCloakSpec;
}

/**
 * Build the proxy-gateway username — a base64-encoded JSON object.
 * Pure and synchronous — no verification. Use `buildAndVerifyProxyUsername`
 * to also verify that the proxy set exists and the upstream is reachable.
 *
 * @example
 * // Identity only — same upstream IP for all calls with these params
 * buildProxyUsername({ proxySet: "residential", minutes: 60, sessionParams: { user: "alice" } })
 *
 * // With informational meta for analytics — same IP as above
 * buildProxyUsername({
 *   proxySet: "residential",
 *   minutes: 60,
 *   sessionParams: { user: "alice" },
 *   sessionMeta: { tenant: "acme", campaign: "spring" },
 * })
 *
 * // With httpcloak
 * buildProxyUsername({
 *   proxySet: "direct",
 *   minutes: 0,
 *   sessionParams: {},
 *   httpcloak: { preset: "chrome-latest", user_agent: "preset" },
 * })
 */
export function buildProxyUsername(opts: BuildProxyUsernameOptions): string {
    const payload: Record<string, unknown> = {
        set: opts.proxySet,
        minutes: opts.minutes,
        session_params: opts.sessionParams,
    };
    if (opts.sessionMeta !== undefined && Object.keys(opts.sessionMeta).length > 0) {
        payload.session_meta = opts.sessionMeta;
    }
    if (opts.httpcloak !== undefined) {
        payload.httpcloak = opts.httpcloak;
    }
    const json = JSON.stringify(payload);
    return btoa(json);
}

/**
 * Decode a proxy-gateway username back into its components.
 * Returns `null` if the string cannot be decoded or parsed.
 */
export function parseProxyUsername(username: string): {
    proxySet: string;
    minutes: number;
    sessionParams: SessionParams;
    sessionMeta?: SessionMeta;
    httpcloak?: HTTPCloakSpec;
} | null {
    try {
        const json = atob(username);
        const obj = JSON.parse(json);
        if (typeof obj !== "object" || obj === null) return null;

        const { set, minutes, session_params: sessionParams, session_meta: sessionMeta, httpcloak } = obj;
        if (
            typeof set !== "string" ||
            typeof minutes !== "number" ||
            typeof sessionParams !== "object" ||
            sessionParams === null
        ) {
            return null;
        }

        const paramsResult = sessionParamsSchema.safeParse(sessionParams);
        if (!paramsResult.success) return null;

        const result: {
            proxySet: string;
            minutes: number;
            sessionParams: SessionParams;
            sessionMeta?: SessionMeta;
            httpcloak?: HTTPCloakSpec;
        } = {
            proxySet: set,
            minutes,
            sessionParams: paramsResult.data,
        };
        if (sessionMeta !== undefined && sessionMeta !== null) {
            const metaResult = sessionMetaSchema.safeParse(sessionMeta);
            if (!metaResult.success) return null;
            result.sessionMeta = metaResult.data;
        }
        if (httpcloak !== undefined) {
            result.httpcloak = httpcloak;
        }
        return result;
    } catch {
        return null;
    }
}
