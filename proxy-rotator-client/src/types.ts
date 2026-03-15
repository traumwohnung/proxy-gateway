import { z } from "zod";

/**
 * Flat JSON metadata object carried inside the username JSON.
 * All values are strings.
 */
export const sessionMetadataSchema = z.record(z.string(), z.string());

export type SessionMetadata = Record<string, string>;

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
    /** When the current proxy assignment expires (ISO 8601 UTC). Reset on force_rotate. */
    next_rotation_at: z.string(),
    /** When the proxy was last assigned — equals created_at unless force_rotate was called (ISO 8601 UTC). */
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
// Username construction helpers
// ---------------------------------------------------------------------------

/**
 * Build the proxy-rotator username — a base64-encoded JSON object.
 * Pure and synchronous — no verification. Use `buildAndVerifyProxyUsername`
 * to also verify that the proxy set exists and the upstream is reachable.
 *
 * @example
 * buildProxyUsername("residential", 60, { platform: "ka", user: "alice" })
 */
export function buildProxyUsername(proxySet: string, affinityMinutes: number, metadata: SessionMetadata): string {
    const json = JSON.stringify({ meta: metadata, minutes: affinityMinutes, set: proxySet });
    return btoa(json);
}

/**
 * Decode a proxy-rotator username back into its components.
 * Returns `null` if the string cannot be decoded or parsed.
 */
export function parseProxyUsername(username: string): {
    proxySet: string;
    affinityMinutes: number;
    metadata: SessionMetadata;
} | null {
    try {
        const json = atob(username);
        const obj = JSON.parse(json);
        if (typeof obj !== "object" || obj === null) return null;

        const { set, minutes, meta } = obj;
        if (typeof set !== "string" || typeof minutes !== "number" || typeof meta !== "object" || meta === null) {
            return null;
        }

        const metaResult = sessionMetadataSchema.safeParse(meta);
        if (!metaResult.success) return null;

        return {
            proxySet: set,
            affinityMinutes: minutes,
            metadata: metaResult.data,
        };
    } catch {
        return null;
    }
}
