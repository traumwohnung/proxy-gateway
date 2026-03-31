import { ProxyGatewayClient } from "./client";
import { buildProxyUsername } from "./types";
import type { SessionMetadata } from "./types";

let _client: ProxyGatewayClient | null = null;

export interface ProxyConfig {
    /** Base URL of the proxy-gateway, e.g. "http://proxy-gateway:8100" */
    proxyUrl: string;
    /** API key for authenticating with the proxy-gateway management API */
    apiKey: string;
}

/**
 * Configure the proxy-gateway client once at startup.
 *
 * After calling this, `buildAndVerifyProxyUsername` can be used to build and
 * verify usernames against the proxy-gateway before use.
 *
 * @example
 * configureProxy({ proxyUrl: PROXY_URL, apiKey: PROXY_API_KEY });
 */
export function configureProxy(opts: ProxyConfig): void {
    _client = new ProxyGatewayClient({ baseUrl: opts.proxyUrl, apiKey: opts.apiKey });
}

/**
 * Build the proxy-gateway username — a base64-encoded JSON object — and
 * verify it against the proxy-gateway before returning.
 *
 * Verification checks:
 * 1. The proxy set exists in the proxy-gateway config
 * 2. The upstream proxy is reachable and returns an outbound IP
 *
 * Throws if `configureProxy` has not been called, or if verification fails.
 *
 * @example
 * const username = await buildAndVerifyProxyUsername("residential", 60, { platform: "ka" });
 */
export async function buildAndVerifyProxyUsername(
    proxySet: string,
    affinityMinutes: number,
    metadata: SessionMetadata,
): Promise<string> {
    if (!_client) {
        throw new Error(
            "buildAndVerifyProxyUsername: proxy-gateway client not configured. Call configureProxy() at startup.",
        );
    }

    const username = buildProxyUsername(proxySet, affinityMinutes, metadata);
    const result = await _client.verifyUsername(username);

    if (!result.ok) {
        throw new Error(
            `Proxy username verification failed: ${result.error ?? "unknown error"} ` +
                `(set=${proxySet}, minutes=${affinityMinutes}, metadata=${JSON.stringify(metadata)})`,
        );
    }

    return username;
}
