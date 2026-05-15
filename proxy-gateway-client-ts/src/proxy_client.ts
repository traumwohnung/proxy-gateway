import { ProxyGatewayClient } from "./client";

/**
 * Holds the connection details for a proxy-gateway deployment: the proxy
 * endpoint (host:port) and optionally the admin endpoint + API key
 * (required for rotation calls). Build one at startup and pass it to
 * `ProxyConfiguration.withProxyClient`.
 */
export class ProxyClient {
    private _proxyHost = "";
    private _proxyPort = 0;
    private _adminUrl = "";
    private _apiKey = "";

    /** Set the proxy endpoint host:port. */
    proxy(host: string, port: number): this {
        this._proxyHost = host;
        this._proxyPort = port;
        return this;
    }

    /** Convenience for `proxy(host, port)` accepting a "host:port" string. */
    proxyAddr(addr: string): this {
        const idx = addr.lastIndexOf(":");
        if (idx < 0) throw new Error(`ProxyClient.proxyAddr: malformed addr ${addr}`);
        const port = Number(addr.slice(idx + 1));
        if (!Number.isFinite(port)) throw new Error(`ProxyClient.proxyAddr: bad port in ${addr}`);
        return this.proxy(addr.slice(0, idx), port);
    }

    /** Set the admin API base URL and bearer token. Required for rotation. */
    admin(baseUrl: string, apiKey: string): this {
        this._adminUrl = baseUrl;
        this._apiKey = apiKey;
        return this;
    }

    proxyHost(): string { return this._proxyHost; }
    proxyPort(): number { return this._proxyPort; }

    /** @internal Build the typed admin client, or null if not configured. */
    adminClient(): ProxyGatewayClient | null {
        if (!this._adminUrl) return null;
        return new ProxyGatewayClient({ baseUrl: this._adminUrl, apiKey: this._apiKey });
    }
}
