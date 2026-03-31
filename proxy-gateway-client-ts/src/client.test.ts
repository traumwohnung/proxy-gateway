import { describe, expect, it } from "bun:test";
import { ProxyGatewayClient } from "./client";
import type { UsageResponse } from "./types";

// ---------------------------------------------------------------------------
// Minimal test server using Bun.serve
// ---------------------------------------------------------------------------

function makeUsageServer(handler: (req: Request) => Response): { url: string; close: () => void } {
    const srv = Bun.serve({ port: 0, fetch: handler });
    return {
        url: `http://localhost:${srv.port}`,
        close: () => srv.stop(true),
    };
}

const emptyUsageResponse: UsageResponse = {
    rows: [],
    total_count: 0,
    page: 1,
    page_size: 100,
    total_pages: 1,
};

const singleRowResponse: UsageResponse = {
    rows: [
        {
            hour_ts: "2026-01-15T10:00:00Z",
            proxyset: "residential",
            affinity_params: '{"user":"alice"}',
            upload_bytes: 1024,
            download_bytes: 2048,
            total_bytes: 3072,
        },
    ],
    total_count: 1,
    page: 1,
    page_size: 100,
    total_pages: 1,
};

// ---------------------------------------------------------------------------
// queryUsage — response parsing
// ---------------------------------------------------------------------------

describe("queryUsage response parsing", () => {
    it("returns empty response when no rows", async () => {
        const srv = makeUsageServer(() => Response.json(emptyUsageResponse));
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        const result = await client.queryUsage();
        expect(result.rows).toHaveLength(0);
        expect(result.total_count).toBe(0);
        expect(result.total_pages).toBe(1);
        srv.close();
    });

    it("parses row fields correctly", async () => {
        const srv = makeUsageServer(() => Response.json(singleRowResponse));
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        const result = await client.queryUsage();
        expect(result.rows).toHaveLength(1);
        const row = result.rows[0];
        expect(row.proxyset).toBe("residential");
        expect(row.upload_bytes).toBe(1024);
        expect(row.download_bytes).toBe(2048);
        expect(row.total_bytes).toBe(3072);
        expect(row.hour_ts).toBe("2026-01-15T10:00:00Z");
        srv.close();
    });

    it("parses pagination fields", async () => {
        const resp: UsageResponse = {
            rows: [],
            total_count: 250,
            page: 2,
            page_size: 50,
            total_pages: 5,
        };
        const srv = makeUsageServer(() => Response.json(resp));
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        const result = await client.queryUsage({ page: 2, pageSize: 50 });
        expect(result.total_count).toBe(250);
        expect(result.page).toBe(2);
        expect(result.page_size).toBe(50);
        expect(result.total_pages).toBe(5);
        srv.close();
    });
});

// ---------------------------------------------------------------------------
// queryUsage — query parameter encoding
// ---------------------------------------------------------------------------

describe("queryUsage query parameters", () => {
    function captureParams(req: Request): URLSearchParams {
        return new URL(req.url).searchParams;
    }

    it("sends no params when filter is empty", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage();
        expect([...received!.keys()]).toHaveLength(0);
        srv.close();
    });

    it("sends from param", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ from: "2026-01-01T00:00:00Z" });
        expect(received!.get("from")).toBe("2026-01-01T00:00:00Z");
        srv.close();
    });

    it("sends to param", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ to: "2026-01-31T23:59:59Z" });
        expect(received!.get("to")).toBe("2026-01-31T23:59:59Z");
        srv.close();
    });

    it("sends proxyset param", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ proxyset: "datacenter" });
        expect(received!.get("proxyset")).toBe("datacenter");
        srv.close();
    });

    it("sends meta param", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ meta: '{"user":"alice"}' });
        expect(received!.get("meta")).toBe('{"user":"alice"}');
        srv.close();
    });

    it("sends granularity=hour", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ granularity: "hour" });
        expect(received!.get("granularity")).toBe("hour");
        srv.close();
    });

    it("sends granularity=day", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ granularity: "day" });
        expect(received!.get("granularity")).toBe("day");
        srv.close();
    });

    it("sends granularity=proxyset", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ granularity: "proxyset" });
        expect(received!.get("granularity")).toBe("proxyset");
        srv.close();
    });

    it("sends granularity=total", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ granularity: "total" });
        expect(received!.get("granularity")).toBe("total");
        srv.close();
    });

    it("sends page and page_size params", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage({ page: 3, pageSize: 25 });
        expect(received!.get("page")).toBe("3");
        expect(received!.get("page_size")).toBe("25");
        srv.close();
    });

    it("sends all filters together", async () => {
        let received: URLSearchParams | undefined;
        const srv = makeUsageServer((req) => {
            received = captureParams(req);
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url, apiKey: "secret" });
        await client.queryUsage({
            from: "2026-01-01T00:00:00Z",
            to: "2026-01-31T23:59:59Z",
            proxyset: "residential",
            meta: '{"platform":"ios"}',
            granularity: "day",
            page: 2,
            pageSize: 50,
        });
        expect(received!.get("from")).toBe("2026-01-01T00:00:00Z");
        expect(received!.get("to")).toBe("2026-01-31T23:59:59Z");
        expect(received!.get("proxyset")).toBe("residential");
        expect(received!.get("meta")).toBe('{"platform":"ios"}');
        expect(received!.get("granularity")).toBe("day");
        expect(received!.get("page")).toBe("2");
        expect(received!.get("page_size")).toBe("50");
        srv.close();
    });
});

// ---------------------------------------------------------------------------
// queryUsage — error handling
// ---------------------------------------------------------------------------

describe("queryUsage error handling", () => {
    it("throws on 400 response", async () => {
        const srv = makeUsageServer(
            () => new Response(JSON.stringify({ error: "invalid granularity" }), { status: 400 }),
        );
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await expect(client.queryUsage({ granularity: "weekly" as never })).rejects.toThrow("400");
        srv.close();
    });

    it("throws on 401 response", async () => {
        const srv = makeUsageServer(() => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await expect(client.queryUsage()).rejects.toThrow("401");
        srv.close();
    });

    it("sends Authorization header when apiKey is set", async () => {
        let authHeader: string | null = null;
        const srv = makeUsageServer((req) => {
            authHeader = req.headers.get("Authorization");
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url, apiKey: "my-secret-key" });
        await client.queryUsage();
        expect(authHeader).toBe("Bearer my-secret-key");
        srv.close();
    });

    it("sends Authorization header from getToken", async () => {
        let authHeader: string | null = null;
        const srv = makeUsageServer((req) => {
            authHeader = req.headers.get("Authorization");
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({
            baseUrl: srv.url,
            getToken: () => "dynamic-token",
        });
        await client.queryUsage();
        expect(authHeader).toBe("Bearer dynamic-token");
        srv.close();
    });
});

// ---------------------------------------------------------------------------
// queryUsage — hits the correct path
// ---------------------------------------------------------------------------

describe("queryUsage URL", () => {
    it("calls /api/usage", async () => {
        let receivedPath: string | undefined;
        const srv = makeUsageServer((req) => {
            receivedPath = new URL(req.url).pathname;
            return Response.json(emptyUsageResponse);
        });
        const client = new ProxyGatewayClient({ baseUrl: srv.url });
        await client.queryUsage();
        expect(receivedPath).toBe("/api/usage");
        srv.close();
    });
});
