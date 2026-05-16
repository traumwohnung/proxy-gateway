import { describe, expect, it } from "bun:test";
import { ProxyClient } from "./proxy_client";
import { ProxyConfiguration } from "./proxy_configuration";

function decode(username: string): {
    set: string;
    minutes: number;
    session_params: Record<string, string>;
    session_meta?: Record<string, string>;
} {
    return JSON.parse(atob(username));
}

describe("ProxyConfiguration", () => {
    it("encodes the configured fields", () => {
        const u = new ProxyConfiguration("residential")
            .minutes(60)
            .sessionParams("platform", "myapp")
            .sessionParams("user", "alice")
            .buildUsername();
        const decoded = decode(u);
        expect(decoded.set).toBe("residential");
        expect(decoded.minutes).toBe(60);
        expect(decoded.session_params).toEqual({ platform: "myapp", user: "alice" });
    });

    it("is deterministic — same inputs produce identical usernames", () => {
        const a = new ProxyConfiguration("residential").minutes(60).sessionParams("user", "alice").buildUsername();
        const b = new ProxyConfiguration("residential").minutes(60).sessionParams("user", "alice").buildUsername();
        expect(a).toBe(b);
    });

    it("buildUrl requires withProxyClient", () => {
        const c = new ProxyConfiguration("set").minutes(60);
        expect(() => c.buildUrl()).toThrow(/withProxyClient/);
    });

    it("buildUrl produces http://user:x@host:port", () => {
        const pc = new ProxyClient().proxy("127.0.0.1", 8100);
        const c = new ProxyConfiguration("residential").minutes(60).withProxyClient(pc);
        const url = c.buildUrl();
        expect(url).toMatch(/^http:\/\/[^:]+:x@127\.0\.0\.1:8100$/);
    });

    it("rotate without admin throws", async () => {
        const pc = new ProxyClient().proxy("127.0.0.1", 8100); // no admin
        const c = new ProxyConfiguration("set").minutes(60).withProxyClient(pc);
        await expect(c.rotate()).rejects.toThrow(/admin/);
    });

    it("rotate calls the gateway admin endpoint", async () => {
        let rotateCalls = 0;
        const srv = Bun.serve({
            port: 0,
            fetch: (req) => {
                if (req.method === "POST" && new URL(req.url).pathname.endsWith("/rotate-now")) {
                    rotateCalls++;
                    return new Response(
                        JSON.stringify({
                            session_id: 1,
                            username: "u",
                            proxy_set: "set",
                            upstream: "host:1",
                            created_at: new Date().toISOString(),
                            next_rotation_at: new Date().toISOString(),
                            last_rotation_at: new Date().toISOString(),
                            metadata: {},
                        }),
                        { headers: { "Content-Type": "application/json" } },
                    );
                }
                return new Response("nope", { status: 404 });
            },
        });

        const pc = new ProxyClient().proxy("127.0.0.1", 8100).admin(`http://localhost:${srv.port}`, "");
        const c = new ProxyConfiguration("set").minutes(60).withProxyClient(pc);

        const info = await c.rotate();
        srv.stop(true);
        expect(info?.session_id).toBe(1);
        expect(rotateCalls).toBe(1);
    });

    it("retryN stops at maxRetries with last value", async () => {
        const srv = Bun.serve({
            port: 0,
            fetch: () =>
                new Response(
                    JSON.stringify({
                        session_id: 1,
                        username: "u",
                        proxy_set: "set",
                        upstream: "host:1",
                        created_at: new Date().toISOString(),
                        next_rotation_at: new Date().toISOString(),
                        last_rotation_at: new Date().toISOString(),
                        metadata: {},
                    }),
                    { headers: { "Content-Type": "application/json" } },
                ),
        });
        const pc = new ProxyClient().proxy("127.0.0.1", 8100).admin(`http://localhost:${srv.port}`, "");
        const c = new ProxyConfiguration("set").minutes(60).withProxyClient(pc);

        let calls = 0;
        const result = await c.retryN<string>(3, async () => {
            calls++;
            return null;
        });
        srv.stop(true);
        expect(calls).toBe(3);
        expect(result).toBeNull();
    });
});
