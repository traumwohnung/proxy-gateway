import { describe, expect, it } from "bun:test";
import { ProxyConfiguration } from "./proxy_configuration";
import {
    buildProxyUsername,
    parseProxyUsername,
    scriptEntryInputSchema,
    scriptEntrySchema,
    scriptRef,
    scriptSource,
} from "./types";

function decode<T = unknown>(username: string): T {
    return JSON.parse(atob(username)) as T;
}

describe("scriptEntrySchema (zod 4)", () => {
    it("accepts {ref}", () => {
        expect(scriptEntrySchema.parse({ kind: "ref", name: "antibot" })).toEqual({ kind: "ref", name: "antibot" });
    });

    it("accepts {source}", () => {
        expect(scriptEntrySchema.parse({ kind: "source", source: "x" })).toEqual({ kind: "source", source: "x" });
    });

    it("rejects {ref + source}", () => {
        expect(scriptEntrySchema.safeParse({ ref: "a", source: "b" }).success).toBe(false);
    });

    it("rejects empty {}", () => {
        expect(scriptEntrySchema.safeParse({}).success).toBe(false);
    });

    it("rejects bare string (must use input schema for that)", () => {
        expect(scriptEntrySchema.safeParse("antibot").success).toBe(false);
    });
});

describe("scriptEntryInputSchema (zod 4)", () => {
    it("normalises bare string to {ref}", () => {
        expect(scriptEntryInputSchema.parse("antibot")).toEqual({ kind: "ref", name: "antibot" });
    });

    it("passes {ref} through", () => {
        expect(scriptEntryInputSchema.parse({ kind: "ref", name: "x" })).toEqual({ kind: "ref", name: "x" });
    });

    it("passes {source} through", () => {
        expect(scriptEntryInputSchema.parse({ kind: "source", source: "y" })).toEqual({ kind: "source", source: "y" });
    });

    it("rejects empty string", () => {
        expect(scriptEntryInputSchema.safeParse("").success).toBe(false);
    });
});

describe("scriptRef / scriptSource helpers", () => {
    it("scriptRef produces {ref}", () => {
        expect(scriptRef("a")).toEqual({ kind: "ref", name: "a" });
    });
    it("scriptSource produces {source}", () => {
        expect(scriptSource("y")).toEqual({ kind: "source", source: "y" });
    });
});

describe("buildProxyUsername scripts field", () => {
    it("omits scripts when absent", () => {
        const u = buildProxyUsername({
            proxySet: "set",
            minutes: 0,
            sessionParams: {},
        });
        expect(decode<{ scripts?: unknown }>(u).scripts).toBeUndefined();
    });

    it("emits bare strings as {ref} objects", () => {
        const u = buildProxyUsername({
            proxySet: "set",
            minutes: 0,
            sessionParams: {},
            httpcloak: { preset: "chrome-latest" },
            scripts: ["antibot", scriptSource("def response_bailing(r): return None")],
        });
        const decoded = decode<{ scripts: { ref?: string; source?: string }[] }>(u);
        expect(decoded.scripts).toEqual([
            { kind: "ref", name: "antibot" },
            { kind: "source", source: "def response_bailing(r): return None" },
        ]);
    });

    it("rejects malformed entries at build", () => {
        expect(() =>
            buildProxyUsername({
                proxySet: "set",
                minutes: 0,
                sessionParams: {},
                // @ts-expect-error intentionally invalid
                scripts: [{ unknown: "field" }],
            }),
        ).toThrow();
    });
});

describe("parseProxyUsername scripts field", () => {
    it("round-trips a mixed chain", () => {
        const u = buildProxyUsername({
            proxySet: "set",
            minutes: 0,
            sessionParams: {},
            httpcloak: { preset: "chrome-latest" },
            scripts: ["antibot", scriptSource("def response_bailing(r): pass")],
        });
        const parsed = parseProxyUsername(u);
        expect(parsed?.scripts).toEqual([
            { kind: "ref", name: "antibot" },
            { kind: "source", source: "def response_bailing(r): pass" },
        ]);
    });

    it("returns null on a malformed scripts array", () => {
        const bad = btoa(
            JSON.stringify({
                set: "x",
                minutes: 0,
                session_params: {},
                scripts: [{ ref: "a", source: "b" }],
            }),
        );
        expect(parseProxyUsername(bad)).toBeNull();
    });
});

describe("ProxyConfiguration scripts", () => {
    it("appends via scripts(...), scriptRef, scriptSource", () => {
        const u = new ProxyConfiguration("set")
            .scripts("a")
            .scriptRef("b")
            .scriptSource("def response_bailing(r): pass")
            .buildUsername();
        expect(decode<{ scripts: unknown[] }>(u).scripts).toEqual([
            { kind: "ref", name: "a" },
            { kind: "ref", name: "b" },
            { kind: "source", source: "def response_bailing(r): pass" },
        ]);
    });

    it("clone deep-copies the scripts array", () => {
        const base = new ProxyConfiguration("set").scriptRef("antibot");
        const cp = base.clone().scriptRef("extra");
        expect(decode<{ scripts: unknown[] }>(base.buildUsername()).scripts.length).toBe(1);
        expect(decode<{ scripts: unknown[] }>(cp.buildUsername()).scripts.length).toBe(2);
    });

    it("clearScripts wipes previously appended entries", () => {
        const u = new ProxyConfiguration("set").scriptRef("a").scriptRef("b").clearScripts().buildUsername();
        expect(decode<{ scripts?: unknown }>(u).scripts).toBeUndefined();
    });

    it("omits the field entirely when no scripts have been appended", () => {
        const u = new ProxyConfiguration("set").buildUsername();
        expect(decode<{ scripts?: unknown }>(u).scripts).toBeUndefined();
    });
});
