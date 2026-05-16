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

describe("buildProxyUsername mitm.scripts field", () => {
    it("omits mitm when absent", () => {
        const u = buildProxyUsername({
            proxySet: "set",
            minutes: 0,
            sessionParams: {},
        });
        expect(decode<{ mitm?: unknown }>(u).mitm).toBeUndefined();
    });

    it("emits scripts under mitm with bare strings normalised to {ref}", () => {
        const u = buildProxyUsername({
            proxySet: "set",
            minutes: 0,
            sessionParams: {},
            httpcloak: { preset: "chrome-latest" },
            scripts: ["antibot", scriptSource("def response_bailing(r): return None")],
        });
        const decoded = decode<{ mitm: { httpcloak: unknown; scripts: unknown[] } }>(u);
        expect(decoded.mitm.scripts).toEqual([
            { kind: "ref", name: "antibot" },
            { kind: "source", source: "def response_bailing(r): return None" },
        ]);
        expect(decoded.mitm.httpcloak).toEqual({ preset: "chrome-latest" });
    });

    it("emits an empty mitm object when only mitm: true is set", () => {
        const u = buildProxyUsername({
            proxySet: "set",
            minutes: 0,
            sessionParams: {},
            mitm: true,
        });
        expect(decode<{ mitm: unknown }>(u).mitm).toEqual({});
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

describe("parseProxyUsername mitm.scripts field", () => {
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
        expect(parsed?.mitm).toBe(true);
    });

    it("returns null on a malformed scripts array", () => {
        const bad = btoa(
            JSON.stringify({
                set: "x",
                minutes: 0,
                session_params: {},
                mitm: { scripts: [{ ref: "a", source: "b" }] },
            }),
        );
        expect(parseProxyUsername(bad)).toBeNull();
    });

    it("returns null on top-level httpcloak (must live under mitm)", () => {
        const bad = btoa(
            JSON.stringify({
                set: "x",
                minutes: 0,
                session_params: {},
                httpcloak: { preset: "chrome-latest" },
            }),
        );
        expect(parseProxyUsername(bad)).toBeNull();
    });

    it("returns null on top-level scripts (must live under mitm)", () => {
        const bad = btoa(
            JSON.stringify({
                set: "x",
                minutes: 0,
                session_params: {},
                scripts: [{ kind: "ref", name: "x" }],
            }),
        );
        expect(parseProxyUsername(bad)).toBeNull();
    });
});

describe("ProxyConfiguration scripts", () => {
    it("appends via scripts(...), scriptRef, scriptSource and emits under mitm", () => {
        const u = new ProxyConfiguration("set")
            .scripts("a")
            .scriptRef("b")
            .scriptSource("def response_bailing(r): pass")
            .buildUsername();
        expect(decode<{ mitm: { scripts: unknown[] } }>(u).mitm.scripts).toEqual([
            { kind: "ref", name: "a" },
            { kind: "ref", name: "b" },
            { kind: "source", source: "def response_bailing(r): pass" },
        ]);
    });

    it("clone deep-copies the scripts array", () => {
        const base = new ProxyConfiguration("set").scriptRef("antibot");
        const cp = base.clone().scriptRef("extra");
        expect(decode<{ mitm: { scripts: unknown[] } }>(base.buildUsername()).mitm.scripts.length).toBe(1);
        expect(decode<{ mitm: { scripts: unknown[] } }>(cp.buildUsername()).mitm.scripts.length).toBe(2);
    });

    it("noMitm wipes scripts, httpcloak, and the mitm flag", () => {
        const u = new ProxyConfiguration("set").scriptRef("a").scriptRef("b").noMitm().buildUsername();
        expect(decode<{ mitm?: unknown }>(u).mitm).toBeUndefined();
    });

    it("omits mitm entirely when no MITM-affecting builder is called", () => {
        const u = new ProxyConfiguration("set").buildUsername();
        expect(decode<{ mitm?: unknown }>(u).mitm).toBeUndefined();
    });

    it("emits an empty mitm object when only .mitm() is called", () => {
        const u = new ProxyConfiguration("set").mitm().buildUsername();
        expect(decode<{ mitm: unknown }>(u).mitm).toEqual({});
    });
});
