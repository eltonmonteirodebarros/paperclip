import { describe, it, expect } from "vitest";
import { ADAPTER_ENV_REDACTED_SENTINEL, serializeAdapterConfig, getAdapterEnvMaskedKeys } from "../redaction.ts";

// Spec ref: GNO-915 §1-§3 — all adapterConfig.env.*.value must be masked in API responses.

describe("ADAPTER_ENV_REDACTED_SENTINEL", () => {
  it("is the literal string [REDACTED]", () => {
    expect(ADAPTER_ENV_REDACTED_SENTINEL).toBe("[REDACTED]");
  });
});

describe("serializeAdapterConfig", () => {
  it("returns empty object for null/undefined input", () => {
    expect(serializeAdapterConfig(null)).toEqual({});
    expect(serializeAdapterConfig(undefined)).toEqual({});
    expect(serializeAdapterConfig("not-an-object")).toEqual({});
  });

  it("preserves adapterConfig fields unrelated to env", () => {
    const cfg = { cwd: "/workspace", timeoutSec: 30 };
    const result = serializeAdapterConfig(cfg);
    expect(result.cwd).toBe("/workspace");
    expect(result.timeoutSec).toBe(30);
  });

  it("masks a plain binding: value → [REDACTED], hasValue: true", () => {
    const cfg = {
      env: {
        GITHUB_TOKEN: { type: "plain", value: "ghp_secretvalue" },
      },
    };
    const result = serializeAdapterConfig(cfg);
    const token = (result.env as Record<string, unknown>).GITHUB_TOKEN as Record<string, unknown>;
    expect(token.value).toBe("[REDACTED]");
    expect(token.hasValue).toBe(true);
    expect(token.type).toBe("plain");
    // Cleartext must not appear anywhere in the serialized output
    expect(JSON.stringify(result)).not.toContain("ghp_secretvalue");
  });

  it("sets hasValue: false for plain binding with empty string value", () => {
    const cfg = {
      env: {
        EMPTY_KEY: { type: "plain", value: "" },
      },
    };
    const result = serializeAdapterConfig(cfg);
    const key = (result.env as Record<string, unknown>).EMPTY_KEY as Record<string, unknown>;
    expect(key.value).toBe(null);
    expect(key.hasValue).toBe(false);
  });

  it("masks a secret_ref binding: value → [REDACTED], hasValue: true", () => {
    const cfg = {
      env: {
        DB_PASS: { type: "secret_ref", secretId: "s-abc123", version: 1 },
      },
    };
    const result = serializeAdapterConfig(cfg);
    const key = (result.env as Record<string, unknown>).DB_PASS as Record<string, unknown>;
    expect(key.value).toBe("[REDACTED]");
    expect(key.hasValue).toBe(true);
    expect(key.type).toBe("secret_ref");
    // secretId is metadata (not a secret value), preserved for UI/audit use
    expect(key.secretId).toBe("s-abc123");
  });

  it("masks multiple env keys independently", () => {
    const cfg = {
      env: {
        KEY_A: { type: "plain", value: "cleartext_a" },
        KEY_B: { type: "plain", value: "cleartext_b" },
      },
    };
    const result = serializeAdapterConfig(cfg);
    const env = result.env as Record<string, Record<string, unknown>>;
    expect(env.KEY_A.value).toBe("[REDACTED]");
    expect(env.KEY_B.value).toBe("[REDACTED]");
    expect(JSON.stringify(result)).not.toContain("cleartext_a");
    expect(JSON.stringify(result)).not.toContain("cleartext_b");
  });

  it("treats env: {} (no keys) as empty env, no crash", () => {
    const cfg = { env: {} };
    const result = serializeAdapterConfig(cfg);
    expect(result.env).toEqual({});
  });

  it("passes through adapterConfig with no env key unchanged (aside from copy)", () => {
    const cfg = { adapterType: "claude_local", cwd: "/foo" };
    const result = serializeAdapterConfig(cfg);
    expect(result).toEqual(cfg);
  });
});

// Spec ref: GNO-926 / GNO-915 §5 — adapter_env.read_masked audit event
describe("getAdapterEnvMaskedKeys", () => {
  it("returns empty array for non-object input", () => {
    expect(getAdapterEnvMaskedKeys(null)).toEqual([]);
    expect(getAdapterEnvMaskedKeys(undefined)).toEqual([]);
    expect(getAdapterEnvMaskedKeys("string")).toEqual([]);
  });

  it("returns empty array when no env field", () => {
    expect(getAdapterEnvMaskedKeys({ cwd: "/foo" })).toEqual([]);
  });

  it("returns empty array for env: {}", () => {
    expect(getAdapterEnvMaskedKeys({ env: {} })).toEqual([]);
  });

  it("includes key for non-empty plain binding", () => {
    const cfg = { env: { GITHUB_TOKEN: { type: "plain", value: "ghp_abc" } } };
    expect(getAdapterEnvMaskedKeys(cfg)).toEqual(["GITHUB_TOKEN"]);
  });

  it("excludes key for empty plain binding", () => {
    const cfg = { env: { EMPTY: { type: "plain", value: "" } } };
    expect(getAdapterEnvMaskedKeys(cfg)).toEqual([]);
  });

  it("includes key for secret_ref binding", () => {
    const cfg = { env: { DB_PASS: { type: "secret_ref", secretId: "s-xyz" } } };
    expect(getAdapterEnvMaskedKeys(cfg)).toEqual(["DB_PASS"]);
  });

  it("returns all keys that have values, excludes empty ones", () => {
    const cfg = {
      env: {
        HAS_VALUE: { type: "plain", value: "secret" },
        SECRET_REF: { type: "secret_ref", secretId: "s-1" },
        EMPTY: { type: "plain", value: "" },
        NULL_VALUE: { type: "plain", value: null },
      },
    };
    const keys = getAdapterEnvMaskedKeys(cfg);
    expect(keys).toContain("HAS_VALUE");
    expect(keys).toContain("SECRET_REF");
    expect(keys).not.toContain("EMPTY");
    expect(keys).not.toContain("NULL_VALUE");
  });

  it("result mirrors serializeAdapterConfig hasValue:true keys", () => {
    const cfg = {
      env: {
        A: { type: "plain", value: "val" },
        B: { type: "plain", value: "" },
        C: { type: "secret_ref", secretId: "s-2" },
      },
    };
    const serialized = serializeAdapterConfig(cfg);
    const env = serialized.env as Record<string, Record<string, unknown>>;
    const maskedKeys = Object.entries(env)
      .filter(([, b]) => b.hasValue === true)
      .map(([k]) => k)
      .sort();
    expect(getAdapterEnvMaskedKeys(cfg).sort()).toEqual(maskedKeys);
  });
});
