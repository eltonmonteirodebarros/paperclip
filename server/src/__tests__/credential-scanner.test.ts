import { describe, expect, it } from "vitest";
import {
  QA_FIXTURE_MARKERS,
  detectFirstCredential,
  scanObjectForCredentials,
} from "../services/credential-scanner.js";

// A real-looking github_pat token (36 alnum chars after ghp_) — never a live credential.
const FAKE_GHP = "ghp_" + "A".repeat(36);

describe("QA_FIXTURE_MARKERS", () => {
  it("exports the expected markers", () => {
    expect(QA_FIXTURE_MARKERS).toContain("QA-NOSTORE");
    expect(QA_FIXTURE_MARKERS).toContain("SCANNER-FIXTURE");
  });
});

describe("scanObjectForCredentials — fixture marker detection", () => {
  it("returns fixture=false for a real-looking token with no marker", () => {
    const hits = scanObjectForCredentials({ description: FAKE_GHP });
    expect(hits).toHaveLength(1);
    expect(hits[0].fixture).toBe(false);
    expect(hits[0].group).toBe("A");
    expect(hits[0].pattern).toBe("github_pat");
  });

  it("returns fixture=true when QA-NOSTORE appears in the same field", () => {
    const hits = scanObjectForCredentials({
      description: `QA-NOSTORE — fixture token for scanner test: ${FAKE_GHP}`,
    });
    expect(hits).toHaveLength(1);
    expect(hits[0].fixture).toBe(true);
    expect(hits[0].group).toBe("A");
  });

  it("returns fixture=true when SCANNER-FIXTURE appears in the same field", () => {
    const hits = scanObjectForCredentials({
      description: `SCANNER-FIXTURE ${FAKE_GHP}`,
    });
    expect(hits).toHaveLength(1);
    expect(hits[0].fixture).toBe(true);
  });

  it("returns fixture=false when marker is in a different field from the token", () => {
    const hits = scanObjectForCredentials({
      title: "QA-NOSTORE — this is a fixture",
      description: FAKE_GHP,
    });
    // The 'description' field has the token but NOT the marker → fixture=false
    const descHit = hits.find((h) => h.field === "description");
    expect(descHit).toBeDefined();
    expect(descHit?.fixture).toBe(false);
  });

  it("returns fixture=false when marker is inside a code block — cannot suppress via hidden marker", () => {
    // Security invariant: marker inside a code block is stripped before the check,
    // so it cannot suppress detection of a real token outside the block. GNO-799.
    const hits = scanObjectForCredentials({
      description: "```\nQA-NOSTORE\n```\n\ntoken: " + FAKE_GHP,
    });
    expect(hits).toHaveLength(1);
    expect(hits[0].fixture).toBe(false);
  });

  it("does not treat the title-level marker as field-level suppression for description", () => {
    const hits = scanObjectForCredentials({
      title: "QA-NOSTORE",
      description: FAKE_GHP,
    });
    const descHit = hits.find((h) => h.field === "description");
    expect(descHit?.fixture).toBe(false);
  });
});

describe("detectFirstCredential — fixture marker propagation", () => {
  it("propagates fixture=true from the first hit", () => {
    const hit = detectFirstCredential({
      description: `QA-NOSTORE ${FAKE_GHP}`,
    });
    expect(hit).not.toBeNull();
    expect(hit?.fixture).toBe(true);
  });

  it("propagates fixture=false when no marker is present", () => {
    const hit = detectFirstCredential({ description: FAKE_GHP });
    expect(hit).not.toBeNull();
    expect(hit?.fixture).toBe(false);
  });
});

describe("detectFirstCredential — secretRefs false positive (GNO-826)", () => {
  it("returns null for secretRefs.apiKey — key name in GROUP_C_FIELDS, value is a reference", () => {
    const hit = detectFirstCredential({ secretRefs: { apiKey: "secret:my-openai-api-key" } });
    expect(hit).toBeNull();
  });

  it("returns null for secretRefs.token", () => {
    const hit = detectFirstCredential({ secretRefs: { token: "secret:some-service-token" } });
    expect(hit).toBeNull();
  });

  it("returns null for secretRefs.secret", () => {
    const hit = detectFirstCredential({ secretRefs: { secret: "secret:db-password-ref" } });
    expect(hit).toBeNull();
  });

  it("returns null for secretRefs.password with long value", () => {
    const hit = detectFirstCredential({ secretRefs: { password: "secret:vault/prod/db-password" } });
    expect(hit).toBeNull();
  });

  it("still detects a real Group A token outside secretRefs", () => {
    const hit = detectFirstCredential({
      secretRefs: { apiKey: "secret:my-openai-api-key" },
      description: FAKE_GHP,
    });
    expect(hit).not.toBeNull();
    expect(hit?.group).toBe("A");
    expect(hit?.pattern).toBe("github_pat");
  });

  it("still detects Group A token inside a non-secretRefs nested object", () => {
    const hit = detectFirstCredential({ config: { token: FAKE_GHP } });
    expect(hit).not.toBeNull();
    expect(hit?.group).toBe("A");
  });
});
