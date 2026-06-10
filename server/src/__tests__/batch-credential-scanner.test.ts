import { describe, expect, it, vi } from "vitest";
import { batchScanForCredentials, computeScannerFingerprint } from "../services/batch-credential-scanner.js";

describe("computeScannerFingerprint", () => {
  it("matches known test vector (GNO-993 / GNO-1195)", () => {
    const fp = computeScannerFingerprint(
      "issue_comments",
      "9735d861-11e9-4886-9f31-c04ead526b6b",
      "body",
      "github_pat",
    );
    expect(fp).toBe("1da550870752fe554b4165f9271e5c7ecf916c0e");
  });

  it("returns identical fingerprint for the same inputs on repeated calls (GNO-1195)", () => {
    const args = ["issue_comments", "abc123", "body", "github_pat"] as const;
    expect(computeScannerFingerprint(...args)).toBe(computeScannerFingerprint(...args));
  });

  it("produces different fingerprints for different inputs", () => {
    const a = computeScannerFingerprint("issues", "id1", "description", "github_pat");
    const b = computeScannerFingerprint("issue_comments", "id1", "body", "github_pat");
    expect(a).not.toBe(b);
  });
});

describe("batchScanForCredentials — fingerprint stability (GNO-1195)", () => {
  const FIXTURE_TOKEN = "ghp_" + "A".repeat(36);

  it("passes the same fingerprint to onRealHit across two runs on the same fixture", async () => {
    const targets = [
      {
        entityType: "comment" as const,
        entityId: "fixture-comment-id",
        fields: { body: FIXTURE_TOKEN },
      },
    ];

    const run = async () => {
      const fingerprints: string[] = [];
      await batchScanForCredentials(targets, async (_target, _field, _group, _pattern, fp) => {
        fingerprints.push(fp);
      });
      return fingerprints;
    };

    const [fps1, fps2] = await Promise.all([run(), run()]);
    expect(fps1).toHaveLength(1);
    expect(fps1).toEqual(fps2);
  });

  it("fingerprint delivered via onRealHit matches computeScannerFingerprint directly", async () => {
    const targets = [
      {
        entityType: "issue" as const,
        entityId: "fixture-issue-id",
        fields: { description: FIXTURE_TOKEN },
      },
    ];

    let deliveredFp: string | undefined;
    await batchScanForCredentials(targets, async (target, field, _group, pattern, fp) => {
      deliveredFp = fp;
    });

    expect(deliveredFp).toBe(
      computeScannerFingerprint("issue", "fixture-issue-id", "description", "github_pat"),
    );
  });
});
