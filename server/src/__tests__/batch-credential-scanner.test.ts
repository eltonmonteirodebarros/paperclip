/**
 * Regression tests for Layer 2 batch scanner QA fixture suppression (GNO-799).
 *
 * Criterion of done:
 * - fixture with QA-NOSTORE marker  → 0 security issues created.
 * - real credential with no marker  → 1 security issue created.
 */

import { describe, expect, it } from "vitest";
import { batchScanForCredentials } from "../services/batch-credential-scanner.js";

// A real-looking github_pat token (36 alnum chars after ghp_) — never a live credential.
const FAKE_GHP = "ghp_" + "A".repeat(36);

describe("batchScanForCredentials — QA fixture suppression (GNO-799)", () => {
  it("creates 0 security issues when QA-NOSTORE marker appears in the same field as the token", async () => {
    const created: Array<{ entityId: string; field: string }> = [];
    await batchScanForCredentials(
      [
        {
          entityId: "gno-785",
          entityType: "issue",
          fields: { description: `QA-NOSTORE — fixture token for scanner test: ${FAKE_GHP}` },
        },
      ],
      async (target, field) => {
        created.push({ entityId: target.entityId, field });
      },
    );
    expect(created).toHaveLength(0);
  });

  it("creates 0 security issues when SCANNER-FIXTURE marker appears in the same field", async () => {
    const created: Array<{ entityId: string; field: string }> = [];
    await batchScanForCredentials(
      [
        {
          entityId: "gno-785",
          entityType: "issue",
          fields: { description: `SCANNER-FIXTURE ${FAKE_GHP}` },
        },
      ],
      async (target, field) => {
        created.push({ entityId: target.entityId, field });
      },
    );
    expect(created).toHaveLength(0);
  });

  it("creates 1 security issue when a real credential appears with no fixture marker", async () => {
    const created: Array<{ entityId: string; field: string }> = [];
    await batchScanForCredentials(
      [
        {
          entityId: "real-issue",
          entityType: "issue",
          fields: { description: FAKE_GHP },
        },
      ],
      async (target, field) => {
        created.push({ entityId: target.entityId, field });
      },
    );
    expect(created).toHaveLength(1);
    expect(created[0].entityId).toBe("real-issue");
    expect(created[0].field).toBe("description");
  });

  it("marker in title does NOT suppress a token in a different field (field-level isolation)", async () => {
    const created: Array<{ entityId: string; field: string }> = [];
    await batchScanForCredentials(
      [
        {
          entityId: "cross-field",
          entityType: "issue",
          fields: {
            title: "QA-NOSTORE fixture issue",
            description: FAKE_GHP,
          },
        },
      ],
      async (target, field) => {
        created.push({ entityId: target.entityId, field });
      },
    );
    // The marker is only in 'title'; the token is in 'description' → not a fixture hit
    expect(created).toHaveLength(1);
    expect(created[0].field).toBe("description");
  });

  it("marker inside a code block does NOT suppress detection (code blocks are stripped before marker check)", async () => {
    // Security invariant from GNO-799: the fixture check runs on stripped text,
    // so a marker hidden inside a fenced block cannot suppress a token outside it.
    const created: Array<{ entityId: string; field: string }> = [];
    await batchScanForCredentials(
      [
        {
          entityId: "hidden-marker",
          entityType: "issue",
          fields: { description: "```\nQA-NOSTORE\n```\n\ntoken: " + FAKE_GHP },
        },
      ],
      async (target, field) => {
        created.push({ entityId: target.entityId, field });
      },
    );
    expect(created).toHaveLength(1);
  });

  it("returns correct summary counts", async () => {
    const created: string[] = [];
    const summary = await batchScanForCredentials(
      [
        {
          entityId: "fixture-issue",
          entityType: "issue",
          fields: { description: `QA-NOSTORE ${FAKE_GHP}` },
        },
        {
          entityId: "real-issue",
          entityType: "issue",
          fields: { description: FAKE_GHP },
        },
        {
          entityId: "clean-issue",
          entityType: "issue",
          fields: { description: "No credentials here" },
        },
      ],
      async (target) => {
        created.push(target.entityId);
      },
    );
    expect(summary.scanned).toBe(3);
    expect(summary.fixtureHits).toBe(1);
    expect(summary.realHits).toBe(1);
    expect(created).toEqual(["real-issue"]);
  });
});
