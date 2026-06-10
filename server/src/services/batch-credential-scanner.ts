/**
 * Layer 2 — batch retroactive credential scanner (GNO-799).
 *
 * Scans existing issue/comment content for plaintext credentials.
 * Unlike Layer 1 (middleware, write-time block) and Layer 3 (pre-execution guard),
 * Layer 2 runs retroactively on stored content.
 *
 * QA fixture suppression: if a scanned field contains QA-NOSTORE or SCANNER-FIXTURE,
 * the hit is logged but does NOT trigger a security issue.
 * This prevents sticky false positives from intentional test fixtures.
 *
 * Layer 1 and Layer 3 do NOT suppress fixture hits — they treat them the same as real
 * credentials to close the evasion path.
 */

import { createHash } from "node:crypto";
import { scanObjectForCredentials } from "./credential-scanner.js";
import { logger } from "../middleware/logger.js";

/**
 * Canonical fingerprint function for Layer 2 scanner dedup.
 *
 * Formula: SHA1(entityType + entityId + field + patternName) — direct concatenation, no separator.
 * This must be the ONLY place this hash is computed; callers must never reimplement inline.
 *
 * Test vector (GNO-993 / GNO-1195):
 *   computeScannerFingerprint("issue_comments", "9735d861-11e9-4886-9f31-c04ead526b6b", "body", "github_pat")
 *   === "1da550870752fe554b4165f9271e5c7ecf916c0e"
 */
export function computeScannerFingerprint(
  entityType: string,
  entityId: string,
  field: string,
  patternName: string,
): string {
  return createHash("sha1")
    .update(entityType + entityId + field + patternName)
    .digest("hex");
}

export interface BatchScanTarget {
  /** Identifier of the entity being scanned (issue id, comment id, etc.) */
  entityId: string;
  entityType: "issue" | "comment" | "agent";
  /** Map of field name → field value to scan. */
  fields: Record<string, string>;
  /**
   * GNO-1127: optional origin metadata for runner-self exclusion.
   * Callers should populate these from the issue's originKind / originId fields
   * so that description hits on self-generated routine execution issues can be
   * suppressed without false positives.
   */
  originKind?: string;
  originId?: string;
}

export interface BatchScanSummary {
  scanned: number;
  realHits: number;
  fixtureHits: number;
  runnerSelfSkips: number;
}

export interface BatchScanOptions {
  /**
   * GNO-1127: Routine ID of the scanner itself.
   * When set, description-field hits on issues where:
   *   originKind == "routine_execution" AND originId == selfRoutineId
   * are suppressed as "runner-self description matches" — the description contains
   * the routine template (which lists the regex patterns verbatim), not real credentials.
   */
  selfRoutineId?: string;
}

/**
 * Scan a list of entities for plaintext credentials.
 *
 * For each Group-A/B/C hit found:
 * - If runner-self description match (GNO-1127): log and skip.
 * - If `fixture=true` (field contains QA-NOSTORE or SCANNER-FIXTURE): log and skip.
 * - Otherwise: call `onRealHit` so the caller can create a security alert.
 *
 * `onRealHit` is async and awaited sequentially — callers can throttle themselves
 * inside the callback if needed.
 */
export async function batchScanForCredentials(
  targets: BatchScanTarget[],
  onRealHit: (target: BatchScanTarget, field: string, group: string, pattern: string, fingerprint: string) => Promise<void>,
  opts: BatchScanOptions = {},
): Promise<BatchScanSummary> {
  let realHits = 0;
  let fixtureHits = 0;
  let runnerSelfSkips = 0;

  for (const target of targets) {
    const hits = scanObjectForCredentials(target.fields);
    for (const hit of hits) {
      // GNO-1127: suppress runner-self description matches.
      // When the scanner routine scans the universe of issues, it encounters its own
      // execution issues whose description = the routine template (which lists the regex
      // patterns verbatim, including e.g. "slack_webhook: https://hooks.slack.com/...").
      // These are not real credentials — skip rather than alert.
      if (
        opts.selfRoutineId &&
        hit.field === "description" &&
        target.originKind === "routine_execution" &&
        target.originId === opts.selfRoutineId
      ) {
        runnerSelfSkips++;
        logger.info(
          { entityId: target.entityId, entityType: target.entityType, routineId: opts.selfRoutineId, pattern: hit.pattern },
          "credential-scanner layer2: runner-self description match suppressed (GNO-1127)",
        );
        continue;
      }

      if (hit.fixture) {
        fixtureHits++;
        logger.info(
          { entityId: target.entityId, entityType: target.entityType, field: hit.field, pattern: hit.pattern },
          "credential-scanner layer2: QA fixture marker detected — suppressed (log only, GNO-799)",
        );
      } else {
        realHits++;
        const fingerprint = computeScannerFingerprint(target.entityType, target.entityId, hit.field, hit.pattern);
        await onRealHit(target, hit.field, hit.group, hit.pattern, fingerprint);
      }
    }
  }

  return { scanned: targets.length, realHits, fixtureHits, runnerSelfSkips };
}
