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

import { scanObjectForCredentials } from "./credential-scanner.js";
import { logger } from "../middleware/logger.js";

export interface BatchScanTarget {
  /** Identifier of the entity being scanned (issue id, comment id, etc.) */
  entityId: string;
  entityType: "issue" | "comment" | "agent";
  /** Map of field name → field value to scan. */
  fields: Record<string, string>;
}

export interface BatchScanSummary {
  scanned: number;
  realHits: number;
  fixtureHits: number;
}

/**
 * Scan a list of entities for plaintext credentials.
 *
 * For each Group-A/B/C hit found:
 * - If `fixture=true` (field contains QA-NOSTORE or SCANNER-FIXTURE): log and skip.
 * - Otherwise: call `onRealHit` so the caller can create a security alert.
 *
 * `onRealHit` is async and awaited sequentially — callers can throttle themselves
 * inside the callback if needed.
 */
export async function batchScanForCredentials(
  targets: BatchScanTarget[],
  onRealHit: (target: BatchScanTarget, field: string, group: string, pattern: string) => Promise<void>,
): Promise<BatchScanSummary> {
  let realHits = 0;
  let fixtureHits = 0;

  for (const target of targets) {
    const hits = scanObjectForCredentials(target.fields);
    for (const hit of hits) {
      if (hit.fixture) {
        fixtureHits++;
        logger.info(
          { entityId: target.entityId, entityType: target.entityType, field: hit.field, pattern: hit.pattern },
          "credential-scanner layer2: QA fixture marker detected — suppressed (log only, GNO-799)",
        );
      } else {
        realHits++;
        await onRealHit(target, hit.field, hit.group, hit.pattern);
      }
    }
  }

  return { scanned: targets.length, realHits, fixtureHits };
}
