/**
 * Layer 1 token scanner — blocks writes that contain plaintext credentials.
 *
 * Intercepts POST/PATCH mutations on issues, comments, and agent configs.
 * Group A patterns → HTTP 422 + async Aegis alert.
 * Group B patterns → async Aegis alert only.
 * Group C patterns (sensitive field names with long values) → HTTP 422.
 *
 * GNO-752 (original), GNO-790 (persistence fix).
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Request = any;
import type { Db } from "@paperclipai/db";
import { scanObjectForCredentials } from "../services/credential-scanner.js";
import { issueService } from "../services/issues.js";
import { logger } from "./logger.js";

// Use the same loose RequestHandler type pattern as other server middleware.
type RequestHandler = (req: any, res: any, next: any) => void | Promise<void>;

const AEGIS_AGENT_ID = "e532fd90-620b-4f10-a9fc-f2697c083771";

// Request body fields to include in the scan per endpoint type.
// We scan user-supplied text content only — never internal/system fields.
const ISSUE_SCAN_FIELDS = ["title", "description", "comment", "body"];
const AGENT_SCAN_FIELDS = ["adapterConfig", "runtimeConfig"];

// Endpoints that need scanning, matched against req.path (without /api prefix).
const ISSUE_MUTATION_RE = /^\/(?:companies\/[^/]+\/issues|issues(?:\/[^/]+(?:\/(?:children|comments))?)?(?:\/[^/]+)?)$/;
const AGENT_MUTATION_RE = /^\/(?:companies\/[^/]+\/agents|agents\/[^/]+)$/;

function extractScanTarget(
  method: string,
  path: string,
  body: Record<string, unknown>,
): { fields: string[] } | null {
  const m = method.toUpperCase();
  if (m !== "POST" && m !== "PATCH") return null;

  // Issues / comments
  if (
    ISSUE_MUTATION_RE.test(path) ||
    /\/issues\/[^/]+\/comments$/.test(path) ||
    /\/companies\/[^/]+\/issues$/.test(path) ||
    /\/issues\/[^/]+$/.test(path) ||
    /\/issues\/[^/]+\/children$/.test(path)
  ) {
    return { fields: ISSUE_SCAN_FIELDS };
  }

  // Agent config mutations
  if (
    AGENT_MUTATION_RE.test(path) ||
    /\/agents\/[^/]+$/.test(path) ||
    /\/companies\/[^/]+\/agents$/.test(path)
  ) {
    return { fields: AGENT_SCAN_FIELDS };
  }

  return null;
}

function extractBodySubset(body: unknown, fields: string[]): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) return {};
  const obj = body as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const f of fields) {
    if (f in obj) result[f] = obj[f];
  }
  return result;
}

function resolveCompanyId(req: Request): string | null {
  const actor = (req as any).actor as { type: string; companyId?: string } | undefined;
  if (actor?.type === "agent" && actor.companyId) return actor.companyId;
  // Board actors: try to parse from URL params or body
  const body = (req as any).body as Record<string, unknown> | undefined;
  if (body?.companyId && typeof body.companyId === "string") return body.companyId;
  // URL pattern /companies/:companyId/...
  const m = (req.path as string).match(/\/companies\/([a-f0-9\-]{36})/);
  if (m) return m[1];
  return null;
}

async function notifyAegis(
  db: Db,
  companyId: string,
  context: { field: string; pattern: string; group: string; actorId: string; path: string },
): Promise<void> {
  try {
    const svc = issueService(db);
    await svc.create(companyId, {
      title: `[Security] Credential detected in plaintext — field: ${context.field}`,
      description: [
        `## Token Scanner Alert (Layer 1)`,
        ``,
        `A credential pattern was detected in a write operation and blocked.`,
        ``,
        `| Field | Value |`,
        `|---|---|`,
        `| Group | ${context.group} |`,
        `| Pattern | ${context.pattern} |`,
        `| Field path | \`${context.field}\` |`,
        `| Actor | ${context.actorId} |`,
        `| Endpoint | ${context.path} |`,
        ``,
        `**The token value was not logged.** Review the originating agent config and ensure credentials are stored via secret manager (\`secretRefs\`).`,
      ].join("\n"),
      status: "todo",
      priority: "high",
      assigneeAgentId: AEGIS_AGENT_ID,
      createdByAgentId: null,
    });
  } catch (err) {
    logger.warn({ err, companyId, field: context.field }, "token-scanner: failed to create Aegis alert issue");
  }
}

export function createTokenScannerMiddleware(db: Db): RequestHandler {
  return async (req: any, res: any, next: any) => {
    const target = extractScanTarget(req.method, req.path, req.body as Record<string, unknown>);
    if (!target) {
      next();
      return;
    }

    const subset = extractBodySubset(req.body, target.fields);
    if (Object.keys(subset).length === 0) {
      next();
      return;
    }

    let hits;
    try {
      hits = scanObjectForCredentials(subset);
    } catch (err) {
      logger.warn({ err, path: req.path }, "token-scanner: scan error, allowing request through");
      next();
      return;
    }

    if (hits.length === 0) {
      next();
      return;
    }

    const companyId = resolveCompanyId(req as Request);
    const actor = (req as any).actor as { type: string; agentId?: string; userId?: string } | undefined;
    const actorId =
      actor?.type === "agent"
        ? (actor.agentId ?? "agent")
        : actor?.type === "board"
          ? (actor.userId ?? "board")
          : "unknown";

    const blockingHit = hits.find((h) => h.group === "A" || h.group === "C");
    const alertHits = hits.filter((h) => h.group === "B");

    // Fire async Aegis alerts (never awaited — never blocks the response path)
    const allAlertHits = blockingHit ? [blockingHit, ...alertHits] : alertHits;
    if (companyId && allAlertHits.length > 0) {
      void notifyAegis(db, companyId, {
        field: allAlertHits[0].field,
        pattern: allAlertHits[0].pattern,
        group: allAlertHits[0].group,
        actorId,
        path: req.path,
      }).catch(() => {});
    }

    if (blockingHit) {
      res.status(422).json({
        error: "CREDENTIAL_DETECTED",
        message: `Plaintext credential detected in field '${blockingHit.field}'. Store credentials via secretRefs in the secret manager.`,
        field: blockingHit.field,
        group: blockingHit.group,
      });
      return;
    }

    next();
  };
}
