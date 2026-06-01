/**
 * Shared credential scanner module.
 *
 * Used by:
 *   - Layer 1 (GNO-752): API middleware pré-write
 *   - Layer 3 (GNO-753): pre-execution guard no heartbeat init
 *   - Layer 2 (GNO-754): batch scan retroativo
 *
 * Implements Grupo A (high-certainty patterns, block) and Grupo C
 * (sensitive field names in adapterConfig with inline values, block).
 *
 * Ref: GNO-66#document-plan, seções 3.3–3.4
 */

export type CredentialGroup = "A" | "C";

export type CredentialDetection = {
  /** Dot-separated path to the field (e.g. "env.TWITTER_TOKEN"). Never contains the value. */
  field: string;
  group: CredentialGroup;
  patternName: string;
};

export type ScanOptions = {
  /**
   * When true, strip markdown code blocks before scanning string values.
   * Default: true. Set to false only if you want to scan raw markdown.
   */
  stripCodeBlocks?: boolean;
  /**
   * Only report the first detection per object (stops traversal early).
   * Default: false — return all detections.
   */
  firstOnly?: boolean;
  /**
   * Parent path prefix for the root object (used for nested calls).
   */
  prefix?: string;
};

// ------ Field-level allowlist ------
// These field names are never scanned regardless of value content.
const FIELD_ALLOWLIST = new Set([
  "id",
  "identifier",
  "url",
  "iconUrl",
  "avatarUrl",
  "imageUrl",
  "logoUrl",
  "baseUrl",
  "webhookUrl",
  "callbackUrl",
  "redirectUrl",
]);

// The secretRefs top-level key holds correct secret name references, not
// inline values. Skip its children for Grupo C (values are vault key names).
const SECRET_REFS_FIELD = "secretRefs";

// ------ Grupo A patterns ------
// Each entry is applied to all string values, regardless of field name.
export const GROUP_A_PATTERNS: ReadonlyArray<{ readonly name: string; readonly pattern: RegExp }> = [
  { name: "twitter_bearer", pattern: /AAAA[A-Za-z0-9%+/\-_=]{50,}/ },
  { name: "twitter_access_token", pattern: /\b[0-9]{7,20}-[A-Za-z0-9]{20,50}\b/ },
  { name: "facebook_instagram_graph", pattern: /EAA[A-Za-z0-9]{50,}/ },
  { name: "instagram_legacy", pattern: /IGQV[A-Za-z0-9\-_]{50,}/ },
  { name: "google_oauth2_access", pattern: /ya29\.[A-Za-z0-9\-_]{50,}/ },
  { name: "google_refresh_token", pattern: /1\/\/[A-Za-z0-9\-_]{40,}/ },
  { name: "linkedin_oauth", pattern: /\bAQ[A-Za-z0-9\-_]{50,}/ },
  { name: "jwt_full", pattern: /ey[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}/ },
  { name: "bearer_header", pattern: /[Bb]earer\s+[A-Za-z0-9\-_=.+/]{20,}/ },
  { name: "github_pat", pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/ },
];

// ------ Grupo C keywords ------
// A field whose name (last segment) contains any of these keywords is
// subject to the "no inline value" rule.
export const GROUP_C_FIELD_KEYWORDS: ReadonlyArray<string> = [
  "key",
  "secret",
  "token",
  "password",
  "credential",
  "auth",
  "apikey",
  "api_key",
];

// Minimum string length for Grupo C to trigger (values shorter than this
// are unlikely to be real credentials; e.g. a secret vault key name).
const GROUP_C_MIN_VALUE_LENGTH = 16;

// ---- Helpers ----

function stripMarkdownCodeBlocks(text: string): string {
  return text.replace(/```[\s\S]*?```/g, "").replace(/`[^`]*`/g, "");
}

function lastSegment(path: string): string {
  const dot = path.lastIndexOf(".");
  return dot >= 0 ? path.slice(dot + 1) : path;
}

function isGroupCFieldName(fieldName: string): boolean {
  const lower = fieldName.toLowerCase().replace(/[-_]/g, "");
  return GROUP_C_FIELD_KEYWORDS.some((kw) => lower.includes(kw.replace(/[-_]/g, "")));
}

// ---- Core recursive scanner ----

function scanValue(
  value: unknown,
  fieldPath: string,
  insideSecretRefs: boolean,
  options: Required<ScanOptions>,
  results: CredentialDetection[],
): void {
  if (options.firstOnly && results.length > 0) return;

  if (value === null || value === undefined) return;

  if (typeof value === "string") {
    const text = options.stripCodeBlocks ? stripMarkdownCodeBlocks(value) : value;

    // Grupo A: check all string values
    for (const { name, pattern } of GROUP_A_PATTERNS) {
      if (pattern.test(text)) {
        results.push({ field: fieldPath, group: "A", patternName: name });
        return;
      }
    }

    // Grupo C: field name suggests credential + value is long enough
    // Skip if we're inside a secretRefs block (those are vault key names)
    if (!insideSecretRefs && fieldPath && isGroupCFieldName(lastSegment(fieldPath)) && text.length > GROUP_C_MIN_VALUE_LENGTH) {
      results.push({ field: fieldPath, group: "C", patternName: "sensitive_field_inline_value" });
    }

    return;
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (options.firstOnly && results.length > 0) return;
      scanValue(
        value[i],
        fieldPath ? `${fieldPath}[${i}]` : `[${i}]`,
        insideSecretRefs,
        options,
        results,
      );
    }
    return;
  }

  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (options.firstOnly && results.length > 0) return;
      if (FIELD_ALLOWLIST.has(key)) continue;
      const childPath = fieldPath ? `${fieldPath}.${key}` : key;
      const childInsideSecretRefs = insideSecretRefs || key === SECRET_REFS_FIELD;
      scanValue(child, childPath, childInsideSecretRefs, options, results);
    }
  }
}

/**
 * Scan a config object for plaintext credentials.
 *
 * Returns an array of detections. Each detection names the field path and
 * the pattern group that matched, but never the value itself.
 *
 * @param obj  The config object to scan (adapterConfig, runtimeConfig, …)
 * @param opts Scanning options
 */
export function scanObjectForCredentials(
  obj: unknown,
  opts: ScanOptions = {},
): CredentialDetection[] {
  const options: Required<ScanOptions> = {
    stripCodeBlocks: opts.stripCodeBlocks ?? true,
    firstOnly: opts.firstOnly ?? false,
    prefix: opts.prefix ?? "",
  };
  const results: CredentialDetection[] = [];
  scanValue(obj, options.prefix, false, options, results);
  return results;
}

/**
 * Quick check: returns the first credential detection or null.
 * More efficient when you only care about pass/fail (does not collect all hits).
 */
export function detectFirstCredential(obj: unknown): CredentialDetection | null {
  const results = scanObjectForCredentials(obj, { firstOnly: true });
  return results[0] ?? null;
}
