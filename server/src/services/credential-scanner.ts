/**
 * Credential scanner — shared token detection logic for Layer 1 (middleware),
 * Layer 2 (batch retroactive scan), and Layer 3 (pre-execution heartbeat guard).
 *
 * GNO-752 (Layer 1), GNO-753 (Layer 3), GNO-790 (persistence fix), GNO-799 (QA fixture suppression).
 */

export type CredentialGroup = "A" | "B" | "C";

export interface CredentialHit {
  group: CredentialGroup;
  pattern: string;
  field: string;
  /**
   * True when the scanned field contains a QA fixture marker (QA-NOSTORE or SCANNER-FIXTURE).
   * Layer 2 batch scanner logs these but does not create security issues.
   * Layer 1 and Layer 3 treat fixture=true hits identically to real hits (no evasion path).
   */
  fixture?: boolean;
}

/**
 * Markers that identify a field as a QA fixture — not a real credential.
 * Must appear in the same field as the detected pattern (field-level, not entity-level).
 * GNO-799.
 */
export const QA_FIXTURE_MARKERS = ["QA-NOSTORE", "SCANNER-FIXTURE"] as const;

export interface ScanOptions {
  /** Field names to skip entirely (besides the built-in exclusion list). */
  excludeFields?: string[];
  /** Only scan fields whose names match this list. */
  includeFields?: string[];
  /** Whether to strip markdown code blocks before scanning. Default: true. */
  stripMarkdown?: boolean;
}

// Fields that are never scanned regardless of content.
const ALWAYS_EXCLUDED_FIELDS = new Set(["identifier", "url", "iconUrl", "avatarUrl"]);

// Fields whose names suggest credential sensitivity (used for Group B/C checks).
const SENSITIVE_FIELD_PATTERNS = /key|secret|token|credential|auth|password|passwd|apikey|api_key/i;

// Group A — block + alert Aegis
const GROUP_A_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "twitter_bearer", re: /AAAA[A-Za-z0-9%+/\-_=]{50,}/ },
  { name: "twitter_access_token", re: /[0-9]{7,20}-[A-Za-z0-9]{20,50}/ },
  { name: "facebook_instagram_graph", re: /EAA[A-Za-z0-9]{50,}/ },
  { name: "instagram_legacy", re: /IGQV[A-Za-z0-9\-_]{50,}/ },
  { name: "google_oauth2", re: /ya29\.[A-Za-z0-9\-_]{50,}/ },
  { name: "google_refresh", re: /1\/\/[A-Za-z0-9\-_]{40,}/ },
  { name: "linkedin_oauth", re: /AQ[A-Za-z0-9\-_]{50,}/ },
  { name: "jwt", re: /ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/ },
  { name: "bearer_header", re: /[Bb]earer\s+[A-Za-z0-9\-_=.+/]{20,}/ },
  { name: "github_pat", re: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/ },
];

// Group B — alert Aegis only (no block)
const GROUP_B_HEX_RE = /[0-9a-f]{40,}/i;
const GROUP_B_BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/;
const GROUP_B_ALPHANUM_RE = /[A-Za-z0-9]{32,}/;

// Group C — adapterConfig/runtimeConfig long values (block, require secretRefs)
const GROUP_C_FIELDS = new Set(["apiKey", "api_key", "accessToken", "access_token", "token", "secret", "password", "passwd"]);
const GROUP_C_MIN_LENGTH = 16;

/** Remove fenced and inline markdown code blocks from a string before scanning. */
function stripMarkdownCode(text: string): string {
  // Remove fenced code blocks (``` ... ```)
  let stripped = text.replace(/```[\s\S]*?```/g, "");
  // Remove inline code (` ... `)
  stripped = stripped.replace(/`[^`]*`/g, "");
  return stripped;
}

function shouldExcludeField(fieldName: string, opts: ScanOptions): boolean {
  if (ALWAYS_EXCLUDED_FIELDS.has(fieldName)) return true;
  if (opts.excludeFields?.includes(fieldName)) return true;
  if (opts.includeFields && !opts.includeFields.includes(fieldName)) return true;
  return false;
}

/**
 * Returns true if the stripped (post-code-block-removal) field value contains a QA fixture marker.
 * Deliberately checks stripped text so a marker hidden inside a code block cannot suppress
 * detection of a real token outside that block. GNO-799.
 */
function hasFixtureMarker(strippedText: string): boolean {
  return QA_FIXTURE_MARKERS.some((m) => strippedText.includes(m));
}

/**
 * Scan a single string value for credential patterns.
 * Returns the first hit or null.
 */
function scanString(value: string, fieldName: string, opts: ScanOptions): CredentialHit | null {
  const text = opts.stripMarkdown !== false ? stripMarkdownCode(value) : value;
  if (!text.trim()) return null;

  const fixture = hasFixtureMarker(text);

  // Group A check
  for (const { name, re } of GROUP_A_PATTERNS) {
    if (re.test(text)) {
      return { group: "A", pattern: name, field: fieldName, fixture };
    }
  }

  // Group C check (sensitive fields in adapter/runtime config with long values)
  if (GROUP_C_FIELDS.has(fieldName) && text.length > GROUP_C_MIN_LENGTH) {
    return { group: "C", pattern: "long_sensitive_field", field: fieldName, fixture };
  }

  // Group B check (context-sensitive — only if field name looks like a credential field)
  if (SENSITIVE_FIELD_PATTERNS.test(fieldName)) {
    if (GROUP_B_HEX_RE.test(text)) {
      return { group: "B", pattern: "hex_40", field: fieldName, fixture };
    }
    if (GROUP_B_BASE64_RE.test(text)) {
      return { group: "B", pattern: "base64_40", field: fieldName, fixture };
    }
    if (GROUP_B_ALPHANUM_RE.test(text)) {
      return { group: "B", pattern: "alphanum_32", field: fieldName, fixture };
    }
  }

  return null;
}

/**
 * Recursively scan an object (flat or nested) for credential patterns.
 * Returns all hits found. Values are never logged — only field paths.
 */
export function scanObjectForCredentials(
  obj: unknown,
  opts: ScanOptions = {},
  _path = "",
): CredentialHit[] {
  const hits: CredentialHit[] = [];

  if (typeof obj === "string") {
    const hit = scanString(obj, _path || "(root)", opts);
    if (hit) hits.push(hit);
    return hits;
  }

  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return hits;

  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const fieldPath = _path ? `${_path}.${key}` : key;
    if (shouldExcludeField(key, opts)) continue;

    if (typeof value === "string") {
      const hit = scanString(value, fieldPath, opts);
      if (hit) hits.push(hit);
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      hits.push(...scanObjectForCredentials(value, opts, fieldPath));
    }
  }

  return hits;
}

/**
 * Returns the first credential hit or null.
 * Optimized for early exit — use for blocking checks.
 */
export function detectFirstCredential(
  obj: unknown,
  opts: ScanOptions = {},
): CredentialHit | null {
  if (typeof obj === "string") {
    return scanString(obj, "(root)", opts);
  }

  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;

  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (shouldExcludeField(key, opts)) continue;

    if (typeof value === "string") {
      const hit = scanString(value, key, opts);
      if (hit) return hit;
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      const hit = detectFirstCredential(value, opts);
      if (hit) return hit;
    }
  }

  return null;
}
