import type { AdapterModelProfileDefinition } from "@paperclipai/adapter-utils";

export const type = "claude_local";
export const label = "Claude Code (local)";

export const SANDBOX_INSTALL_COMMAND = "npm install -g @anthropic-ai/claude-code";

export const models = [
  { id: "claude-opus-4-8", label: "Claude Opus 4.8" },
  { id: "claude-opus-4-7", label: "Claude Opus 4.7" },
  { id: "claude-opus-4-6", label: "Claude Opus 4.6" },
  { id: "claude-sonnet-4-6", label: "Claude Sonnet 4.6" },
  { id: "claude-haiku-4-6", label: "Claude Haiku 4.6" },
  { id: "claude-sonnet-4-5-20250929", label: "Claude Sonnet 4.5" },
  { id: "claude-haiku-4-5-20251001", label: "Claude Haiku 4.5" },
];

export const modelProfiles: AdapterModelProfileDefinition[] = [
  {
    key: "cheap",
    label: "Cheap",
    description: "Use Claude Sonnet as the lower-cost Claude Code lane while preserving the agent's primary model.",
    adapterConfig: {
      model: "claude-sonnet-4-6",
      effort: "low",
    },
    source: "adapter_default",
  },
];

export const agentConfigurationDoc = `# claude_local agent configuration

Adapter: claude_local

Core fields:
- cwd (string, optional): default absolute working directory fallback for the agent process (created if missing when possible)
- model (string, optional): Claude model id
- effort (string, optional): reasoning effort passed via --effort (low|medium|high)
- chrome (boolean, optional): pass --chrome when running Claude
- promptTemplate (string, optional): run prompt template
- maxTurnsPerRun (number, optional): max turns for one run
- dangerouslySkipPermissions (boolean, optional, default true): pass --dangerously-skip-permissions to claude; defaults to true because Paperclip runs Claude in headless --print mode where interactive permission prompts cannot be answered
- command (string, optional): defaults to "claude"
- extraArgs (string[], optional): additional CLI args
- env (object, optional): KEY=VALUE environment variables
- workspaceStrategy (object, optional): execution workspace strategy; currently supports { type: "git_worktree", baseRef?, branchTemplate?, worktreeParentDir? }
- workspaceRuntime (object, optional): reserved for workspace runtime metadata; workspace runtime services are manually controlled from the workspace UI and are not auto-started by heartbeats
- workspaceRuntimeConfig (object, optional): alternate/companion key for workspace runtime config found in production; aligns with workspaceRuntime semantics

Operational fields:
- timeoutSec (number, optional): run timeout in seconds
- graceSec (number, optional): SIGTERM grace period in seconds

Instructions bundle subsystem (preferred over instructionsFilePath for multi-file bundles):
- instructionsBundleMode (string, optional): "managed" (Paperclip manages bundle) or "external" (agent-side path resolution)
- instructionsRootPath (string, optional): absolute root directory of the instructions bundle; Paperclip scans and serves files from here
- instructionsEntryFile (string, optional): filename of the bundle entry point relative to instructionsRootPath; defaults to "AGENTS.md"
- instructionsFilePath (string, optional, legacy): absolute path to a single markdown instructions file; superseded by the bundle subsystem; kept for backward compatibility

Skill sync subsystem:
- paperclipSkillSync (object, optional): { desiredSkills: string[] } — list of company skill keys to install and keep in sync on this agent; managed by the skills/sync API and surfaced in the agent UI

runtimeConfig fields:
- heartbeat (object, optional): { enabled: boolean, wakeOnDemand: boolean, maxConcurrentRuns: number } — controls scheduler heartbeat behaviour
- budget (object, optional): { monthlyUsd: number } — per-agent monthly spend cap; legitimate billing control field (confirmed in production, e.g. Iris)

Notes:
- When Paperclip realizes a workspace/runtime for a run, it injects PAPERCLIP_WORKSPACE_* and PAPERCLIP_RUNTIME_* env vars for agent-side tooling.

Known benign legacy fields (GNO-1109, 2026-06-08 — accepted residuals, non-exploitable):
- adapterConfig.internalAuthHash: null — Argus only; VALUE nulled in GNO-1067; KEY persists as residue of PATCH-null pattern that did not remove the key. Non-secret (null value), masked by GNO-916 redaction layer.
- adapterConfig.type: "claude_local" — Argus only; duplicates adapterType top-level field; residue of old seeder.
- adapterConfig.mode: "" — Daedalus only; empty string residue from codex_local → claude_local migration.
- adapterConfig.variant: "" — Daedalus only; empty string residue from codex_local → claude_local migration.
- adapterConfig.modelReasoningEffort: "" — Daedalus only; empty string residue from codex_local → claude_local migration.
These five keys were registered as accepted artifacts instead of being PATCHed out (Hephaestus lacks agents:create; Atlas sweep GNO-1108 confirmed non-exploitable). Future orphan-field audits should skip these known keys.
`;
