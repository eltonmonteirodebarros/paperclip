// Spec ref: GNO-926 / GNO-915 §5 — adapter_env.read_masked audit event emitted by choke point.
import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("acpx/runtime", () => ({
  createAcpRuntime: vi.fn(),
  createAgentRegistry: vi.fn(),
  createRuntimeStore: vi.fn(),
  isAcpRuntimeError: vi.fn(() => false),
}));

const agentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const companyId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const baseAgent = {
  id: agentId,
  companyId,
  name: "TestAgent",
  urlKey: "test-agent",
  role: "engineer",
  title: "Test Agent",
  icon: null,
  status: "idle",
  reportsTo: null,
  capabilities: null,
  adapterType: "process",
  adapterConfig: {
    env: {
      GITHUB_TOKEN: { type: "plain", value: "ghp_supersecret" },
      API_KEY: { type: "plain", value: "sk-abcdef" },
    },
  },
  runtimeConfig: {},
  budgetMonthlyCents: 0,
  spentMonthlyCents: 0,
  pauseReason: null,
  pausedAt: null,
  permissions: { canCreateAgents: false },
  lastHeartbeatAt: null,
  metadata: null,
  defaultEnvironmentId: null,
  createdAt: new Date("2026-01-01T00:00:00.000Z"),
  updatedAt: new Date("2026-01-01T00:00:00.000Z"),
};

const mockAgentService = vi.hoisted(() => ({
  getById: vi.fn(),
  list: vi.fn(),
  create: vi.fn(),
  activatePendingApproval: vi.fn(),
  update: vi.fn(),
  updatePermissions: vi.fn(),
  getChainOfCommand: vi.fn(),
  resolveByReference: vi.fn(),
  rollbackConfigRevision: vi.fn(),
  pause: vi.fn(),
  resume: vi.fn(),
  remove: vi.fn(),
  terminate: vi.fn(),
}));

const mockAccessService = vi.hoisted(() => ({
  canUser: vi.fn(),
  decide: vi.fn(),
  hasPermission: vi.fn(),
  getMembership: vi.fn(),
  ensureMembership: vi.fn(),
  listPrincipalGrants: vi.fn(),
  setPrincipalPermission: vi.fn(),
}));

const mockApprovalService = vi.hoisted(() => ({
  create: vi.fn(),
  getById: vi.fn(),
}));

const mockBudgetService = vi.hoisted(() => ({ upsertPolicy: vi.fn() }));
const mockHeartbeatService = vi.hoisted(() => ({
  listTaskSessions: vi.fn(),
  resetRuntimeSession: vi.fn(),
  getRun: vi.fn(),
  cancelRun: vi.fn(),
  cancelActiveForAgent: vi.fn(),
}));
const mockIssueApprovalService = vi.hoisted(() => ({ linkManyForApproval: vi.fn() }));
const mockIssueService = vi.hoisted(() => ({ list: vi.fn() }));
const mockSecretService = vi.hoisted(() => ({
  normalizeAdapterConfigForPersistence: vi.fn(),
  resolveAdapterConfigForRuntime: vi.fn(),
  syncEnvBindingsForTarget: vi.fn(),
}));
const mockAgentInstructionsService = vi.hoisted(() => ({
  materializeManagedBundle: vi.fn(),
}));
const mockCompanySkillService = vi.hoisted(() => ({
  listRuntimeSkillEntries: vi.fn(),
  resolveRequestedSkillKeys: vi.fn(),
}));
const mockWorkspaceOperationService = vi.hoisted(() => ({}));
const mockLogActivity = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
const mockGetTelemetryClient = vi.hoisted(() => vi.fn().mockReturnValue(null));
const mockSyncInstructionsBundleConfigFromFilePath = vi.hoisted(() => vi.fn((_, cfg) => cfg));
const mockEnsureOpenCodeModelConfiguredAndAvailable = vi.hoisted(() => vi.fn());
const mockEnvironmentService = vi.hoisted(() => ({ getById: vi.fn() }));
const mockInstanceSettingsService = vi.hoisted(() => ({
  getGeneral: vi.fn().mockResolvedValue({ censorUsernameInLogs: false }),
}));

function registerModuleMocks() {
  vi.doMock("@paperclipai/adapter-opencode-local/server", async () => {
    const actual = await vi.importActual<typeof import("@paperclipai/adapter-opencode-local/server")>(
      "@paperclipai/adapter-opencode-local/server",
    );
    return { ...actual, ensureOpenCodeModelConfiguredAndAvailable: mockEnsureOpenCodeModelConfiguredAndAvailable };
  });

  vi.doMock("@paperclipai/shared/telemetry", () => ({
    trackAgentCreated: vi.fn(),
    trackErrorHandlerCrash: vi.fn(),
  }));

  vi.doMock("../telemetry.js", () => ({ getTelemetryClient: mockGetTelemetryClient }));
  vi.doMock("../services/agents.js", () => ({ agentService: () => mockAgentService }));
  vi.doMock("../services/access.js", () => ({ accessService: () => mockAccessService }));
  vi.doMock("../services/approvals.js", () => ({ approvalService: () => mockApprovalService }));
  vi.doMock("../services/company-skills.js", () => ({ companySkillService: () => mockCompanySkillService }));
  vi.doMock("../services/budgets.js", () => ({ budgetService: () => mockBudgetService }));
  vi.doMock("../services/heartbeat.js", () => ({ heartbeatService: () => mockHeartbeatService }));
  vi.doMock("../services/issue-approvals.js", () => ({ issueApprovalService: () => mockIssueApprovalService }));
  vi.doMock("../services/issues.js", () => ({ issueService: () => mockIssueService }));
  vi.doMock("../services/secrets.js", () => ({ secretService: () => mockSecretService }));
  vi.doMock("../services/environments.js", () => ({ environmentService: () => mockEnvironmentService }));
  vi.doMock("../services/agent-instructions.js", () => ({
    agentInstructionsService: () => mockAgentInstructionsService,
    syncInstructionsBundleConfigFromFilePath: mockSyncInstructionsBundleConfigFromFilePath,
  }));
  vi.doMock("../services/workspace-operations.js", () => ({
    workspaceOperationService: () => mockWorkspaceOperationService,
  }));
  vi.doMock("../services/activity-log.js", () => ({ logActivity: mockLogActivity }));
  vi.doMock("../services/instance-settings.js", () => ({
    instanceSettingsService: () => mockInstanceSettingsService,
  }));
  vi.doMock("../services/index.js", () => ({
    agentService: () => mockAgentService,
    agentInstructionsService: () => mockAgentInstructionsService,
    accessService: () => mockAccessService,
    approvalService: () => mockApprovalService,
    companySkillService: () => mockCompanySkillService,
    budgetService: () => mockBudgetService,
    heartbeatService: () => mockHeartbeatService,
    ISSUE_LIST_DEFAULT_LIMIT: 500,
    issueApprovalService: () => mockIssueApprovalService,
    issueService: () => mockIssueService,
    logActivity: mockLogActivity,
    secretService: () => mockSecretService,
    syncInstructionsBundleConfigFromFilePath: mockSyncInstructionsBundleConfigFromFilePath,
    workspaceOperationService: () => mockWorkspaceOperationService,
    environmentService: () => mockEnvironmentService,
  }));
}

function createDbStub() {
  return {
    select: vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          then: vi.fn((resolve) =>
            Promise.resolve(
              resolve([{ id: companyId, name: "Paperclip", requireBoardApprovalForNewAgents: false }]),
            ),
          ),
        }),
      }),
    }),
  };
}

async function createApp(actor: Record<string, unknown>) {
  const [{ errorHandler }, { agentRoutes }] = await Promise.all([
    import("../middleware/index.js") as Promise<typeof import("../middleware/index.js")>,
    import("../routes/agents.js") as Promise<typeof import("../routes/agents.js")>,
  ]);
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    (req as any).actor = { ...actor, companyIds: [companyId] };
    next();
  });
  app.use("/api", agentRoutes(createDbStub() as any));
  app.use(errorHandler);
  return app;
}

async function requestApp(app: express.Express, buildRequest: (baseUrl: string) => request.Test) {
  const { createServer } = await vi.importActual<typeof import("node:http")>("node:http");
  const server = createServer(app);
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No address");
    return await buildRequest(`http://127.0.0.1:${(address as { port: number }).port}`);
  } finally {
    if (server.listening) {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    }
  }
}

const agentActor = {
  type: "agent",
  agentId,
  companyId,
  companyIds: [companyId],
  runId: "run-001",
};

describe.sequential("adapter_env.read_masked audit event (GNO-926)", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.doUnmock("@paperclipai/shared/telemetry");
    vi.doUnmock("../telemetry.js");
    vi.doUnmock("../services/access.js");
    vi.doUnmock("../services/activity-log.js");
    vi.doUnmock("../services/agent-instructions.js");
    vi.doUnmock("../services/agents.js");
    vi.doUnmock("../services/approvals.js");
    vi.doUnmock("../services/budgets.js");
    vi.doUnmock("../services/company-skills.js");
    vi.doUnmock("../services/heartbeat.js");
    vi.doUnmock("../services/index.js");
    vi.doUnmock("../services/instance-settings.js");
    vi.doUnmock("../services/issue-approvals.js");
    vi.doUnmock("../services/issues.js");
    vi.doUnmock("../services/secrets.js");
    vi.doUnmock("../services/environments.js");
    vi.doUnmock("../services/workspace-operations.js");
    vi.doUnmock("../adapters/index.js");
    vi.doUnmock("../routes/agents.js");
    vi.doUnmock("../routes/authz.js");
    vi.doUnmock("../middleware/index.js");
    vi.doUnmock("@paperclipai/adapter-opencode-local/server");
    registerModuleMocks();
    vi.resetAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
    mockGetTelemetryClient.mockReturnValue(null);
    mockSyncInstructionsBundleConfigFromFilePath.mockImplementation((_a: unknown, cfg: unknown) => cfg);
    mockInstanceSettingsService.getGeneral.mockResolvedValue({ censorUsernameInLogs: false });
    mockAgentService.getChainOfCommand.mockResolvedValue([]);
    mockAccessService.listPrincipalGrants.mockResolvedValue([]);
    mockAccessService.getMembership.mockResolvedValue(null);
    mockAccessService.hasPermission.mockResolvedValue(false);
    mockAccessService.canUser.mockResolvedValue(false);
    mockAgentService.getById.mockResolvedValue(baseAgent);
  });

  it("emits adapter_env.read_masked on GET /agents/me with keys from adapterConfig", async () => {
    const app = await createApp(agentActor);
    const res = await requestApp(app, (base) => request(base).get("/api/agents/me"));
    expect(res.status).toBe(200);

    const readMaskedCalls = mockLogActivity.mock.calls.filter(
      ([, input]: [unknown, { action: string }]) => input.action === "adapter_env.read_masked",
    );
    expect(readMaskedCalls).toHaveLength(1);
    const [, input] = readMaskedCalls[0] as [unknown, { action: string; details: { keys: string[]; targetAgentId: string } }];
    expect(input.details.keys).toEqual(expect.arrayContaining(["GITHUB_TOKEN", "API_KEY"]));
    expect(input.details.targetAgentId).toBe(agentId);
  });

  it("does not emit adapter_env.read_masked when agent has no env vars", async () => {
    mockAgentService.getById.mockResolvedValue({ ...baseAgent, adapterConfig: {} });
    const app = await createApp(agentActor);
    const res = await requestApp(app, (base) => request(base).get("/api/agents/me"));
    expect(res.status).toBe(200);

    const readMaskedCalls = mockLogActivity.mock.calls.filter(
      ([, input]: [unknown, { action: string }]) => input.action === "adapter_env.read_masked",
    );
    expect(readMaskedCalls).toHaveLength(0);
  });

  it("emits adapter_env.read_masked on GET /agents/:id (non-restricted path)", async () => {
    mockAccessService.decide.mockResolvedValue({ allowed: true });
    const boardActor = { type: "board", userId: "user-123", companyId, companyIds: [companyId] };
    const app = await createApp(boardActor);
    const res = await requestApp(app, (base) => request(base).get(`/api/agents/${agentId}`));
    expect(res.status).toBe(200);

    const readMaskedCalls = mockLogActivity.mock.calls.filter(
      ([, input]: [unknown, { action: string }]) => input.action === "adapter_env.read_masked",
    );
    expect(readMaskedCalls).toHaveLength(1);
    const [, input] = readMaskedCalls[0] as [unknown, { details: { keys: string[]; targetAgentId: string } }];
    expect(input.details.targetAgentId).toBe(agentId);
    expect(input.details.keys).toEqual(expect.arrayContaining(["GITHUB_TOKEN", "API_KEY"]));
  });

  it("does NOT emit adapter_env.read_masked for restricted GET /agents/:id view", async () => {
    mockAccessService.decide.mockResolvedValue({ allowed: false });
    const otherAgentActor = {
      type: "agent",
      agentId: "other-agent-id",
      companyId,
      companyIds: [companyId],
    };
    const app = await createApp(otherAgentActor);
    const res = await requestApp(app, (base) => request(base).get(`/api/agents/${agentId}`));
    expect(res.status).toBe(200);

    const readMaskedCalls = mockLogActivity.mock.calls.filter(
      ([, input]: [unknown, { action: string }]) => input.action === "adapter_env.read_masked",
    );
    expect(readMaskedCalls).toHaveLength(0);
  });
});
