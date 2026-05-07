import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { resolvePluginConfig, validatePluginConfig } from "./config.js";
import { parseGmailPushNotification } from "./gmail.js";
import { createGoogleapisGmailClient } from "./gmailClient.js";
import { gmailScopesAllowModify, resolveGoogleAuthMaterial, resolveSecretResolver } from "./googleAuth.js";
import { createHostActionDeps } from "./hostActions.js";
import { createOpenAiRouterClassifier } from "./openaiRouterClassifier.js";
import { createOpenAiSecurityClassifier, resolveOpenAiApiKey } from "./openaiSecurityClassifier.js";
import { createNoopRouterClassifier } from "./routerClassifier.js";
import { createUnavailableGmailClientFactory, GmailIntakePollingRuntime } from "./runtime.js";
import { createUnavailableSecurityClassifier } from "./securityClassifier.js";
import { openSqliteStateStore, type SqliteStateStore } from "./state.js";
import type { GmailSourceConfig } from "./types.js";

type RuntimeReadinessFinding = {
  severity: "error" | "warning";
  path: string;
  message: string;
};

const PUBSUB_ROUTE_ID = "gmail-intake-firewall-pubsub";
const PUBSUB_ROUTE_PATH = "/gmail-intake-firewall/pubsub";
const PUBSUB_ROUTE_AUTH = "plugin" as const;
const PUBSUB_ROUTE_MATCH = "exact" as const;
const PUBSUB_ROUTE_ACTIVATION_HINT = "gateway-webhook";

export function registerGmailIntakeFirewallPlugin(api: unknown): void {
  const host = api && typeof api === "object" ? api as Record<string, unknown> : {};
  const rawConfig = "pluginConfig" in host ? host.pluginConfig : "config" in host ? host.config : undefined;
  const config = resolvePluginConfig(rawConfig);

  const logger = host.logger && typeof host.logger === "object"
    ? host.logger as { info?: (message: string, metadata?: Record<string, unknown>) => void }
    : undefined;

  logger?.info?.("gmail-intake-firewall registered", {
    enabled: config.enabled,
    dryRun: config.dryRun,
    sources: config.sources.length,
  });

  const service = buildGmailIntakeFirewallService(config, api, logger);

  if (hasRegisterService(api)) {
    api.registerService(service);
  }

  if (hasRegisterTool(api)) {
    api.registerTool(buildOperatorStatusTool(service), { name: "gmail_intake_firewall_status" });
    api.registerTool(buildReviewTool(service), { name: "gmail_intake_firewall_review" });
  }

  if (hasRegisterHttpRoute(api)) {
    api.registerHttpRoute(buildPubSubHttpRoute(service, config));
  }

  void createUnavailableSecurityClassifier();
  void createNoopRouterClassifier();
}

function buildPubSubHttpRoute(
  service: ReturnType<typeof buildGmailIntakeFirewallService>,
  config: ReturnType<typeof resolvePluginConfig>,
): {
  id: string;
  path: string;
  auth: "plugin";
  match: "exact";
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;
} {
  return {
    id: PUBSUB_ROUTE_ID,
    path: PUBSUB_ROUTE_PATH,
    auth: PUBSUB_ROUTE_AUTH,
    match: PUBSUB_ROUTE_MATCH,
    async handler(req, res) {
      if (req.method && req.method.toUpperCase() !== "POST") {
        sendJson(res, 405, { ok: false, error: "method_not_allowed" }, { Allow: "POST" });
        return true;
      }
      if (!config.webhookSecret) {
        sendJson(res, 503, { ok: false, error: "webhook_secret_not_configured" });
        return true;
      }
      if (!requestHasWebhookSecret(req, config.webhookSecret)) {
        sendJson(res, 401, { ok: false, error: "unauthorized" });
        return true;
      }
      const serviceReady = await ensureHttpServiceStarted(service);
      if (!serviceReady.ok) {
        sendJson(res, 503, serviceReady.body);
        return true;
      }
      const body = await readJsonRequestBody(req, 256 * 1024);
      if (!body.ok) {
        sendJson(res, body.status, { ok: false, error: body.error });
        return true;
      }
      try {
        const result = await service.handleGmailNotification(body.value as Record<string, unknown>);
        sendJson(res, 200, result);
      } catch (error) {
        sendJson(res, 400, {
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
      return true;
    },
  };
}

async function ensureHttpServiceStarted(
  service: ReturnType<typeof buildGmailIntakeFirewallService>,
): Promise<
  | { ok: true }
  | { ok: false; body: Record<string, unknown> }
> {
  const status = await service.status();
  if (status.started === true) {
    return { ok: true };
  }
  const start = await service.start();
  if (start.ok === true && start.state === "ready") {
    return { ok: true };
  }
  return {
    ok: false,
    body: {
      ok: false,
      error: "service_not_ready",
      service: start,
    },
  };
}

function pubSubHttpRouteStatus(config: ReturnType<typeof resolvePluginConfig>): Record<string, unknown> {
  return {
    id: PUBSUB_ROUTE_ID,
    path: PUBSUB_ROUTE_PATH,
    auth: PUBSUB_ROUTE_AUTH,
    match: PUBSUB_ROUTE_MATCH,
    webhookSecretConfigured: Boolean(config.webhookSecret),
    routeActivationHint: PUBSUB_ROUTE_ACTIVATION_HINT,
  };
}

function buildOperatorStatusTool(service: ReturnType<typeof buildGmailIntakeFirewallService>): {
  id: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  schema: Record<string, unknown>;
  parameters: Record<string, unknown>;
  handler: (input: unknown) => Promise<Record<string, unknown>>;
  run: (input: unknown) => Promise<Record<string, unknown>>;
  execute: (input: unknown) => Promise<Record<string, unknown>>;
} {
  const schema = {
    type: "object",
    additionalProperties: false,
    properties: {
      operation: {
        type: "string",
        enum: ["status", "probe", "validateConfig", "checkSourceAuth", "doctor", "supportBundle", "setupWatch", "renewWatch", "renewAllWatches", "repairWatch"],
        default: "status",
      },
      sourceId: {
        type: "string",
      },
      force: {
        type: "boolean",
      },
    },
  };
  const run = async (input: unknown): Promise<Record<string, unknown>> => {
    const normalizedInput = normalizeToolInput(input);
    const operation = normalizedInput && "operation" in normalizedInput
      ? normalizedInput.operation
      : "status";
    if (operation === "probe") {
      return service.probe();
    }
    if (operation === "validateConfig") {
      return service.validateConfig();
    }
    if (operation === "checkSourceAuth") {
      const sourceId = typeof normalizedInput?.sourceId === "string"
        ? normalizedInput.sourceId
        : undefined;
      return service.checkSourceAuth(sourceId ? { sourceId } : {});
    }
    if (operation === "doctor") {
      return service.doctor();
    }
    if (operation === "supportBundle") {
      return service.supportBundle();
    }
    if (operation === "setupWatch") {
      return service.setupWatch({
        ...(typeof normalizedInput?.sourceId === "string" ? { sourceId: normalizedInput.sourceId } : {}),
        ...(typeof normalizedInput?.force === "boolean" ? { force: normalizedInput.force } : {}),
      });
    }
    if (operation === "renewWatch" || operation === "renewAllWatches") {
      return service.renewWatch({
        ...(typeof normalizedInput?.sourceId === "string" ? { sourceId: normalizedInput.sourceId } : {}),
        ...(typeof normalizedInput?.force === "boolean" ? { force: normalizedInput.force } : {}),
      });
    }
    if (operation === "repairWatch") {
      return service.repairWatch({
        ...(typeof normalizedInput?.sourceId === "string" ? { sourceId: normalizedInput.sourceId } : {}),
        ...(typeof normalizedInput?.force === "boolean" ? { force: normalizedInput.force } : {}),
      });
    }
    return service.status();
  };
  return {
    id: "gmail_intake_firewall_status",
    name: "gmail_intake_firewall_status",
    description: "Read-only operator status, probe, config validation, and redacted Gmail auth checks for the Gmail intake firewall plugin.",
    inputSchema: schema,
    schema,
    parameters: schema,
    handler: run,
    run,
    execute: run,
  };
}

function buildReviewTool(service: ReturnType<typeof buildGmailIntakeFirewallService>): {
  id: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  schema: Record<string, unknown>;
  parameters: Record<string, unknown>;
  handler: (input: unknown) => Promise<Record<string, unknown>>;
  run: (input: unknown) => Promise<Record<string, unknown>>;
  execute: (input: unknown) => Promise<Record<string, unknown>>;
} {
  const schema = {
    type: "object",
    additionalProperties: false,
    properties: {
      operation: {
        type: "string",
        enum: [
          "listQuarantine",
          "getQuarantineItem",
          "recordFeedback",
          "markHarmful",
          "wakeNow",
          "releaseFromQuarantine",
          "replayWithFeedback",
          "muteSender",
          "unmuteSender",
          "alwaysAggregate",
          "removeAlwaysAggregate",
          "muteDomain",
          "unmuteDomain",
          "alwaysAggregateDomain",
          "removeAlwaysAggregateDomain",
          "listPreferences",
          "reviewSummary",
        ],
      },
      sourceId: { type: "string" },
      messageId: { type: "string" },
      actor: { type: "string" },
      reason: { type: "string" },
      feedbackType: { type: "string" },
      sender: { type: "string" },
      domain: { type: "string" },
      wakeTarget: { type: "string" },
      limit: { type: "number" },
      restoreInbox: { type: "boolean" },
      force: { type: "boolean" },
      dryRun: { type: "boolean" },
    },
    required: ["operation"],
  };
  const run = async (input: unknown): Promise<Record<string, unknown>> => {
    const normalizedInput = normalizeToolInput(input);
    const operation = typeof normalizedInput?.operation === "string" ? normalizedInput.operation : undefined;
    if (operation === "listQuarantine") {
      return service.listQuarantine({
        limit: numberInput(normalizedInput?.limit, 25),
        ...(typeof normalizedInput?.sourceId === "string" ? { sourceId: normalizedInput.sourceId } : {}),
      });
    }
    if (operation === "listPreferences") {
      return service.listPreferences({
        ...(typeof normalizedInput?.sourceId === "string" ? { sourceId: normalizedInput.sourceId } : {}),
      });
    }
    if (operation === "reviewSummary") {
      return service.reviewSummary({
        ...(typeof normalizedInput?.sourceId === "string" ? { sourceId: normalizedInput.sourceId } : {}),
      });
    }
    const sourceId = typeof normalizedInput?.sourceId === "string" ? normalizedInput.sourceId : undefined;
    const messageId = typeof normalizedInput?.messageId === "string" ? normalizedInput.messageId : undefined;
    if (!sourceId || !messageId) {
      throw new Error(`${operation ?? "review operation"} requires sourceId and messageId`);
    }
    const common = {
      sourceId,
      messageId,
      ...(typeof normalizedInput?.actor === "string" ? { actor: normalizedInput.actor } : {}),
      ...(typeof normalizedInput?.reason === "string" ? { reason: normalizedInput.reason } : {}),
      ...(typeof normalizedInput?.sender === "string" ? { sender: normalizedInput.sender } : {}),
      ...(typeof normalizedInput?.domain === "string" ? { domain: normalizedInput.domain } : {}),
    };
    if (operation === "getQuarantineItem") {
      return service.getQuarantineItem({ sourceId, messageId });
    }
    if (operation === "markHarmful") {
      return service.recordReviewFeedback({ ...common, feedbackType: "harmful" });
    }
    if (operation === "muteSender") {
      return service.recordReviewFeedback({ ...common, feedbackType: "mute_sender" });
    }
    if (operation === "unmuteSender") {
      return service.recordReviewFeedback({ ...common, feedbackType: "unmute_sender" });
    }
    if (operation === "alwaysAggregate") {
      return service.recordReviewFeedback({ ...common, feedbackType: "always_aggregate" });
    }
    if (operation === "removeAlwaysAggregate") {
      return service.recordReviewFeedback({ ...common, feedbackType: "remove_always_aggregate" });
    }
    if (operation === "muteDomain") {
      return service.recordReviewFeedback({ ...common, feedbackType: "mute_domain" });
    }
    if (operation === "unmuteDomain") {
      return service.recordReviewFeedback({ ...common, feedbackType: "unmute_domain" });
    }
    if (operation === "alwaysAggregateDomain") {
      return service.recordReviewFeedback({ ...common, feedbackType: "always_aggregate_domain" });
    }
    if (operation === "removeAlwaysAggregateDomain") {
      return service.recordReviewFeedback({ ...common, feedbackType: "remove_always_aggregate_domain" });
    }
    if (operation === "wakeNow") {
      return service.wakeReviewedMessage({
        ...common,
        ...(typeof normalizedInput?.wakeTarget === "string" ? { wakeTarget: normalizedInput.wakeTarget } : {}),
        ...(typeof normalizedInput?.dryRun === "boolean" ? { dryRun: normalizedInput.dryRun } : {}),
      });
    }
    if (operation === "releaseFromQuarantine") {
      return service.releaseFromQuarantine({
        ...common,
        ...(typeof normalizedInput?.restoreInbox === "boolean" ? { restoreInbox: normalizedInput.restoreInbox } : {}),
        ...(typeof normalizedInput?.dryRun === "boolean" ? { dryRun: normalizedInput.dryRun } : {}),
      });
    }
    if (operation === "replayWithFeedback") {
      return service.replayWithFeedback({
        ...common,
        ...(typeof normalizedInput?.feedbackType === "string" ? { feedbackType: normalizedInput.feedbackType } : {}),
        ...(typeof normalizedInput?.force === "boolean" ? { force: normalizedInput.force } : {}),
        ...(typeof normalizedInput?.dryRun === "boolean" ? { dryRun: normalizedInput.dryRun } : {}),
      });
    }
    if (operation === "recordFeedback") {
      const feedbackType = typeof normalizedInput?.feedbackType === "string" ? normalizedInput.feedbackType : "feedback";
      return service.recordReviewFeedback({ ...common, feedbackType });
    }
    throw new Error(`Unknown review operation: ${operation ?? "undefined"}`);
  };
  return {
    id: "gmail_intake_firewall_review",
    name: "gmail_intake_firewall_review",
    description: "Text-based quarantine review and feedback tool for Gmail intake firewall decisions.",
    inputSchema: schema,
    schema,
    parameters: schema,
    handler: run,
    run,
    execute: run,
  };
}

function normalizeToolInput(input: unknown): Record<string, unknown> | undefined {
  if (!input || typeof input !== "object") {
    return undefined;
  }
  const raw = input as Record<string, unknown>;
  if (typeof raw.operation === "string") {
    return raw;
  }
  for (const key of ["input", "arguments", "args", "params"]) {
    const nested = raw[key];
    if (nested && typeof nested === "object" && typeof (nested as Record<string, unknown>).operation === "string") {
      return nested as Record<string, unknown>;
    }
  }
  return raw;
}

function numberInput(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function buildGmailIntakeFirewallService(
  config: ReturnType<typeof resolvePluginConfig>,
  host: unknown,
  logger?: { info?: (message: string, metadata?: Record<string, unknown>) => void; error?: (message: string, metadata?: Record<string, unknown>) => void },
): {
  id: string;
  name: string;
  description: string;
  start: () => Promise<Record<string, unknown>>;
  stop: () => Promise<Record<string, unknown>>;
  probe: () => Promise<Record<string, unknown>>;
  status: () => Promise<Record<string, unknown>>;
  validateConfig: () => Promise<Record<string, unknown>>;
  doctor: () => Promise<Record<string, unknown>>;
  supportBundle: () => Promise<Record<string, unknown>>;
  backfill: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  inspectMessage: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  replayEvent: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  drainAggregates: () => Promise<Record<string, unknown>>;
  handleGmailNotification: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  setupWatch: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  renewWatch: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  repairWatch: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  checkSourceAuth: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  recordFeedback: (event: Record<string, unknown>) => Promise<Record<string, unknown>>;
  listQuarantine: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  getQuarantineItem: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  recordReviewFeedback: (event: Record<string, unknown>) => Promise<Record<string, unknown>>;
  wakeReviewedMessage: (event: Record<string, unknown>) => Promise<Record<string, unknown>>;
  releaseFromQuarantine: (event: Record<string, unknown>) => Promise<Record<string, unknown>>;
  replayWithFeedback: (event: Record<string, unknown>) => Promise<Record<string, unknown>>;
  listPreferences: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  reviewSummary: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
} {
  let runtime: GmailIntakePollingRuntime | undefined;
  let stateStore: SqliteStateStore | undefined;
  let runtimeReadiness: RuntimeReadinessFinding[] = [];
  return {
    id: "gmail-intake-firewall-service",
    name: "Gmail Intake Firewall Service",
    description: "Polling runtime for Gmail intake classification and routing.",
    async start() {
      if (!config.enabled) {
        return {
          ok: true,
          service: "gmail-intake-firewall-service",
          enabled: false,
          sources: 0,
          dryRun: config.dryRun,
          state: "disabled",
        };
      }
      stateStore = openSqliteStateStore(config.sqlitePath);
      const validation = validatePluginConfig(config);
      const errors = validation.filter((finding) => finding.severity === "error");
      if (errors.length > 0) {
        stateStore.close();
        stateStore = undefined;
        return {
          ok: false,
          service: "gmail-intake-firewall-service",
          state: "config_error",
          validation,
        };
      }
      const secretResolver = resolveSecretResolver(host);
      const openaiApiKey = await resolveOpenAiApiKey(config, secretResolver);
      runtimeReadiness = await validateRuntimeReadiness(config, secretResolver, openaiApiKey);
      const runtimeDeps = {
        stateStore,
        gmailClientFactory: async (source: GmailSourceConfig) => createGoogleapisGmailClient(source, await resolveGoogleAuthMaterial(source, secretResolver)),
        securityClassifier: openaiApiKey
          ? createOpenAiSecurityClassifier({ apiKey: openaiApiKey, model: config.openai_model })
          : createUnavailableSecurityClassifier(),
        routerClassifier: openaiApiKey
          ? createOpenAiRouterClassifier({ apiKey: openaiApiKey, model: config.openai_model })
          : createNoopRouterClassifier(),
        actionDeps: createHostActionDeps(host, logger),
      };
      runtime = new GmailIntakePollingRuntime(config, logger ? { ...runtimeDeps, logger } : runtimeDeps);
      runtime.start();
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        enabled: config.enabled,
        sources: config.sources.filter((source) => source.enabled).length,
        dryRun: config.dryRun,
        httpRoute: pubSubHttpRouteStatus(config),
        state: config.enabled ? "ready" : "disabled",
        validation,
        runtimeReadiness,
      };
    },
    async stop() {
      runtime?.stop();
      stateStore?.close();
      runtime = undefined;
      stateStore = undefined;
      runtimeReadiness = [];
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        state: "stopped",
      };
    },
    async probe() {
      const runtimeProbe = runtime?.probe() ?? {};
      const validation = validatePluginConfig(config);
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        enabled: config.enabled,
        configuredSources: config.sources.length,
        httpRoute: pubSubHttpRouteStatus(config),
        sqlitePath: config.sqlitePath,
        validation,
        ...runtimeProbe,
      };
    },
    async status() {
      if (!runtime) {
        return {
          ok: true,
          service: "gmail-intake-firewall-service",
          started: false,
          enabled: config.enabled,
          dryRun: config.dryRun,
          configuredSources: config.sources.length,
          httpRoute: pubSubHttpRouteStatus(config),
          validation: validatePluginConfig(config),
          runtimeReadiness,
        };
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        started: true,
        runtimeReadiness,
        httpRoute: pubSubHttpRouteStatus(config),
        ...runtime.status(),
      };
    },
    async validateConfig() {
      const validation = validatePluginConfig(config);
      return {
        ok: !validation.some((finding) => finding.severity === "error"),
        service: "gmail-intake-firewall-service",
        validation,
      };
    },
    async doctor() {
      const validation = validatePluginConfig(config);
      const status = await this.status();
      const auth = await this.checkSourceAuth({});
      const findings = buildDoctorFindings(config, validation, status, auth);
      return {
        ok: !findings.some((finding) => finding.severity === "error"),
        service: "gmail-intake-firewall-service",
        generatedAt: new Date().toISOString(),
        summary: {
          enabled: config.enabled,
          dryRun: config.dryRun,
          started: status.started === true,
          configuredSources: config.sources.length,
          errorCount: findings.filter((finding) => finding.severity === "error").length,
          warningCount: findings.filter((finding) => finding.severity === "warning").length,
        },
        findings,
        validation,
        auth: redactSupportStatus(auth),
      };
    },
    async supportBundle() {
      const validation = validatePluginConfig(config);
      const status = await this.status();
      const auth = await this.checkSourceAuth({});
      const review = runtime?.reviewSummary();
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        generatedAt: new Date().toISOString(),
        validation: redactSupportStatus(validation),
        runtimeReadiness: redactSupportStatus(runtimeReadiness),
        auth: redactSupportStatus(auth),
        status: redactSupportStatus(status),
        review: redactSupportStatus(review),
        notes: [
          "Support bundle is redacted and excludes raw email bodies, raw HTML, attachment contents, OAuth tokens, client secrets, and API keys.",
          "Share alongside gateway logs only after separately redacting deployment-specific secrets.",
        ],
      };
    },
    async backfill(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof options.sourceId === "string" ? options.sourceId : undefined;
      if (!sourceId) {
        throw new Error("backfill requires sourceId");
      }
      const allowUnbounded = options.allowUnbounded === true;
      if (!allowUnbounded && typeof options.query !== "string" && typeof options.maxResults !== "number") {
        throw new Error("backfill requires query or maxResults unless allowUnbounded is true");
      }
      return {
        ok: true,
        ...await runtime.runBackfill({
          sourceId,
          ...(typeof options.query === "string" ? { query: options.query } : {}),
          ...(typeof options.maxResults === "number" ? { maxResults: options.maxResults } : {}),
          ...(typeof options.force === "boolean" ? { force: options.force } : {}),
          ...(typeof options.dryRun === "boolean" ? { dryRun: options.dryRun } : {}),
        }),
      };
    },
    async inspectMessage(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof options.sourceId === "string" ? options.sourceId : undefined;
      const messageId = typeof options.messageId === "string" ? options.messageId : undefined;
      if (!sourceId || !messageId) {
        throw new Error("inspectMessage requires sourceId and messageId");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...runtime.inspectMessage(sourceId, messageId),
      };
    },
    async replayEvent(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof options.sourceId === "string" ? options.sourceId : undefined;
      const messageId = typeof options.messageId === "string" ? options.messageId : undefined;
      if (!sourceId || !messageId) {
        throw new Error("replayEvent requires sourceId and messageId");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.replayEvent({
          sourceId,
          messageId,
          ...(typeof options.force === "boolean" ? { force: options.force } : {}),
          ...(typeof options.dryRun === "boolean" ? { dryRun: options.dryRun } : {}),
        }),
      };
    },
    async drainAggregates() {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        ...await runtime.drainAggregates(),
      };
    },
    async handleGmailNotification(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const notification = parseGmailPushNotification(options);
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        notification,
        ...await runtime.handleGmailNotification({
          ...notification,
          ...(typeof options.force === "boolean" ? { force: options.force } : {}),
          ...(typeof options.dryRun === "boolean" ? { dryRun: options.dryRun } : {}),
        }),
      };
    },
    async setupWatch(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.setupWatch({
          ...(typeof options.sourceId === "string" ? { sourceId: options.sourceId } : {}),
          ...(typeof options.force === "boolean" ? { force: options.force } : {}),
        }),
      };
    },
    async renewWatch(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.renewWatch({
          ...(typeof options.sourceId === "string" ? { sourceId: options.sourceId } : {}),
          ...(typeof options.force === "boolean" ? { force: options.force } : {}),
        }),
      };
    },
    async repairWatch(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.repairWatch({
          ...(typeof options.sourceId === "string" ? { sourceId: options.sourceId } : {}),
          ...(typeof options.force === "boolean" ? { force: options.force } : {}),
        }),
      };
    },
    async checkSourceAuth(options) {
      const sourceId = typeof options.sourceId === "string" ? options.sourceId : undefined;
      const sources = sourceId
        ? config.sources.filter((source) => source.id === sourceId)
        : config.sources;
      if (sourceId && sources.length === 0) {
        return {
          ok: false,
          service: "gmail-intake-firewall-service",
          error: `Unknown source: ${sourceId}`,
        };
      }
      const secretResolver = resolveSecretResolver(host);
      const checks = [];
      for (const source of sources) {
        checks.push(await checkSourceAuthMaterial(source, secretResolver));
      }
      return {
        ok: checks.every((check) => check.ok),
        service: "gmail-intake-firewall-service",
        sources: checks,
      };
    },
    async recordFeedback(event) {
      if (!stateStore) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      stateStore.recordFeedback(event);
      return { ok: true };
    },
    async listQuarantine(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...runtime.listQuarantine(
          numberInput(options.limit, 25),
          typeof options.sourceId === "string" ? options.sourceId : undefined,
        ),
      };
    },
    async listPreferences(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...runtime.listPreferences(typeof options.sourceId === "string" ? options.sourceId : undefined),
      };
    },
    async reviewSummary(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        stats: runtime.reviewSummary(typeof options.sourceId === "string" ? options.sourceId : undefined),
      };
    },
    async getQuarantineItem(options) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof options.sourceId === "string" ? options.sourceId : undefined;
      const messageId = typeof options.messageId === "string" ? options.messageId : undefined;
      if (!sourceId || !messageId) {
        throw new Error("getQuarantineItem requires sourceId and messageId");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...runtime.getQuarantineItem(sourceId, messageId),
      };
    },
    async recordReviewFeedback(event) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof event.sourceId === "string" ? event.sourceId : undefined;
      const messageId = typeof event.messageId === "string" ? event.messageId : undefined;
      const feedbackType = typeof event.feedbackType === "string" ? event.feedbackType : undefined;
      if (!sourceId || !messageId || !feedbackType) {
        throw new Error("recordReviewFeedback requires sourceId, messageId, and feedbackType");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...runtime.recordReviewFeedback({
          sourceId,
          messageId,
          feedbackType,
          ...(typeof event.actor === "string" ? { actor: event.actor } : {}),
          ...(typeof event.reason === "string" ? { reason: event.reason } : {}),
          ...(typeof event.sender === "string" ? { sender: event.sender } : {}),
          ...(typeof event.domain === "string" ? { domain: event.domain } : {}),
        }),
      };
    },
    async wakeReviewedMessage(event) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof event.sourceId === "string" ? event.sourceId : undefined;
      const messageId = typeof event.messageId === "string" ? event.messageId : undefined;
      if (!sourceId || !messageId) {
        throw new Error("wakeReviewedMessage requires sourceId and messageId");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.wakeReviewedMessage({
          sourceId,
          messageId,
          ...(typeof event.actor === "string" ? { actor: event.actor } : {}),
          ...(typeof event.reason === "string" ? { reason: event.reason } : {}),
          ...(typeof event.wakeTarget === "string" ? { wakeTarget: event.wakeTarget } : {}),
          ...(typeof event.dryRun === "boolean" ? { dryRun: event.dryRun } : {}),
        }),
      };
    },
    async releaseFromQuarantine(event) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof event.sourceId === "string" ? event.sourceId : undefined;
      const messageId = typeof event.messageId === "string" ? event.messageId : undefined;
      if (!sourceId || !messageId) {
        throw new Error("releaseFromQuarantine requires sourceId and messageId");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.releaseFromQuarantine({
          sourceId,
          messageId,
          ...(typeof event.actor === "string" ? { actor: event.actor } : {}),
          ...(typeof event.reason === "string" ? { reason: event.reason } : {}),
          ...(typeof event.restoreInbox === "boolean" ? { restoreInbox: event.restoreInbox } : {}),
          ...(typeof event.dryRun === "boolean" ? { dryRun: event.dryRun } : {}),
        }),
      };
    },
    async replayWithFeedback(event) {
      if (!runtime) {
        throw new Error("gmail-intake-firewall service is not started");
      }
      const sourceId = typeof event.sourceId === "string" ? event.sourceId : undefined;
      const messageId = typeof event.messageId === "string" ? event.messageId : undefined;
      if (!sourceId || !messageId) {
        throw new Error("replayWithFeedback requires sourceId and messageId");
      }
      return {
        ok: true,
        service: "gmail-intake-firewall-service",
        ...await runtime.replayWithFeedback({
          sourceId,
          messageId,
          ...(typeof event.actor === "string" ? { actor: event.actor } : {}),
          ...(typeof event.reason === "string" ? { reason: event.reason } : {}),
          ...(typeof event.feedbackType === "string" ? { feedbackType: event.feedbackType } : {}),
          ...(typeof event.force === "boolean" ? { force: event.force } : {}),
          ...(typeof event.dryRun === "boolean" ? { dryRun: event.dryRun } : {}),
        }),
      };
    },
  };
}

async function checkSourceAuthMaterial(
  source: GmailSourceConfig,
  secretResolver: ReturnType<typeof resolveSecretResolver>,
): Promise<Record<string, unknown>> {
  try {
    const material = await resolveGoogleAuthMaterial(source, secretResolver);
    const hasAccessToken = Boolean(material.accessToken);
    const hasRefreshToken = Boolean(material.refreshToken);
    const hasClientId = Boolean(material.clientId);
    const hasClientSecret = Boolean(material.clientSecret);
    const credentialShapeOk = hasAccessToken || (hasRefreshToken && hasClientId && hasClientSecret);
    const configuredModifyScope = source.gmailActions.enabled && source.gmailActions.hasModifyScope;
    const credentialModifyScope = gmailScopesAllowModify(material.scopes);
    const canModifyGmail = configuredModifyScope && credentialModifyScope !== false;
    if (material.tokenType === "workspace_domain_wide_delegation") {
      return {
        ...safeSourceAuthStatus(source),
        ok: false,
        tokenType: material.tokenType,
        hasAccessToken,
        hasRefreshToken,
        hasClientId,
        hasClientSecret,
        scopes: material.scopes ?? [],
        configuredModifyScope,
        credentialModifyScope,
        canModifyGmail,
        error: "Workspace domain-wide delegation is not implemented in v1.",
      };
    }
    return {
      ...safeSourceAuthStatus(source),
      ok: credentialShapeOk,
      tokenType: material.tokenType,
      hasAccessToken,
      hasRefreshToken,
      hasClientId,
      hasClientSecret,
      scopes: material.scopes ?? [],
      configuredModifyScope,
      credentialModifyScope,
      canModifyGmail,
    };
  } catch (error) {
    return {
      ...safeSourceAuthStatus(source),
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function safeSourceAuthStatus(source: GmailSourceConfig, error?: string): Record<string, unknown> {
  return {
    sourceId: source.id,
    accountEmail: source.accountEmail,
    enabled: source.enabled,
    authRefConfigured: Boolean(source.authRef),
    credentialRefConfigured: Boolean(source.credentialRef),
    ok: false,
    ...(error ? { error } : {}),
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  res.statusCode = status;
  for (const [key, value] of Object.entries(headers ?? {})) {
    res.setHeader(key, value);
  }
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

async function readJsonRequestBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<{ ok: true; value: unknown } | { ok: false; status: number; error: string }> {
  let bytes = 0;
  const chunks: Buffer[] = [];
  try {
    for await (const chunk of req) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      bytes += buffer.length;
      if (bytes > maxBytes) {
        return { ok: false, status: 413, error: "payload_too_large" };
      }
      chunks.push(buffer);
    }
    const raw = Buffer.concat(chunks).toString("utf8").trim();
    if (!raw) {
      return { ok: true, value: {} };
    }
    return { ok: true, value: JSON.parse(raw) as unknown };
  } catch {
    return { ok: false, status: 400, error: "invalid_json" };
  }
}

function requestHasWebhookSecret(req: IncomingMessage, expected: string): boolean {
  const candidates = [
    bearerToken(req.headers.authorization),
    headerValue(req.headers["x-openclaw-token"]),
    queryToken(req.url),
  ].filter((candidate): candidate is string => Boolean(candidate));
  return candidates.some((candidate) => safeEqual(candidate, expected));
}

function bearerToken(value: unknown): string | undefined {
  const header = headerValue(value);
  if (!header || !header.toLowerCase().startsWith("bearer ")) {
    return undefined;
  }
  const token = header.slice(7).trim();
  return token || undefined;
}

function headerValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  if (Array.isArray(value)) {
    return headerValue(value[0]);
  }
  return undefined;
}

function queryToken(url: string | undefined): string | undefined {
  if (!url) {
    return undefined;
  }
  try {
    const parsed = new URL(url, "http://localhost");
    return parsed.searchParams.get("token")?.trim() || undefined;
  } catch {
    return undefined;
  }
}

function safeEqual(candidate: string, expected: string): boolean {
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function hasRegisterService(api: unknown): api is {
  registerService: (service: unknown) => unknown;
} {
  return Boolean(api && typeof api === "object" && typeof (api as { registerService?: unknown }).registerService === "function");
}

function hasRegisterTool(api: unknown): api is {
  registerTool: (tool: unknown, options?: Record<string, unknown>) => unknown;
} {
  return Boolean(api && typeof api === "object" && typeof (api as { registerTool?: unknown }).registerTool === "function");
}

function hasRegisterHttpRoute(api: unknown): api is {
  registerHttpRoute: (route: unknown) => unknown;
} {
  return Boolean(api && typeof api === "object" && typeof (api as { registerHttpRoute?: unknown }).registerHttpRoute === "function");
}

async function validateRuntimeReadiness(
  config: ReturnType<typeof resolvePluginConfig>,
  secretResolver: ReturnType<typeof resolveSecretResolver>,
  openaiApiKey: string | undefined,
): Promise<RuntimeReadinessFinding[]> {
  const findings: RuntimeReadinessFinding[] = [];
  if (!openaiApiKey) {
    findings.push({
      severity: "error",
      path: "openaiApiKeyRef",
      message: "OpenAI API key did not resolve; security classifier will fail closed.",
    });
  }
  if (!secretResolver) {
    const hasOnlyHostRefs = config.sources.some((source) => source.enabled && sourceHasHostOnlyAuthRef(source));
    if (hasOnlyHostRefs) {
      findings.push({
        severity: "error",
        path: "secrets",
        message: "Host secret resolver is unavailable; Gmail source credentials must use inline, env, or file auth references in this runtime.",
      });
    }
  }
  for (const source of config.sources.filter((candidate) => candidate.enabled)) {
    try {
      const material = await resolveGoogleAuthMaterial(source, secretResolver);
      if (!material.refreshToken && !material.accessToken) {
        findings.push({
          severity: "error",
          path: `sources.${source.id}.authRef`,
          message: "Gmail credentials resolved without accessToken or refreshToken.",
        });
      }
      if (material.refreshToken && (!material.clientId || !material.clientSecret)) {
        findings.push({
          severity: "error",
          path: `sources.${source.id}.authRef`,
          message: "Gmail refresh-token auth requires clientId and clientSecret.",
        });
      }
    } catch (error) {
      findings.push({
        severity: "error",
        path: `sources.${source.id}.authRef`,
        message: `Gmail credentials could not be resolved: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  return findings;
}

function sourceHasHostOnlyAuthRef(source: GmailSourceConfig): boolean {
  const ref = source.authRef ?? source.credentialRef;
  if (!ref || typeof ref !== "object") {
    return false;
  }
  const raw = ref as Record<string, unknown>;
  if (typeof raw.accessToken === "string" || typeof raw.refreshToken === "string") {
    return false;
  }
  const sourceKind = typeof raw.source === "string" ? raw.source : undefined;
  const provider = typeof raw.provider === "string" ? raw.provider : undefined;
  return sourceKind !== "env" && sourceKind !== "file" && provider !== "env" && provider !== "file" && !raw.path;
}

function buildDoctorFindings(
  config: ReturnType<typeof resolvePluginConfig>,
  validation: RuntimeReadinessFinding[],
  status: Record<string, unknown>,
  auth: Record<string, unknown>,
): RuntimeReadinessFinding[] {
  const findings: RuntimeReadinessFinding[] = [...validation];
  if (config.dryRun) {
    findings.push({
      severity: "warning",
      path: "dryRun",
      message: "dryRun is enabled; Gmail, Slack, local log, and agent wake mutations are intentionally skipped.",
    });
  }
  const authSources = Array.isArray(auth.sources) ? auth.sources as Array<Record<string, unknown>> : [];
  for (const sourceAuth of authSources) {
    const sourceId = String(sourceAuth.sourceId ?? sourceAuth.id ?? "unknown");
    if (sourceAuth.ok !== true) {
      findings.push({
        severity: "error",
        path: `sources.${sourceId}.authRef`,
        message: typeof sourceAuth.error === "string" ? redactSecretString(sourceAuth.error) : "Gmail source credentials are not ready.",
      });
    }
    if (sourceAuth.configuredModifyScope === true && sourceAuth.credentialModifyScope === false) {
      findings.push({
        severity: "warning",
        path: `sources.${sourceId}.gmailActions.hasModifyScope`,
        message: "Gmail write actions are configured, but resolved OAuth scopes do not allow Gmail modify.",
      });
    }
  }
  const statusSources = Array.isArray(status.sources) ? status.sources as Array<Record<string, unknown>> : [];
  for (const sourceStatus of statusSources) {
    const sourceId = String(sourceStatus.id ?? "unknown");
    const readiness = objectValue(sourceStatus.readiness);
    if (readiness?.mode === "watch" && readiness.watchTopicConfigured !== true) {
      findings.push({
        severity: "error",
        path: `sources.${sourceId}.watchTopicName`,
        message: "Watch source has no Pub/Sub topic configured.",
      });
    }
    if (readiness?.mode === "watch" && readiness.historyCursorPresent !== true) {
      findings.push({
        severity: "warning",
        path: `sources.${sourceId}.watch`,
        message: "Watch source has no stored Gmail history cursor yet; run setupWatch or let the first notification establish the cursor.",
      });
    }
    if (readiness?.watchNeedsRenewal === true) {
      findings.push({
        severity: "warning",
        path: `sources.${sourceId}.watch`,
        message: "Gmail watch is expired or inside the renewal window; run renewWatch.",
      });
    }
    if (readiness?.missedNotificationRepairDue === true) {
      findings.push({
        severity: "warning",
        path: `sources.${sourceId}.watch`,
        message: "No recent Gmail notification/history activity; run repairWatch to drain history and refresh diagnostics.",
      });
    }
    const lastPoll = objectValue(sourceStatus.lastPoll);
    if (lastPoll?.status === "failed" || lastPoll?.status === "completed_with_errors") {
      const error = objectValue(lastPoll.error);
      findings.push({
        severity: lastPoll.status === "failed" ? "error" : "warning",
        path: `sources.${sourceId}.lastPoll`,
        message: `Last poll ${String(lastPoll.status)} at stage ${String(lastPoll.stage ?? "unknown")}${typeof error?.message === "string" ? `: ${redactSecretString(error.message)}` : ""}`,
      });
    }
  }
  return dedupeFindings(findings);
}

function redactSupportStatus(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => redactSupportStatus(entry));
  }
  const raw = objectValue(value);
  if (!raw) {
    return typeof value === "string" ? redactSecretString(value) : value;
  }
  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(raw)) {
    if (/token|secret|api[_-]?key|authorization/i.test(key)) {
      result[key] = "[redacted]";
    } else {
      result[key] = redactSupportStatus(entry);
    }
  }
  return result;
}

function redactSecretString(value: string): string {
  return value
    .replace(/(["'])(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|authorization)\1\s*:\s*(["'])[^"']*\3/gi, "$1$2$1: $3[redacted]$3")
    .replace(/(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|authorization)\s*(=|:)\s*[^,\s)}]+/gi, "$1$2 [redacted]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]");
}

function dedupeFindings(findings: RuntimeReadinessFinding[]): RuntimeReadinessFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.severity}:${finding.path}:${finding.message}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
