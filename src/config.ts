import type {
  AlertSinkConfig,
  GmailSourceConfig,
  PluginConfig,
  SecurityConfig,
  TagConfig,
  WakeMode,
  WakeTargetConfig,
} from "./types.js";

const DEFAULT_SECURITY: SecurityConfig = {
  quarantineLabel: "OpenClaw/Quarantine",
  maxBodyChars: 24000,
  maliciousThreshold: 0.65,
  uncertainThreshold: 0.35,
  failClosedOnUncertain: true,
  archiveOnQuarantine: false,
};

const DEFAULT_CONFIG: PluginConfig = {
  enabled: true,
  dryRun: true,
  openai_model: "gpt-5.5",
  statePath: "~/.openclaw/gmail-intake-firewall/state.json",
  sqlitePath: "~/.openclaw/gmail-intake-firewall/state.sqlite",
  sources: [],
  security: DEFAULT_SECURITY,
  tags: [],
  wakeTargets: [],
  alertSinks: [
    {
      id: "local",
      kind: "local_log",
      enabled: true,
    },
  ],
  aggregate: {
    maxDigestItems: 50,
    timezone: "UTC",
  },
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function numberInRange(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(1, Math.max(0, value));
}

function positiveInteger(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.max(1, Math.floor(value));
}

function wakeModeValue(value: unknown): WakeMode | undefined {
  return value === "none" || value === "wake_now" || value === "aggregate" ? value : undefined;
}

function intakeModeValue(value: unknown): "watch" | "history" | "poll" {
  return value === "watch" || value === "history" || value === "poll" ? value : "poll";
}

function assignOptional<T extends Record<string, unknown>>(
  target: T,
  key: string,
  value: unknown,
): void {
  if (value !== undefined) {
    (target as Record<string, unknown>)[key] = value;
  }
}

function normalizeSources(value: unknown): GmailSourceConfig[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((entry) => {
    const raw = asRecord(entry);
    const id = stringValue(raw.id);
    const accountEmail = stringValue(raw.accountEmail);
    if (!id || !accountEmail) {
      return [];
    }
    const source: GmailSourceConfig = {
      id,
      accountEmail,
      enabled: booleanValue(raw.enabled, true),
      intakeMode: intakeModeValue(raw.intakeMode),
      polling: {
        intervalMs: positiveInteger(asRecord(raw.polling).intervalMs, 60000),
        maxResults: positiveInteger(asRecord(raw.polling).maxResults, 25),
      },
      gmailActions: {
        enabled: booleanValue(asRecord(raw.gmailActions).enabled, true),
        applyLabels: booleanValue(asRecord(raw.gmailActions).applyLabels, true),
        archive: booleanValue(asRecord(raw.gmailActions).archive, true),
        hasModifyScope: booleanValue(asRecord(raw.gmailActions).hasModifyScope, true),
      },
    };
    assignOptional(source, "authRef", Object.keys(asRecord(raw.authRef)).length ? asRecord(raw.authRef) : undefined);
    assignOptional(source, "credentialRef", Object.keys(asRecord(raw.credentialRef)).length ? asRecord(raw.credentialRef) : undefined);
    assignOptional(source, "candidateQuery", stringValue(raw.candidateQuery));
    assignOptional(source, "include", stringValue(raw.include));
    assignOptional(source, "exclude", stringValue(raw.exclude));
    assignOptional(source, "defaultRoutingPolicy", stringValue(raw.defaultRoutingPolicy));
    assignOptional(source, "watchTopicName", stringValue(raw.watchTopicName));
    assignOptional(source, "historyLookback", stringValue(raw.historyLookback));
    return [source];
  });
}

function normalizeWakeTargets(value: unknown): WakeTargetConfig[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((entry) => {
    const raw = asRecord(entry);
    const id = stringValue(raw.id);
    const agentId = stringValue(raw.agentId);
    if (!id || !agentId) {
      return [];
    }
    const target: WakeTargetConfig = { id, agentId };
    assignOptional(target, "workspaceDir", stringValue(raw.workspaceDir));
    assignOptional(target, "sessionId", stringValue(raw.sessionId));
    const deliveryContext = asRecord(raw.deliveryContext);
    if (Object.keys(deliveryContext).length > 0) {
      target.deliveryContext = deliveryContext;
    }
    return [target];
  });
}

function normalizeAlertSinks(value: unknown): AlertSinkConfig[] {
  if (!Array.isArray(value)) {
    return DEFAULT_CONFIG.alertSinks;
  }
  const sinks = value.flatMap((entry) => {
    const raw = asRecord(entry);
    const id = stringValue(raw.id);
    const kind = raw.kind === "slack" || raw.kind === "local_log"
      ? raw.kind
      : undefined;
    if (!id || !kind) {
      return [];
    }
    const sink: AlertSinkConfig = {
      id,
      kind,
      enabled: booleanValue(raw.enabled, true),
    };
    assignOptional(sink, "target", stringValue(raw.target));
    return [sink];
  });
  return sinks.length > 0 ? sinks : DEFAULT_CONFIG.alertSinks;
}

function normalizeTags(value: unknown): TagConfig[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((entry) => {
    const raw = asRecord(entry);
    const id = stringValue(raw.id);
    const description = stringValue(raw.description);
    const wakeMode = wakeModeValue(raw.wakeMode);
    if (!id || !description || !wakeMode) {
      return [];
    }
    const tag: TagConfig = {
      id,
      description,
      wakeMode,
    };
    assignOptional(tag, "gmailLabel", stringValue(raw.gmailLabel));
    assignOptional(tag, "aggregateCadence", stringValue(raw.aggregateCadence));
    assignOptional(tag, "wakeTarget", stringValue(raw.wakeTarget));
    return [tag];
  });
}

export function resolvePluginConfig(rawConfig: unknown): PluginConfig {
  const raw = asRecord(rawConfig);
  const securityRaw = asRecord(raw.security);
  const alertTarget = stringValue(securityRaw.alertTarget);
  const provider = stringValue(securityRaw.provider);
  const model = stringValue(securityRaw.model);
  const openaiApiKey = stringValue(raw.OPENAI_API_KEY);
  const aggregateRaw = asRecord(raw.aggregate);
  const security: SecurityConfig = {
    quarantineLabel: stringValue(securityRaw.quarantineLabel) ?? DEFAULT_SECURITY.quarantineLabel,
    maxBodyChars: positiveInteger(securityRaw.maxBodyChars, DEFAULT_SECURITY.maxBodyChars),
    maliciousThreshold: numberInRange(securityRaw.maliciousThreshold, DEFAULT_SECURITY.maliciousThreshold),
    uncertainThreshold: numberInRange(securityRaw.uncertainThreshold, DEFAULT_SECURITY.uncertainThreshold),
    failClosedOnUncertain: booleanValue(securityRaw.failClosedOnUncertain, DEFAULT_SECURITY.failClosedOnUncertain),
    ...(alertTarget ? { alertTarget } : {}),
    archiveOnQuarantine: booleanValue(securityRaw.archiveOnQuarantine, DEFAULT_SECURITY.archiveOnQuarantine),
  };
  if (provider) {
    security.provider = provider;
  }
  if (model) {
    security.model = model;
  }
  return {
    enabled: booleanValue(raw.enabled, DEFAULT_CONFIG.enabled),
    dryRun: booleanValue(raw.dryRun, DEFAULT_CONFIG.dryRun),
    ...(Object.keys(asRecord(raw.openaiApiKeyRef)).length ? { openaiApiKeyRef: asRecord(raw.openaiApiKeyRef) } : {}),
    ...(openaiApiKey ? { OPENAI_API_KEY: openaiApiKey } : {}),
    openai_model: stringValue(raw.openai_model) ?? model ?? DEFAULT_CONFIG.openai_model,
    statePath: stringValue(raw.statePath) ?? DEFAULT_CONFIG.statePath,
    sqlitePath: stringValue(raw.sqlitePath) ?? stringValue(raw.statePath) ?? DEFAULT_CONFIG.sqlitePath,
    sources: normalizeSources(raw.sources),
    security,
    tags: normalizeTags(raw.tags),
    wakeTargets: normalizeWakeTargets(raw.wakeTargets),
    alertSinks: normalizeAlertSinks(raw.alertSinks),
    aggregate: {
      maxDigestItems: positiveInteger(aggregateRaw.maxDigestItems, DEFAULT_CONFIG.aggregate.maxDigestItems),
      timezone: stringValue(aggregateRaw.timezone) ?? DEFAULT_CONFIG.aggregate.timezone,
    },
  };
}
