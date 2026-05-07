const DEFAULT_SECURITY = {
    quarantineLabel: "OpenClaw/Quarantine",
    maxBodyChars: 24000,
    maliciousThreshold: 0.65,
    uncertainThreshold: 0.35,
    failClosedOnUncertain: true,
    includeSnippetInAlerts: false,
    archiveOnQuarantine: false,
};
const DEFAULT_CONFIG = {
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
    artifacts: {
        analyzeLinks: true,
        analyzeAttachments: true,
        fetchLinks: false,
        downloadAttachments: false,
        maxDisplayedUrlChars: 160,
    },
    watch: {
        autoSetup: true,
        renewBeforeMs: 24 * 60 * 60 * 1000,
        repairOnNoNotificationMs: 6 * 60 * 60 * 1000,
        labelIds: ["INBOX"],
        labelFilterBehavior: "INCLUDE",
    },
};
function asRecord(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function stringValue(value) {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
function booleanValue(value, fallback) {
    return typeof value === "boolean" ? value : fallback;
}
function numberInRange(value, fallback) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        return fallback;
    }
    return Math.min(1, Math.max(0, value));
}
function positiveInteger(value, fallback) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        return fallback;
    }
    return Math.max(1, Math.floor(value));
}
function wakeModeValue(value) {
    return value === "none" || value === "wake_now" || value === "aggregate" ? value : undefined;
}
function intakeModeValue(value) {
    return value === "watch" || value === "history" || value === "poll" ? value : "poll";
}
function assignOptional(target, key, value) {
    if (value !== undefined) {
        target[key] = value;
    }
}
function normalizeSources(value) {
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
        const source = {
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
function normalizeWakeTargets(value) {
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
        const target = { id, agentId };
        assignOptional(target, "workspaceDir", stringValue(raw.workspaceDir));
        assignOptional(target, "sessionId", stringValue(raw.sessionId));
        const deliveryContext = asRecord(raw.deliveryContext);
        if (Object.keys(deliveryContext).length > 0) {
            target.deliveryContext = deliveryContext;
        }
        return [target];
    });
}
function normalizeAlertSinks(value) {
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
        const sink = {
            id,
            kind,
            enabled: booleanValue(raw.enabled, true),
        };
        assignOptional(sink, "target", stringValue(raw.target));
        return [sink];
    });
    return sinks.length > 0 ? sinks : DEFAULT_CONFIG.alertSinks;
}
function normalizeStringArray(value, fallback) {
    if (!Array.isArray(value)) {
        return fallback;
    }
    const normalized = value.flatMap((entry) => {
        const text = stringValue(entry);
        return text ? [text] : [];
    });
    return normalized.length > 0 ? normalized : fallback;
}
function normalizeTags(value) {
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
        const tag = {
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
export function resolvePluginConfig(rawConfig) {
    const raw = asRecord(rawConfig);
    const securityRaw = asRecord(raw.security);
    const alertTarget = stringValue(securityRaw.alertTarget);
    const provider = stringValue(securityRaw.provider);
    const model = stringValue(securityRaw.model);
    const openaiApiKey = stringValue(raw.OPENAI_API_KEY);
    const webhookSecret = stringValue(raw.webhookSecret);
    const aggregateRaw = asRecord(raw.aggregate);
    const artifactsRaw = asRecord(raw.artifacts);
    const watchRaw = asRecord(raw.watch);
    const security = {
        quarantineLabel: stringValue(securityRaw.quarantineLabel) ?? DEFAULT_SECURITY.quarantineLabel,
        maxBodyChars: positiveInteger(securityRaw.maxBodyChars, DEFAULT_SECURITY.maxBodyChars),
        maliciousThreshold: numberInRange(securityRaw.maliciousThreshold, DEFAULT_SECURITY.maliciousThreshold),
        uncertainThreshold: numberInRange(securityRaw.uncertainThreshold, DEFAULT_SECURITY.uncertainThreshold),
        failClosedOnUncertain: booleanValue(securityRaw.failClosedOnUncertain, DEFAULT_SECURITY.failClosedOnUncertain),
        includeSnippetInAlerts: booleanValue(securityRaw.includeSnippetInAlerts, DEFAULT_SECURITY.includeSnippetInAlerts),
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
        ...(webhookSecret ? { webhookSecret } : {}),
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
        artifacts: normalizeArtifacts(artifactsRaw),
        watch: normalizeWatch(watchRaw),
    };
}
function normalizeArtifacts(raw) {
    return {
        analyzeLinks: booleanValue(raw.analyzeLinks, DEFAULT_CONFIG.artifacts.analyzeLinks),
        analyzeAttachments: booleanValue(raw.analyzeAttachments, DEFAULT_CONFIG.artifacts.analyzeAttachments),
        fetchLinks: booleanValue(raw.fetchLinks, DEFAULT_CONFIG.artifacts.fetchLinks),
        downloadAttachments: booleanValue(raw.downloadAttachments, DEFAULT_CONFIG.artifacts.downloadAttachments),
        maxDisplayedUrlChars: positiveInteger(raw.maxDisplayedUrlChars, DEFAULT_CONFIG.artifacts.maxDisplayedUrlChars),
    };
}
function normalizeWatch(raw) {
    const labelFilterBehavior = raw.labelFilterBehavior === "EXCLUDE" ? "EXCLUDE" : "INCLUDE";
    return {
        autoSetup: booleanValue(raw.autoSetup, DEFAULT_CONFIG.watch.autoSetup),
        renewBeforeMs: positiveInteger(raw.renewBeforeMs, DEFAULT_CONFIG.watch.renewBeforeMs),
        repairOnNoNotificationMs: positiveInteger(raw.repairOnNoNotificationMs, DEFAULT_CONFIG.watch.repairOnNoNotificationMs),
        labelIds: normalizeStringArray(raw.labelIds, DEFAULT_CONFIG.watch.labelIds),
        labelFilterBehavior,
    };
}
export function validatePluginConfig(config) {
    const findings = [];
    addDuplicateFindings(findings, "sources", config.sources.map((source) => source.id));
    addDuplicateFindings(findings, "tags", config.tags.map((tag) => tag.id));
    addDuplicateFindings(findings, "wakeTargets", config.wakeTargets.map((target) => target.id));
    addDuplicateFindings(findings, "alertSinks", config.alertSinks.map((sink) => sink.id));
    const wakeTargetIds = new Set(config.wakeTargets.map((target) => target.id));
    const alertSinkIds = new Set(config.alertSinks.map((sink) => sink.id));
    for (const source of config.sources) {
        if (!source.authRef && !source.credentialRef) {
            findings.push({
                severity: "warning",
                path: `sources.${source.id}.authRef`,
                message: "Source has no authRef/credentialRef; Gmail access will be unavailable unless the host injects a Gmail client.",
            });
        }
        if (source.intakeMode === "watch" && !source.watchTopicName) {
            findings.push({
                severity: "error",
                path: `sources.${source.id}.watchTopicName`,
                message: "watch intakeMode requires watchTopicName.",
            });
        }
        if (source.intakeMode === "watch" && !source.historyLookback) {
            findings.push({
                severity: "warning",
                path: `sources.${source.id}.historyLookback`,
                message: "watch intakeMode should configure historyLookback so stale history cursors can repair with a bounded poll.",
            });
        }
        if (source.intakeMode === "watch" && !/^projects\/[^/]+\/topics\/[^/]+$/.test(source.watchTopicName ?? "")) {
            findings.push({
                severity: "warning",
                path: `sources.${source.id}.watchTopicName`,
                message: "watchTopicName should use the fully-qualified Pub/Sub topic format projects/{project}/topics/{topic}.",
            });
        }
        if (source.intakeMode === "watch" && !config.webhookSecret) {
            findings.push({
                severity: "warning",
                path: "webhookSecret",
                message: "watch intakeMode should configure webhookSecret before exposing the Pub/Sub HTTP route.",
            });
        }
        if (source.gmailActions.enabled && (source.gmailActions.applyLabels || source.gmailActions.archive) && !source.gmailActions.hasModifyScope) {
            findings.push({
                severity: "warning",
                path: `sources.${source.id}.gmailActions.hasModifyScope`,
                message: "Gmail write actions are configured but hasModifyScope is false; label/archive actions will degrade to log/alert only.",
            });
        }
    }
    if (config.watch.renewBeforeMs < 60 * 60 * 1000) {
        findings.push({
            severity: "warning",
            path: "watch.renewBeforeMs",
            message: "renewBeforeMs is less than one hour; production Gmail watches should renew with a larger buffer.",
        });
    }
    for (const tag of config.tags) {
        if (tag.wakeTarget && !wakeTargetIds.has(tag.wakeTarget)) {
            findings.push({
                severity: "error",
                path: `tags.${tag.id}.wakeTarget`,
                message: `Tag references unknown wakeTarget "${tag.wakeTarget}".`,
            });
        }
        if (tag.wakeMode === "wake_now" && !tag.wakeTarget) {
            findings.push({
                severity: "error",
                path: `tags.${tag.id}.wakeTarget`,
                message: "wake_now tags require wakeTarget.",
            });
        }
        if (tag.wakeMode === "aggregate" && tag.aggregateCadence && !["hourly", "daily", "weekly"].includes(tag.aggregateCadence)) {
            findings.push({
                severity: "error",
                path: `tags.${tag.id}.aggregateCadence`,
                message: "aggregateCadence must be hourly, daily, or weekly.",
            });
        }
    }
    if (config.security.alertTarget && !alertSinkIds.has(config.security.alertTarget) && !config.alertSinks.some((sink) => sink.target === config.security.alertTarget)) {
        findings.push({
            severity: "warning",
            path: "security.alertTarget",
            message: "alertTarget does not match an alert sink id or target; Slack alerts may have no explicit destination.",
        });
    }
    if (!isValidTimezone(config.aggregate.timezone)) {
        findings.push({
            severity: "error",
            path: "aggregate.timezone",
            message: `Invalid IANA timezone "${config.aggregate.timezone}".`,
        });
    }
    if (config.artifacts.fetchLinks) {
        findings.push({
            severity: "error",
            path: "artifacts.fetchLinks",
            message: "Link fetching is not supported in this version; keep fetchLinks false.",
        });
    }
    if (config.artifacts.downloadAttachments) {
        findings.push({
            severity: "error",
            path: "artifacts.downloadAttachments",
            message: "Attachment downloading is not supported in this version; keep downloadAttachments false.",
        });
    }
    return findings;
}
function addDuplicateFindings(findings, path, values) {
    const seen = new Set();
    for (const value of values) {
        if (seen.has(value)) {
            findings.push({
                severity: "error",
                path,
                message: `Duplicate id "${value}".`,
            });
        }
        seen.add(value);
    }
}
function isValidTimezone(timezone) {
    try {
        new Intl.DateTimeFormat("en-US", { timeZone: timezone });
        return true;
    }
    catch {
        return false;
    }
}
