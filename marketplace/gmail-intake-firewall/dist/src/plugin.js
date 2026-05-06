import { resolvePluginConfig, validatePluginConfig } from "./config.js";
import { createGoogleapisGmailClient } from "./gmailClient.js";
import { resolveGoogleAuthMaterial, resolveSecretResolver } from "./googleAuth.js";
import { createHostActionDeps } from "./hostActions.js";
import { createOpenAiRouterClassifier } from "./openaiRouterClassifier.js";
import { createOpenAiSecurityClassifier, resolveOpenAiApiKey } from "./openaiSecurityClassifier.js";
import { createNoopRouterClassifier } from "./routerClassifier.js";
import { createUnavailableGmailClientFactory, GmailIntakePollingRuntime } from "./runtime.js";
import { createUnavailableSecurityClassifier } from "./securityClassifier.js";
import { openSqliteStateStore } from "./state.js";
export function registerGmailIntakeFirewallPlugin(api) {
    const host = api && typeof api === "object" ? api : {};
    const rawConfig = "config" in host ? host.config : undefined;
    const config = resolvePluginConfig(rawConfig);
    const logger = host.logger && typeof host.logger === "object"
        ? host.logger
        : undefined;
    logger?.info?.("gmail-intake-firewall registered", {
        enabled: config.enabled,
        dryRun: config.dryRun,
        sources: config.sources.length,
    });
    if (hasRegisterService(api)) {
        api.registerService(buildGmailIntakeFirewallService(config, api, logger));
    }
    void createUnavailableSecurityClassifier();
    void createNoopRouterClassifier();
}
function buildGmailIntakeFirewallService(config, host, logger) {
    let runtime;
    let stateStore;
    let runtimeReadiness = [];
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
                gmailClientFactory: secretResolver
                    ? async (source) => createGoogleapisGmailClient(source, await resolveGoogleAuthMaterial(source, secretResolver))
                    : createUnavailableGmailClientFactory(),
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
                    validation: validatePluginConfig(config),
                    runtimeReadiness,
                };
            }
            return {
                ok: true,
                service: "gmail-intake-firewall-service",
                started: true,
                runtimeReadiness,
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
        async recordFeedback(event) {
            if (!stateStore) {
                throw new Error("gmail-intake-firewall service is not started");
            }
            stateStore.recordFeedback(event);
            return { ok: true };
        },
    };
}
function hasRegisterService(api) {
    return Boolean(api && typeof api === "object" && typeof api.registerService === "function");
}
async function validateRuntimeReadiness(config, secretResolver, openaiApiKey) {
    const findings = [];
    if (!openaiApiKey) {
        findings.push({
            severity: "error",
            path: "openaiApiKeyRef",
            message: "OpenAI API key did not resolve; security classifier will fail closed.",
        });
    }
    if (!secretResolver) {
        findings.push({
            severity: "error",
            path: "secrets",
            message: "Host secret resolver is unavailable; Gmail source credentials cannot be resolved.",
        });
        return findings;
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
        }
        catch (error) {
            findings.push({
                severity: "error",
                path: `sources.${source.id}.authRef`,
                message: `Gmail credentials could not be resolved: ${error instanceof Error ? error.message : String(error)}`,
            });
        }
    }
    return findings;
}
