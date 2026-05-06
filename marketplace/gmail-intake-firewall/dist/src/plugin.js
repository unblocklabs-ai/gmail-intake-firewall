import { resolvePluginConfig } from "./config.js";
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
            const secretResolver = resolveSecretResolver(host);
            const openaiApiKey = await resolveOpenAiApiKey(config, secretResolver);
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
            };
        },
        async stop() {
            runtime?.stop();
            stateStore?.close();
            runtime = undefined;
            stateStore = undefined;
            return {
                ok: true,
                service: "gmail-intake-firewall-service",
                state: "stopped",
            };
        },
        async probe() {
            const runtimeProbe = runtime?.probe() ?? {};
            return {
                ok: true,
                service: "gmail-intake-firewall-service",
                enabled: config.enabled,
                configuredSources: config.sources.length,
                sqlitePath: config.sqlitePath,
                ...runtimeProbe,
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
