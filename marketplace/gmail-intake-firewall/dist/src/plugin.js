import { resolvePluginConfig, validatePluginConfig } from "./config.js";
import { createGoogleapisGmailClient } from "./gmailClient.js";
import { gmailScopesAllowModify, resolveGoogleAuthMaterial, resolveSecretResolver } from "./googleAuth.js";
import { createHostActionDeps } from "./hostActions.js";
import { createOpenAiRouterClassifier } from "./openaiRouterClassifier.js";
import { createOpenAiSecurityClassifier, resolveOpenAiApiKey } from "./openaiSecurityClassifier.js";
import { createNoopRouterClassifier } from "./routerClassifier.js";
import { createUnavailableGmailClientFactory, GmailIntakePollingRuntime } from "./runtime.js";
import { createUnavailableSecurityClassifier } from "./securityClassifier.js";
import { openSqliteStateStore } from "./state.js";
export function registerGmailIntakeFirewallPlugin(api) {
    const host = api && typeof api === "object" ? api : {};
    const rawConfig = "pluginConfig" in host ? host.pluginConfig : "config" in host ? host.config : undefined;
    const config = resolvePluginConfig(rawConfig);
    const logger = host.logger && typeof host.logger === "object"
        ? host.logger
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
        api.registerTool(buildOperatorStatusTool(service));
    }
    void createUnavailableSecurityClassifier();
    void createNoopRouterClassifier();
}
function buildOperatorStatusTool(service) {
    const schema = {
        type: "object",
        additionalProperties: false,
        properties: {
            operation: {
                type: "string",
                enum: ["status", "probe", "validateConfig", "checkSourceAuth"],
                default: "status",
            },
            sourceId: {
                type: "string",
            },
        },
    };
    const run = async (input) => {
        const operation = input && typeof input === "object" && "operation" in input
            ? input.operation
            : "status";
        if (operation === "probe") {
            return service.probe();
        }
        if (operation === "validateConfig") {
            return service.validateConfig();
        }
        if (operation === "checkSourceAuth") {
            const sourceId = typeof input.sourceId === "string"
                ? input.sourceId
                : undefined;
            return service.checkSourceAuth(sourceId ? { sourceId } : {});
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
            if (!secretResolver) {
                return {
                    ok: false,
                    service: "gmail-intake-firewall-service",
                    error: "Host secret resolver is unavailable.",
                    sources: sources.map((source) => safeSourceAuthStatus(source)),
                };
            }
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
    };
}
async function checkSourceAuthMaterial(source, secretResolver) {
    if (!secretResolver) {
        return safeSourceAuthStatus(source, "secret_resolver_unavailable");
    }
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
    }
    catch (error) {
        return {
            ...safeSourceAuthStatus(source),
            ok: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
function safeSourceAuthStatus(source, error) {
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
function hasRegisterService(api) {
    return Boolean(api && typeof api === "object" && typeof api.registerService === "function");
}
function hasRegisterTool(api) {
    return Boolean(api && typeof api === "object" && typeof api.registerTool === "function");
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
