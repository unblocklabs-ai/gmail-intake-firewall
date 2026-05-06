import { timingSafeEqual } from "node:crypto";
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
import { openSqliteStateStore } from "./state.js";
const PUBSUB_ROUTE_ID = "gmail-intake-firewall-pubsub";
const PUBSUB_ROUTE_PATH = "/gmail-intake-firewall/pubsub";
const PUBSUB_ROUTE_AUTH = "plugin";
const PUBSUB_ROUTE_MATCH = "exact";
const PUBSUB_ROUTE_ACTIVATION_HINT = "gateway-webhook";
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
        api.registerTool(buildOperatorStatusTool(service), { name: "gmail_intake_firewall_status" });
    }
    if (hasRegisterHttpRoute(api)) {
        api.registerHttpRoute(buildPubSubHttpRoute(service, config));
    }
    void createUnavailableSecurityClassifier();
    void createNoopRouterClassifier();
}
function buildPubSubHttpRoute(service, config) {
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
                const result = await service.handleGmailNotification(body.value);
                sendJson(res, 200, result);
            }
            catch (error) {
                sendJson(res, 400, {
                    ok: false,
                    error: error instanceof Error ? error.message : String(error),
                });
            }
            return true;
        },
    };
}
async function ensureHttpServiceStarted(service) {
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
function pubSubHttpRouteStatus(config) {
    return {
        id: PUBSUB_ROUTE_ID,
        path: PUBSUB_ROUTE_PATH,
        auth: PUBSUB_ROUTE_AUTH,
        match: PUBSUB_ROUTE_MATCH,
        webhookSecretConfigured: Boolean(config.webhookSecret),
        routeActivationHint: PUBSUB_ROUTE_ACTIVATION_HINT,
    };
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
function normalizeToolInput(input) {
    if (!input || typeof input !== "object") {
        return undefined;
    }
    const raw = input;
    if (typeof raw.operation === "string") {
        return raw;
    }
    for (const key of ["input", "arguments", "args", "params"]) {
        const nested = raw[key];
        if (nested && typeof nested === "object" && typeof nested.operation === "string") {
            return nested;
        }
    }
    return raw;
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
function sendJson(res, status, body, headers) {
    res.statusCode = status;
    for (const [key, value] of Object.entries(headers ?? {})) {
        res.setHeader(key, value);
    }
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(body));
}
async function readJsonRequestBody(req, maxBytes) {
    let bytes = 0;
    const chunks = [];
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
        return { ok: true, value: JSON.parse(raw) };
    }
    catch {
        return { ok: false, status: 400, error: "invalid_json" };
    }
}
function requestHasWebhookSecret(req, expected) {
    const candidates = [
        bearerToken(req.headers.authorization),
        headerValue(req.headers["x-openclaw-token"]),
        queryToken(req.url),
    ].filter((candidate) => Boolean(candidate));
    return candidates.some((candidate) => safeEqual(candidate, expected));
}
function bearerToken(value) {
    const header = headerValue(value);
    if (!header || !header.toLowerCase().startsWith("bearer ")) {
        return undefined;
    }
    const token = header.slice(7).trim();
    return token || undefined;
}
function headerValue(value) {
    if (typeof value === "string" && value.trim()) {
        return value.trim();
    }
    if (Array.isArray(value)) {
        return headerValue(value[0]);
    }
    return undefined;
}
function queryToken(url) {
    if (!url) {
        return undefined;
    }
    try {
        const parsed = new URL(url, "http://localhost");
        return parsed.searchParams.get("token")?.trim() || undefined;
    }
    catch {
        return undefined;
    }
}
function safeEqual(candidate, expected) {
    const left = Buffer.from(candidate);
    const right = Buffer.from(expected);
    return left.length === right.length && timingSafeEqual(left, right);
}
function hasRegisterService(api) {
    return Boolean(api && typeof api === "object" && typeof api.registerService === "function");
}
function hasRegisterTool(api) {
    return Boolean(api && typeof api === "object" && typeof api.registerTool === "function");
}
function hasRegisterHttpRoute(api) {
    return Boolean(api && typeof api === "object" && typeof api.registerHttpRoute === "function");
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
