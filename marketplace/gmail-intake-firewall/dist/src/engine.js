import { buildQuarantineActions, buildSafeRoutingActions } from "./actions.js";
import { normalizeMessageForSecurity, shouldQuarantine } from "./securityClassifier.js";
import { isProcessed, recordDecision } from "./state.js";
export async function processMessage(message, config, state, deps) {
    if (!config.enabled) {
        return { state, skipped: true, skipReason: "plugin_disabled" };
    }
    const source = config.sources.find((candidate) => candidate.id === message.sourceId);
    if (!source) {
        return { state, skipped: true, skipReason: "unknown_source" };
    }
    if (!source.enabled) {
        return { state, skipped: true, skipReason: "source_disabled" };
    }
    if (isProcessed(state, message.sourceId, message.messageId)) {
        return { state, skipped: true, skipReason: "already_processed" };
    }
    const normalized = normalizeMessageForSecurity(message, config.security.maxBodyChars);
    const security = await deps.securityClassifier.classify(normalized);
    const quarantined = shouldQuarantine(security, config.security);
    const routing = quarantined
        ? undefined
        : applyRoutingPreference(message, await deps.routerClassifier.classify({ message, normalized, security }, config.tags), config, deps.routingPreferences ?? []);
    const actions = quarantined
        ? buildQuarantineActions(message, security, config, source)
        : buildSafeRoutingActions(message, routing, security, config.tags, config.wakeTargets, source);
    const decision = {
        processedAt: (deps.now ?? (() => new Date()))().toISOString(),
        sourceId: message.sourceId,
        accountEmail: message.accountEmail,
        messageId: message.messageId,
        threadId: message.threadId,
        security,
        actions,
        dryRun: config.dryRun,
    };
    if (routing) {
        decision.routing = routing;
    }
    return { state: recordDecision(state, decision), decision, skipped: false };
}
function applyRoutingPreference(message, routing, config, preferences) {
    const sender = message.from?.toLowerCase();
    if (!sender) {
        return routing;
    }
    const preference = preferences.find((candidate) => candidate.sourceId === message.sourceId && candidate.sender === sender);
    if (!preference) {
        return routing;
    }
    if (preference.type === "mute_sender") {
        return {
            tags: [],
            wakeMode: "none",
            sanitizedSummary: routing.sanitizedSummary,
            reasons: [...routing.reasons, `Human feedback preference muted sender ${message.from}`],
        };
    }
    const aggregateTag = config.tags.find((tag) => tag.wakeMode === "aggregate");
    if (!aggregateTag) {
        return routing;
    }
    const aggregateRouting = {
        tags: Array.from(new Set([...routing.tags, aggregateTag.id])),
        wakeMode: "aggregate",
        sanitizedSummary: routing.sanitizedSummary,
        reasons: [...routing.reasons, `Human feedback preference always aggregates sender ${message.from}`],
    };
    if (aggregateTag.wakeTarget) {
        aggregateRouting.wakeTarget = aggregateTag.wakeTarget;
    }
    return aggregateRouting;
}
