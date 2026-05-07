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
    const normalized = normalizeMessageForSecurity(message, config.security.maxBodyChars, config.artifacts);
    const security = await deps.securityClassifier.classify(normalized);
    const quarantined = shouldQuarantine(security, config.security);
    const routing = quarantined
        ? undefined
        : applyRoutingPreference(message, await deps.routerClassifier.classify({ message, normalized, security }, config.tags), config, deps.routingPreferences ?? []);
    const actions = quarantined
        ? buildQuarantineActions(message, security, config, source, normalized.artifactAnalysis)
        : buildSafeRoutingActions(message, routing, security, config.tags, config.wakeTargets, source, normalized.artifactAnalysis);
    const decision = {
        processedAt: (deps.now ?? (() => new Date()))().toISOString(),
        sourceId: message.sourceId,
        accountEmail: message.accountEmail,
        messageId: message.messageId,
        threadId: message.threadId,
        security,
        artifactAnalysis: normalized.artifactAnalysis,
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
    const domain = sender?.split("@").pop();
    if (!sender && !domain) {
        return routing;
    }
    const preference = preferences.find((candidate) => candidate.sourceId === message.sourceId && ((candidate.scope === "sender" && candidate.value === sender) ||
        (candidate.scope === "domain" && candidate.value === domain)));
    if (!preference) {
        return routing;
    }
    const preferenceTarget = preference.scope === "domain" ? `domain ${preference.value}` : `sender ${preference.value}`;
    if (preference.type === "mute") {
        return {
            tags: [],
            wakeMode: "none",
            sanitizedSummary: routing.sanitizedSummary,
            reasons: [...routing.reasons, `Human feedback preference muted ${preferenceTarget}`],
        };
    }
    const aggregateTag = config.tags.find((tag) => tag.wakeMode === "aggregate");
    if (!aggregateTag) {
        return routing;
    }
    const nonInterruptingTags = routing.tags.filter((tagId) => {
        const tag = config.tags.find((candidate) => candidate.id === tagId);
        return tag?.wakeMode !== "wake_now";
    });
    const aggregateRouting = {
        tags: Array.from(new Set([...nonInterruptingTags, aggregateTag.id])),
        wakeMode: "aggregate",
        sanitizedSummary: routing.sanitizedSummary,
        reasons: [...routing.reasons, `Human feedback preference always aggregates ${preferenceTarget}`],
    };
    if (aggregateTag.wakeTarget) {
        aggregateRouting.wakeTarget = aggregateTag.wakeTarget;
    }
    return aggregateRouting;
}
