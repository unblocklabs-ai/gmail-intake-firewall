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
        : await deps.routerClassifier.classify({ message, normalized, security }, config.tags);
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
