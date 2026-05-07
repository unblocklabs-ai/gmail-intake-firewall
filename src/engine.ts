import { buildQuarantineActions, buildSafeRoutingActions } from "./actions.js";
import type { RouterClassifier } from "./routerClassifier.js";
import type { SecurityClassifier } from "./securityClassifier.js";
import { normalizeMessageForSecurity, shouldQuarantine } from "./securityClassifier.js";
import { isProcessed, recordDecision, type FirewallState } from "./state.js";
import type { DecisionLogEntry, InboundMessage, PluginConfig, ProcessSkipReason, RoutingClassification, RoutingPreference } from "./types.js";

export type ProcessMessageDeps = {
  securityClassifier: SecurityClassifier;
  routerClassifier: RouterClassifier;
  routingPreferences?: RoutingPreference[];
  now?: () => Date;
};

export async function processMessage(
  message: InboundMessage,
  config: PluginConfig,
  state: FirewallState,
  deps: ProcessMessageDeps,
): Promise<{ state: FirewallState; decision?: DecisionLogEntry; skipped: boolean; skipReason?: ProcessSkipReason }> {
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
    : applyRoutingPreference(
      message,
      await deps.routerClassifier.classify({ message, normalized, security }, config.tags),
      config,
      deps.routingPreferences ?? [],
    );
  const actions = quarantined
    ? buildQuarantineActions(message, security, config, source, normalized.artifactAnalysis)
    : buildSafeRoutingActions(message, routing!, security, config.tags, config.wakeTargets, source, normalized.artifactAnalysis);

  const decision: DecisionLogEntry = {
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

function applyRoutingPreference(
  message: InboundMessage,
  routing: RoutingClassification,
  config: PluginConfig,
  preferences: RoutingPreference[],
): RoutingClassification {
  const sender = message.from?.toLowerCase();
  const domain = sender?.split("@").pop();
  if (!sender && !domain) {
    return routing;
  }
  const preference = preferences.find((candidate) => candidate.sourceId === message.sourceId && (
    (candidate.scope === "sender" && candidate.value === sender) ||
    (candidate.scope === "domain" && candidate.value === domain)
  ));
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
  const aggregateRouting: RoutingClassification = {
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
