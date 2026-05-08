import type {
  ActionModeConfig,
  ActionExecutionMode,
  ActionsConfig,
  AgentWakePayload,
  ArtifactAnalysis,
  ArtifactWakeSummary,
  AggregateItem,
  InboundMessage,
  PlannedAction,
  PluginConfig,
  RoutingClassification,
  SecurityClassification,
  GmailSourceConfig,
  TagConfig,
  WakeTargetConfig,
} from "./types.js";

export function buildQuarantineActions(
  message: InboundMessage,
  classification: SecurityClassification,
  config: PluginConfig,
  source: GmailSourceConfig,
  artifactAnalysis?: ArtifactAnalysis,
): PlannedAction[] {
  const actions: PlannedAction[] = [];
  if (canApplyGmailModifications(source)) {
    actions.push({ type: "gmail_label", label: config.security.quarantineLabel, messageId: message.messageId });
  }
  if (canApplyGmailModifications(source) && config.security.archiveOnQuarantine) {
    actions.push({ type: "gmail_archive", messageId: message.messageId });
  }
  for (const sink of config.alertSinks.filter((candidate) => candidate.enabled)) {
    if (sink.kind === "local_log") {
      actions.push({ type: "local_log", summary: classification.safeSummary, payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts, artifactAnalysis) });
      continue;
    }
    if (sink.kind === "slack") {
      const alert: PlannedAction = {
        type: "human_alert",
        sink: "slack",
        summary: classification.safeSummary,
        payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts, artifactAnalysis),
      };
      const target = sink.target ?? config.security.alertTarget;
      if (target) {
        alert.target = target;
      }
      actions.push(alert);
    }
  }
  if (!actions.some((action) => action.type === "human_alert" || action.type === "local_log")) {
    actions.push({ type: "local_log", summary: classification.safeSummary, payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts, artifactAnalysis) });
  }
  return actions;
}

export type ActionExecutorDeps = {
  gmail?: {
    applyLabel(messageId: string, label: string): Promise<void>;
    removeLabel?(messageId: string, label: string): Promise<void>;
    archive(messageId: string): Promise<void>;
    restoreInbox?(messageId: string): Promise<void>;
  };
  slack?: {
    postAlert(target: string | undefined, summary: string, payload: Record<string, unknown> | undefined): Promise<void>;
  };
  wake?: {
    startDetachedAgentTurn(payload: AgentWakePayload): Promise<void>;
  };
  localLog?: {
    write(summary: string, payload: Record<string, unknown> | undefined): Promise<void>;
  };
};

export type ActionExecutionStatus = {
  actionIndex: number;
  action: PlannedAction;
  required: boolean;
  status: "succeeded" | "failed" | "skipped_dry_run" | "disabled";
  error?: string;
  reason?: string;
};

export type ActionExecutionOptions = {
  dryRun: boolean;
  actions: ActionsConfig;
  source?: GmailSourceConfig | undefined;
};

export async function executePlannedActions(
  actions: PlannedAction[],
  options: ActionExecutionOptions,
  deps: ActionExecutorDeps,
): Promise<ActionExecutionStatus[]> {
  const results: ActionExecutionStatus[] = [];
  for (const action of actions) {
    const actionIndex = results.length;
    const required = isRequiredExecutableAction(action);
    const gate = resolveActionGate(action, options);
    if (gate.status) {
      const gated: ActionExecutionStatus = { actionIndex, action, required, status: gate.status };
      if (gate.reason) {
        gated.reason = gate.reason;
      }
      results.push(gated);
      continue;
    }
    try {
      if (action.type === "gmail_label") {
        if (!deps.gmail) {
          throw new Error("Gmail action executor is not configured");
        }
        await deps.gmail.applyLabel(action.messageId, action.label);
      } else if (action.type === "gmail_remove_label") {
        if (!deps.gmail?.removeLabel) {
          throw new Error("Gmail label removal executor is not configured");
        }
        await deps.gmail.removeLabel(action.messageId, action.label);
      } else if (action.type === "gmail_archive") {
        if (!deps.gmail) {
          throw new Error("Gmail action executor is not configured");
        }
        await deps.gmail.archive(action.messageId);
      } else if (action.type === "gmail_restore_inbox") {
        if (!deps.gmail?.restoreInbox) {
          throw new Error("Gmail inbox restore executor is not configured");
        }
        await deps.gmail.restoreInbox(action.messageId);
      } else if (action.type === "human_alert" && action.sink === "slack") {
        if (!deps.slack) {
          throw new Error("Slack alert executor is not configured");
        }
        await deps.slack.postAlert(action.target, action.summary, action.payload);
      } else if (action.type === "local_log") {
        if (!deps.localLog) {
          throw new Error("Local log executor is not configured");
        }
        await deps.localLog.write(action.summary, action.payload);
      } else if (action.type === "agent_wake") {
        if (!deps.wake) {
          throw new Error("Detached wake executor is not configured");
        }
        await deps.wake.startDetachedAgentTurn(action.payload);
      }
      results.push({ actionIndex, action, required, status: "succeeded" });
    } catch (error) {
      const failed: ActionExecutionStatus = {
        actionIndex,
        action,
        required,
        status: "failed",
      };
      if (error instanceof Error) {
        failed.error = error.message;
      } else {
        failed.error = String(error);
      }
      results.push(failed);
    }
  }
  return results;
}

export function requiredActionsSucceeded(results: ActionExecutionStatus[]): boolean {
  return results.every((result) => !result.required || result.status !== "failed");
}

function isRequiredExecutableAction(action: PlannedAction): boolean {
  return action.type === "gmail_label"
    || action.type === "gmail_remove_label"
    || action.type === "gmail_archive"
    || action.type === "gmail_restore_inbox"
    || action.type === "human_alert"
    || action.type === "agent_wake";
}

export function buildSafeRoutingActions(
  message: InboundMessage,
  routing: RoutingClassification,
  security: SecurityClassification,
  tags: TagConfig[],
  wakeTargets: WakeTargetConfig[],
  source: GmailSourceConfig,
  artifactAnalysis?: ArtifactAnalysis,
): PlannedAction[] {
  const actions: PlannedAction[] = [];
  const policy = resolveRoutingPolicy(routing, tags, wakeTargets);
  for (const tag of policy.tags) {
    if (tag?.gmailLabel && canApplyGmailModifications(source)) {
      actions.push({ type: "gmail_label", label: tag.gmailLabel, messageId: message.messageId });
    }
  }

  if (policy.wakeMode === "wake_now" && policy.wakeTarget) {
    const wakeAction: PlannedAction = {
      type: "agent_wake",
      target: policy.wakeTarget.id,
      payload: buildWakePayload(message, routing, security, artifactAnalysis),
    };
    wakeAction.payload.wakeTarget = policy.wakeTarget;
    actions.push(wakeAction);
  } else if (policy.wakeMode === "aggregate") {
    const item = buildAggregateItem(message, routing);
    if (policy.aggregateCadence) {
      item.cadence = policy.aggregateCadence;
    }
    const aggregateAction: PlannedAction = {
      type: "aggregate_enqueue",
      item,
    };
    if (policy.aggregateCadence) {
      aggregateAction.cadence = policy.aggregateCadence;
    }
    actions.push(aggregateAction);
  } else if (actions.length === 0) {
    actions.push({ type: "record_only", reason: "safe_message_no_wake" });
  }

  return actions;
}

function canApplyGmailModifications(source: GmailSourceConfig): boolean {
  return source.gmailActions.hasModifyScope;
}

export function resolveActionMode(
  action: PlannedAction,
  actions: ActionsConfig,
): { path: string; mode: ActionExecutionMode } {
  if (action.type === "gmail_label") {
    return { path: "actions.gmail.label.mode", mode: actions.gmail.label.mode };
  }
  if (action.type === "gmail_remove_label") {
    return { path: "actions.gmail.removeLabel.mode", mode: actions.gmail.removeLabel.mode };
  }
  if (action.type === "gmail_archive") {
    return { path: "actions.gmail.archive.mode", mode: actions.gmail.archive.mode };
  }
  if (action.type === "gmail_restore_inbox") {
    return { path: "actions.gmail.restoreInbox.mode", mode: actions.gmail.restoreInbox.mode };
  }
  if (action.type === "human_alert" && action.sink === "slack") {
    return { path: "actions.slack.alert.mode", mode: actions.slack.alert.mode };
  }
  if (action.type === "local_log") {
    return { path: "actions.local.log.mode", mode: actions.local.log.mode };
  }
  if (action.type === "agent_wake") {
    return { path: "actions.wake.agent.mode", mode: actions.wake.agent.mode };
  }
  return { path: "actions.local.log.mode", mode: "live" };
}

export function resolveConfiguredMode(
  modeConfig: ActionModeConfig,
  path: string,
  dryRun: boolean,
): { mode: ActionExecutionMode; reason?: string } {
  if (dryRun) {
    return { mode: "dry_run", reason: "dryRun is enabled" };
  }
  if (modeConfig.mode === "dry_run") {
    return { mode: "dry_run", reason: `${path} is dry_run` };
  }
  if (modeConfig.mode === "disabled") {
    return { mode: "disabled", reason: `${path} is disabled` };
  }
  return { mode: "live" };
}

function resolveActionGate(
  action: PlannedAction,
  options: ActionExecutionOptions,
): { status?: "skipped_dry_run" | "disabled"; reason?: string } {
  if (action.type === "record_only" || action.type === "aggregate_enqueue") {
    return {};
  }
  const { path, mode } = resolveActionMode(action, options.actions);
  const resolved = resolveConfiguredMode({ mode }, path, options.dryRun);
  if (resolved.mode === "dry_run") {
    return resolved.reason
      ? { status: "skipped_dry_run", reason: resolved.reason }
      : { status: "skipped_dry_run" };
  }
  if (resolved.mode === "disabled") {
    return resolved.reason
      ? { status: "disabled", reason: resolved.reason }
      : { status: "disabled" };
  }
  if (isGmailAction(action) && options.source && !options.source.gmailActions.hasModifyScope) {
    return { status: "disabled", reason: `sources.${options.source.id}.gmailActions.hasModifyScope is false` };
  }
  return {};
}

function isGmailAction(action: PlannedAction): boolean {
  return action.type === "gmail_label"
    || action.type === "gmail_remove_label"
    || action.type === "gmail_archive"
    || action.type === "gmail_restore_inbox";
}

function buildWakePayload(
  message: InboundMessage,
  routing: RoutingClassification,
  security: SecurityClassification,
  artifactAnalysis?: ArtifactAnalysis,
): AgentWakePayload {
  const payload: AgentWakePayload = {
    sourceId: message.sourceId,
    accountEmail: message.accountEmail,
    messageId: message.messageId,
    threadId: message.threadId,
    tags: routing.tags,
    sanitizedSummary: routing.sanitizedSummary,
    security,
  };
  const artifactSummary = buildArtifactWakeSummary(artifactAnalysis);
  if (artifactSummary) {
    payload.artifacts = artifactSummary;
  }
  if (message.subject) {
    payload.subject = message.subject;
  }
  if (message.from) {
    payload.from = message.from;
  }
  return payload;
}

function resolveRoutingPolicy(
  routing: RoutingClassification,
  tags: TagConfig[],
  wakeTargets: WakeTargetConfig[],
): {
  tags: TagConfig[];
  wakeMode: "none" | "wake_now" | "aggregate";
  wakeTarget?: WakeTargetConfig;
  aggregateCadence?: string;
} {
  const validTags = routing.tags
    .map((tagId) => tags.find((tag) => tag.id === tagId))
    .filter((tag): tag is TagConfig => Boolean(tag));

  const wakeTag = validTags.find((tag) => tag.wakeMode === "wake_now" && tag.wakeTarget);
  if (wakeTag?.wakeTarget) {
    const wakeTarget = wakeTargets.find((target) => target.id === wakeTag.wakeTarget);
    if (wakeTarget) {
      return { tags: validTags, wakeMode: "wake_now", wakeTarget };
    }
  }

  const aggregateTag = validTags.find((tag) => tag.wakeMode === "aggregate");
  if (aggregateTag) {
    const policy: {
      tags: TagConfig[];
      wakeMode: "aggregate";
      aggregateCadence?: string;
    } = {
      tags: validTags,
      wakeMode: "aggregate",
    };
    if (aggregateTag.aggregateCadence) {
      policy.aggregateCadence = aggregateTag.aggregateCadence;
    }
    return policy;
  }

  return { tags: validTags, wakeMode: "none" };
}

function buildAggregateItem(message: InboundMessage, routing: RoutingClassification): AggregateItem {
  const item: AggregateItem = {
    sourceId: message.sourceId,
    accountEmail: message.accountEmail,
    messageId: message.messageId,
    threadId: message.threadId,
    tags: routing.tags,
    sanitizedSummary: routing.sanitizedSummary,
    queuedAt: new Date().toISOString(),
  };
  if (routing.wakeTarget) {
    item.wakeTarget = routing.wakeTarget;
  }
  return item;
}

function buildSuspiciousAlertPayload(
  message: InboundMessage,
  classification: SecurityClassification,
  includeSnippet: boolean,
  artifactAnalysis?: ArtifactAnalysis,
): Record<string, unknown> {
  const artifactSummary = buildArtifactWakeSummary(artifactAnalysis);
  const payload: Record<string, unknown> = {
    sourceId: message.sourceId,
    accountEmail: message.accountEmail,
    sender: message.from,
    replyTo: findHeader(message.headers, "reply-to"),
    recipients: message.to,
    cc: message.cc,
    subject: message.subject,
    date: findHeader(message.headers, "date"),
    messageId: message.messageId,
    threadId: message.threadId,
    gmailLink: `https://mail.google.com/mail/u/${encodeURIComponent(message.accountEmail)}/#all/${encodeURIComponent(message.messageId)}`,
    labels: message.labels,
    authHeaders: {
      authenticationResults: findHeader(message.headers, "authentication-results"),
      receivedSpf: findHeader(message.headers, "received-spf"),
      dkimSignature: findHeader(message.headers, "dkim-signature"),
      arcAuthenticationResults: findHeader(message.headers, "arc-authentication-results"),
    },
    linkDomains: artifactSummary?.linkDomains ?? Array.from(new Set((message.linkUrls ?? []).flatMap((url) => {
      try {
        return [new URL(url).hostname.toLowerCase()];
      } catch {
        return [];
      }
    }))),
    links: artifactAnalysis?.links,
    linkRiskHints: artifactSummary?.linkRiskHints,
    attachments: artifactAnalysis?.attachments ?? message.attachments,
    attachmentRiskHints: artifactSummary?.attachmentRiskHints,
    artifactNotes: artifactAnalysis?.notes,
    riskReasons: classification.reasons,
    suspiciousSignals: classification.suspiciousSignals,
    sanitizedSummary: classification.safeSummary,
  };
  if (includeSnippet && message.snippet) {
    payload.snippet = message.snippet;
  }
  return payload;
}

function buildArtifactWakeSummary(artifactAnalysis: ArtifactAnalysis | undefined): ArtifactWakeSummary | undefined {
  if (!artifactAnalysis) {
    return undefined;
  }
  return {
    linkCount: artifactAnalysis.links.length,
    linkDomains: Array.from(new Set(artifactAnalysis.links.map((link) => link.domain).filter(Boolean))),
    linkRiskHints: Array.from(new Set(artifactAnalysis.links.flatMap((link) => link.riskHints))),
    attachmentCount: artifactAnalysis.attachments.length,
    attachments: artifactAnalysis.attachments,
    attachmentRiskHints: Array.from(new Set(artifactAnalysis.attachments.flatMap((attachment) => attachment.riskHints))),
  };
}

function findHeader(headers: Record<string, string>, name: string): string | undefined {
  const lowerName = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === lowerName)?.[1];
}
