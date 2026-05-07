import type {
  AgentWakePayload,
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
): PlannedAction[] {
  const actions: PlannedAction[] = [];
  if (canApplyGmailModifications(source) && source.gmailActions.applyLabels) {
    actions.push({ type: "gmail_label", label: config.security.quarantineLabel, messageId: message.messageId });
  }
  if (canApplyGmailModifications(source) && source.gmailActions.archive && config.security.archiveOnQuarantine) {
    actions.push({ type: "gmail_archive", messageId: message.messageId });
  }
  for (const sink of config.alertSinks.filter((candidate) => candidate.enabled)) {
    if (sink.kind === "local_log") {
      actions.push({ type: "local_log", summary: classification.safeSummary, payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts) });
      continue;
    }
    if (sink.kind === "slack") {
      const alert: PlannedAction = {
        type: "human_alert",
        sink: "slack",
        summary: classification.safeSummary,
        payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts),
      };
      const target = sink.target ?? config.security.alertTarget;
      if (target) {
        alert.target = target;
      }
      actions.push(alert);
    }
  }
  if (!actions.some((action) => action.type === "human_alert" || action.type === "local_log")) {
    actions.push({ type: "local_log", summary: classification.safeSummary, payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts) });
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
  status: "succeeded" | "failed" | "skipped_dry_run";
  error?: string;
};

export async function executePlannedActions(
  actions: PlannedAction[],
  dryRun: boolean,
  deps: ActionExecutorDeps,
): Promise<ActionExecutionStatus[]> {
  if (dryRun) {
    return actions.map((action, actionIndex) => ({
      actionIndex,
      action,
      required: isRequiredExecutableAction(action),
      status: "skipped_dry_run",
    }));
  }
  const results: ActionExecutionStatus[] = [];
  for (const action of actions) {
    const actionIndex = results.length;
    const required = isRequiredExecutableAction(action);
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
        await deps.localLog?.write(action.summary, action.payload);
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
): PlannedAction[] {
  const actions: PlannedAction[] = [];
  const policy = resolveRoutingPolicy(routing, tags, wakeTargets);
  for (const tag of policy.tags) {
    if (tag?.gmailLabel && canApplyGmailModifications(source) && source.gmailActions.applyLabels) {
      actions.push({ type: "gmail_label", label: tag.gmailLabel, messageId: message.messageId });
    }
  }

  if (policy.wakeMode === "wake_now" && policy.wakeTarget) {
    const wakeAction: PlannedAction = {
      type: "agent_wake",
      target: policy.wakeTarget.id,
      payload: buildWakePayload(message, routing, security),
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
  return source.gmailActions.enabled && source.gmailActions.hasModifyScope;
}

function buildWakePayload(
  message: InboundMessage,
  routing: RoutingClassification,
  security: SecurityClassification,
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
): Record<string, unknown> {
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
    linkDomains: Array.from(new Set((message.linkUrls ?? []).flatMap((url) => {
      try {
        return [new URL(url).hostname.toLowerCase()];
      } catch {
        return [];
      }
    }))),
    attachments: message.attachments,
    riskReasons: classification.reasons,
    suspiciousSignals: classification.suspiciousSignals,
    sanitizedSummary: classification.safeSummary,
  };
  if (includeSnippet && message.snippet) {
    payload.snippet = message.snippet;
  }
  return payload;
}

function findHeader(headers: Record<string, string>, name: string): string | undefined {
  const lowerName = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === lowerName)?.[1];
}
