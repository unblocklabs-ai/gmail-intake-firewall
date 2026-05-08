import { buildDigestWake } from "./aggregate.js";
import {
  executePlannedActions,
  requiredActionsSucceeded,
  resolveConfiguredMode,
  type ActionExecutionStatus,
  type ActionExecutorDeps,
} from "./actions.js";
import { buildCandidateQuery, candidateToIntakeEvent, type GmailCandidate, type GmailClient, type GmailHistoryPage, type GmailPushNotification } from "./gmail.js";
import { gmailScopesAllowModify } from "./googleAuth.js";
import { processMessage, type ProcessMessageDeps } from "./engine.js";
import { createNoopRouterClassifier } from "./routerClassifier.js";
import { createUnavailableSecurityClassifier } from "./securityClassifier.js";
import { createEmptyState, type FirewallState, type SqliteStateStore } from "./state.js";
import type { AgentWakePayload, DecisionLogEntry, GmailSourceConfig, IntakeEvent, PlannedAction, PluginConfig, SecurityClassification } from "./types.js";

export type GmailClientFactory = (source: GmailSourceConfig) => Promise<GmailClient> | GmailClient;

export type RuntimeLogger = {
  info?: (message: string, metadata?: Record<string, unknown>) => void;
  warn?: (message: string, metadata?: Record<string, unknown>) => void;
  error?: (message: string, metadata?: Record<string, unknown>) => void;
};

export type PollingRuntimeDeps = Partial<ProcessMessageDeps> & {
  stateStore: SqliteStateStore;
  gmailClientFactory: GmailClientFactory;
  actionDeps?: ActionExecutorDeps;
  logger?: RuntimeLogger;
  now?: () => Date;
  setInterval?: typeof setInterval;
  clearInterval?: typeof clearInterval;
};

export type PollingRunSummary = {
  sources: number;
  events: number;
  fetched: number;
  processed: number;
  skipped: number;
  errors: number;
};

export type BackfillOptions = {
  sourceId: string;
  query?: string;
  maxResults?: number;
  force?: boolean;
  dryRun?: boolean;
};

export type ReplayOptions = {
  sourceId: string;
  messageId: string;
  force?: boolean;
  dryRun?: boolean;
};

export type GmailNotificationOptions = GmailPushNotification & {
  force?: boolean;
  dryRun?: boolean;
};

export type WatchLifecycleOptions = {
  sourceId?: string;
  force?: boolean;
};

type TimerHandle = ReturnType<typeof setInterval>;
type PollStage =
  | "client_create"
  | "candidate_list"
  | "event_record"
  | "message_fetch"
  | "thread_context"
  | "classification"
  | "action_execute"
  | "cursor_update";

type SourcePollDiagnostic = {
  status: "running" | "succeeded" | "completed_with_errors" | "failed" | "skipped";
  startedAt?: string;
  finishedAt?: string;
  stage?: PollStage;
  eventCount?: number;
  fetched?: number;
  processed?: number;
  skipped?: number;
  errors?: number;
  error?: {
    name?: string;
    message: string;
    code?: string | number;
    status?: string | number;
  };
};
type SafeRuntimeError = NonNullable<SourcePollDiagnostic["error"]>;
type ProcessEventResult = Pick<PollingRunSummary, "fetched" | "processed" | "skipped" | "errors"> & {
  diagnostic?: {
    stage: PollStage;
    error: SafeRuntimeError;
  };
};
type ProcessCandidateEventsResult = Pick<PollingRunSummary, "events" | "fetched" | "processed" | "skipped" | "errors"> & {
  lastEventDiagnostic?: ProcessEventResult["diagnostic"];
  stage: PollStage;
};
type NotificationSourceResolution = {
  source?: GmailSourceConfig;
  error?: string;
};

export class GmailIntakePollingRuntime {
  private readonly timers = new Map<string, TimerHandle>();
  private readonly inFlightSources = new Set<string>();
  private readonly pollDiagnostics = new Map<string, SourcePollDiagnostic>();
  private running = false;

  constructor(
    private readonly config: PluginConfig,
    private readonly deps: PollingRuntimeDeps,
  ) {}

  start(): PollingRunSummary {
    if (this.running || !this.config.enabled) {
      return this.emptySummary();
    }
    this.running = true;
    const setTimer = this.deps.setInterval ?? setInterval;
    for (const source of this.enabledSources()) {
      void this.runSource(source);
      const timer = setTimer(() => {
        void this.runSource(source);
      }, source.polling.intervalMs);
      this.timers.set(source.id, timer);
    }
    return this.emptySummary();
  }

  stop(): void {
    const clearTimer = this.deps.clearInterval ?? clearInterval;
    for (const timer of this.timers.values()) {
      clearTimer(timer);
    }
    this.timers.clear();
    this.running = false;
  }

  async runOnce(): Promise<PollingRunSummary> {
    const summary = this.emptySummary();
    if (!this.config.enabled) {
      return summary;
    }
    for (const source of this.enabledSources()) {
      const sourceSummary = await this.runSource(source);
      summary.sources += sourceSummary.sources;
      summary.events += sourceSummary.events;
      summary.fetched += sourceSummary.fetched;
      summary.processed += sourceSummary.processed;
      summary.skipped += sourceSummary.skipped;
      summary.errors += sourceSummary.errors;
    }
    return summary;
  }

  async runBackfill(options: BackfillOptions): Promise<PollingRunSummary> {
    const source = this.config.sources.find((candidate) => candidate.id === options.sourceId);
    const summary = this.emptySummary();
    if (!source || !source.enabled || !this.config.enabled) {
      summary.skipped += 1;
      return summary;
    }
    summary.sources = 1;
    let client: GmailClient;
    let candidates: GmailCandidate[];
    try {
      client = await this.deps.gmailClientFactory(source);
      candidates = await client.listCandidates(options.query ?? buildCandidateQuery(source));
    } catch (error) {
      summary.errors += 1;
      const safeError = safeRuntimeError(error);
      this.deps.logger?.error?.("gmail-intake-firewall backfill list failed", {
        sourceId: source.id,
        error: safeError.message,
        ...(safeError.code !== undefined ? { code: safeError.code } : {}),
        ...(safeError.status !== undefined ? { status: safeError.status } : {}),
      });
      return summary;
    }
    const limitedCandidates = candidates.slice(0, options.maxResults ?? source.polling.maxResults);
    const observedAt = this.now();
    for (const candidate of limitedCandidates) {
      const event = candidateToIntakeEvent(source, candidate, observedAt);
      this.deps.stateStore.recordEvent(event);
      const processOptions: { force?: boolean; dryRun?: boolean } = { force: options.force ?? false };
      if (typeof options.dryRun === "boolean") {
        processOptions.dryRun = options.dryRun;
      }
      const result = await this.processEvent(client, event, processOptions);
      summary.events += 1;
      summary.fetched += result.fetched;
      summary.processed += result.processed;
      summary.skipped += result.skipped;
      summary.errors += result.errors;
    }
    return summary;
  }

  async drainAggregates(now = this.now()): Promise<PollingRunSummary> {
    const summary = this.emptySummary();
    const items = this.deps.stateStore.listAggregateQueue(this.config.aggregate.maxDigestItems);
    const dueItems = items.filter((item) => aggregateItemDue(item.queuedAt, item.cadence, now, this.config.aggregate.timezone));
    const groups = groupAggregateItems(dueItems);
    for (const group of groups) {
      const wake = buildDigestWake(group.items, group.key);
      if (!wake) {
        continue;
      }
      const wakeTarget = group.wakeTarget
        ? this.config.wakeTargets.find((target) => target.id === group.wakeTarget)
        : undefined;
      if (wakeTarget) {
        wake.wakeTarget = wakeTarget;
      }
      try {
        if (group.wakeTarget && !wakeTarget) {
          throw new Error(`Aggregate wake target is not configured: ${group.wakeTarget}`);
        }
        const aggregateMode = resolveConfiguredMode(
          this.config.actions.wake.aggregate,
          "actions.wake.aggregate.mode",
          this.config.dryRun,
        );
        const wakeExecutor = this.deps.actionDeps?.wake;
        if (!wakeExecutor && aggregateMode.mode === "live") {
          throw new Error("Detached wake executor is not configured");
        }
        if (aggregateMode.mode === "dry_run") {
          this.deps.logger?.info?.("gmail-intake-firewall dry-run aggregate wake", {
            group: group.key,
            itemCount: group.items.length,
            wake,
            reason: aggregateMode.reason,
          });
        } else if (aggregateMode.mode === "disabled") {
          this.deps.logger?.info?.("gmail-intake-firewall aggregate wake disabled", {
            group: group.key,
            itemCount: group.items.length,
            reason: aggregateMode.reason,
          });
          summary.skipped += group.items.length;
          continue;
        } else {
          await wakeExecutor!.startDetachedAgentTurn(wake);
          this.deps.stateStore.markAggregateDelivered(group.items, now.toISOString());
        }
        summary.processed += group.items.length;
      } catch (error) {
        summary.errors += 1;
        this.deps.logger?.error?.("gmail-intake-firewall aggregate drain failed", {
          group: group.key,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return summary;
  }

  probe(): Record<string, unknown> {
    return {
      running: this.running,
      configuredSources: this.config.sources.length,
      enabledSources: this.enabledSources().length,
      sqlitePath: this.config.sqlitePath,
    };
  }

  status(): Record<string, unknown> {
    const sources = this.config.sources.map((source) => {
      const cursor = this.deps.stateStore.getSourceCursor(source.id);
      return {
        id: source.id,
        accountEmail: source.accountEmail,
        enabled: source.enabled,
        intakeMode: source.intakeMode ?? "poll",
        polling: source.polling,
        gmailActions: {
          hasModifyScope: source.gmailActions.hasModifyScope,
        },
        lastPoll: this.pollDiagnostics.get(source.id),
        readiness: buildSourceReadiness(source, cursor, this.config.watch, this.now()),
        cursor,
        stats: this.deps.stateStore.getSourceStats(source.id),
      };
    });
    return {
      running: this.running,
      enabled: this.config.enabled,
      dryRun: this.config.dryRun,
      sqlitePath: this.config.sqlitePath,
      aggregate: {
        timezone: this.config.aggregate.timezone,
        pending: this.deps.stateStore.countPendingAggregates(),
        maxDigestItems: this.config.aggregate.maxDigestItems,
      },
      sources,
    };
  }

  inspectMessage(sourceId: string, messageId: string): Record<string, unknown> {
    return {
      sourceId,
      messageId,
      processed: this.deps.stateStore.isProcessed(sourceId, messageId),
      events: this.deps.stateStore.listEvents(sourceId, messageId),
      decisions: this.deps.stateStore.listDecisions(sourceId, messageId),
      latestActionStatuses: this.deps.stateStore.listActionStatuses(sourceId, messageId),
      actionAttempts: this.deps.stateStore.listActionAttempts(sourceId, messageId),
    };
  }

  listQuarantine(limit = 25, sourceId?: string): Record<string, unknown> {
    return {
      stats: this.deps.stateStore.getReviewStats(sourceId),
      items: this.deps.stateStore.listQuarantine(limit, sourceId).map((decision) => safeQuarantineItem(decision, {
        feedback: this.deps.stateStore.listFeedbackForMessage(String(decision.sourceId), String(decision.messageId), 10),
        compact: true,
      })),
    };
  }

  listPreferences(sourceId?: string): Record<string, unknown> {
    return {
      preferences: this.deps.stateStore.listRoutingPreferences(sourceId),
    };
  }

  reviewSummary(sourceId?: string): Record<string, unknown> {
    return this.deps.stateStore.getReviewStats(sourceId);
  }

  getQuarantineItem(sourceId: string, messageId: string): Record<string, unknown> {
    const decision = this.deps.stateStore.listDecisions(sourceId, messageId, 1)[0];
    if (!decision || decision.routing) {
      return { found: false };
    }
    return {
      found: true,
      item: safeQuarantineItem(decision, {
        feedback: this.deps.stateStore.listFeedbackForMessage(sourceId, messageId, 100),
        actionStatuses: this.deps.stateStore.listActionStatuses(sourceId, messageId),
        actionAttempts: this.deps.stateStore.listActionAttempts(sourceId, messageId),
      }),
    };
  }

  recordReviewFeedback(input: {
    sourceId: string;
    messageId: string;
    feedbackType: string;
    actor?: string;
    reason?: string;
    sender?: string;
    domain?: string;
  }): Record<string, unknown> {
    const decision = this.deps.stateStore.listDecisions(input.sourceId, input.messageId, 1)[0];
    const sender = normalizeEmailAddress(input.sender ?? senderFromDecision(decision));
    const domain = normalizeDomain(input.domain ?? domainFromSender(sender));
    const event = {
      createdAt: this.now().toISOString(),
      sourceId: input.sourceId,
      messageId: input.messageId,
      threadId: typeof decision?.threadId === "string" ? decision.threadId : undefined,
      feedbackType: input.feedbackType,
      actor: input.actor,
      reason: input.reason,
      sender,
      domain,
    };
    this.deps.stateStore.recordFeedback(event);
    return { recorded: true, feedback: event };
  }

  async wakeReviewedMessage(input: {
    sourceId: string;
    messageId: string;
    actor?: string;
    reason?: string;
    wakeTarget?: string;
    dryRun?: boolean;
  }): Promise<Record<string, unknown>> {
    const decision = this.deps.stateStore.listDecisions(input.sourceId, input.messageId, 1)[0];
    if (!decision) {
      return { found: false, executed: false };
    }
    const source = this.config.sources.find((candidate) => candidate.id === input.sourceId);
    const wakeTargetId = input.wakeTarget;
    if (!wakeTargetId) {
      return { found: true, executed: false, error: "wakeTarget is required for reviewed quarantine wake." };
    }
    const wakeTarget = this.config.wakeTargets.find((target) => target.id === wakeTargetId);
    if (!wakeTarget) {
      return { found: true, executed: false, error: `Unknown wake target: ${wakeTargetId}` };
    }
    const security = decision.security as SecurityClassification;
    const payload: AgentWakePayload = {
      sourceId: input.sourceId,
      accountEmail: String(decision.accountEmail),
      messageId: input.messageId,
      threadId: String(decision.threadId),
      tags: ["human-reviewed"],
      sanitizedSummary: security.safeSummary,
      security,
      wakeTarget,
    };
    const subject = subjectFromDecision(decision);
    if (subject) {
      payload.subject = subject;
    }
    const sender = senderFromDecision(decision);
    if (sender) {
      payload.from = sender;
    }
    const action: PlannedAction = {
      type: "agent_wake",
      target: wakeTargetId,
      payload,
    };
    const actionResults = await executePlannedActions([action], {
      dryRun: input.dryRun ?? this.config.dryRun,
      actions: this.config.actions,
      source,
    }, this.deps.actionDeps ?? {});
    const attemptedAt = this.now().toISOString();
    for (const actionResult of actionResults) {
      this.deps.stateStore.recordActionStatus(decision as DecisionLogEntry, actionResult, attemptedAt);
    }
    const feedbackInput: {
      sourceId: string;
      messageId: string;
      feedbackType: string;
      actor?: string;
      reason?: string;
    } = {
      sourceId: input.sourceId,
      messageId: input.messageId,
      feedbackType: "wake_now",
    };
    if (input.actor) {
      feedbackInput.actor = input.actor;
    }
    if (input.reason) {
      feedbackInput.reason = input.reason;
    }
    const feedback = this.recordReviewFeedback(feedbackInput);
    return {
      found: true,
      executed: actionResults.every((result) => result.status !== "failed"),
      actionResults,
      feedback: feedback.feedback,
    };
  }

  async releaseFromQuarantine(input: {
    sourceId: string;
    messageId: string;
    actor?: string;
    reason?: string;
    restoreInbox?: boolean;
    dryRun?: boolean;
  }): Promise<Record<string, unknown>> {
    const source = this.config.sources.find((candidate) => candidate.id === input.sourceId);
    const decision = this.deps.stateStore.listDecisions(input.sourceId, input.messageId, 1)[0];
    if (!source || !decision || decision.routing) {
      return { found: false, executed: false };
    }
    const actions: PlannedAction[] = [];
    if (source.gmailActions.hasModifyScope) {
      actions.push({ type: "gmail_remove_label", label: this.config.security.quarantineLabel, messageId: input.messageId });
      if (input.restoreInbox) {
        actions.push({ type: "gmail_restore_inbox", messageId: input.messageId });
      }
    }
    let actionResults: ActionExecutionStatus[] = [];
    if (actions.length > 0) {
      const client = await this.deps.gmailClientFactory(source);
      actionResults = await executePlannedActions(actions, {
        dryRun: input.dryRun ?? this.config.dryRun,
        actions: this.config.actions,
        source,
      }, {
        ...(this.deps.actionDeps ?? {}),
        gmail: this.deps.actionDeps?.gmail ?? client,
      });
      const attemptedAt = this.now().toISOString();
      for (const actionResult of actionResults) {
        this.deps.stateStore.recordActionStatus(decision as DecisionLogEntry, actionResult, attemptedAt);
      }
    }
    const feedbackInput: {
      sourceId: string;
      messageId: string;
      feedbackType: string;
      actor?: string;
      reason?: string;
    } = {
      sourceId: input.sourceId,
      messageId: input.messageId,
      feedbackType: "release_from_quarantine",
    };
    if (input.actor) {
      feedbackInput.actor = input.actor;
    }
    if (input.reason) {
      feedbackInput.reason = input.reason;
    }
    const feedback = this.recordReviewFeedback(feedbackInput);
    return {
      found: true,
      executed: actionResults.length === 0 || actionResults.every((result) => result.status !== "failed"),
      actionResults,
      feedback: feedback.feedback,
      gmailMutationConfigured: source.gmailActions.hasModifyScope,
    };
  }

  async replayWithFeedback(input: ReplayOptions & {
    actor?: string;
    reason?: string;
    feedbackType?: string;
  }): Promise<Record<string, unknown>> {
    const feedback = this.recordReviewFeedback({
      sourceId: input.sourceId,
      messageId: input.messageId,
      feedbackType: input.feedbackType ?? "safe",
      ...(input.actor ? { actor: input.actor } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
    });
    const replay = await this.replayEvent({
      sourceId: input.sourceId,
      messageId: input.messageId,
      force: input.force ?? true,
      ...(typeof input.dryRun === "boolean" ? { dryRun: input.dryRun } : {}),
    });
    return {
      feedback: feedback.feedback,
      replay,
    };
  }

  async replayEvent(options: ReplayOptions): Promise<PollingRunSummary> {
    const summary = this.emptySummary();
    const source = this.config.sources.find((candidate) => candidate.id === options.sourceId);
    if (!source || !source.enabled || !this.config.enabled) {
      summary.skipped += 1;
      return summary;
    }
    const event = this.deps.stateStore.findLatestEvent(options.sourceId, options.messageId);
    if (!event) {
      summary.skipped += 1;
      return summary;
    }
    let client: GmailClient;
    try {
      client = await this.deps.gmailClientFactory(source);
    } catch (error) {
      summary.sources = 1;
      summary.events = 1;
      summary.errors += 1;
      const safeError = safeRuntimeError(error);
      this.deps.logger?.error?.("gmail-intake-firewall replay client creation failed", {
        sourceId: source.id,
        messageId: options.messageId,
        error: safeError.message,
        ...(safeError.code !== undefined ? { code: safeError.code } : {}),
        ...(safeError.status !== undefined ? { status: safeError.status } : {}),
      });
      return summary;
    }
    const result = await this.processEvent(client, {
      ...event,
      observedAt: this.now().toISOString(),
    }, {
      force: options.force ?? false,
      ...(typeof options.dryRun === "boolean" ? { dryRun: options.dryRun } : {}),
    });
    summary.sources = 1;
    summary.events = 1;
    summary.fetched += result.fetched;
    summary.processed += result.processed;
    summary.skipped += result.skipped;
    summary.errors += result.errors;
    return summary;
  }

  async handleGmailNotification(options: GmailNotificationOptions): Promise<PollingRunSummary> {
    const summary = this.emptySummary();
    const resolution = this.findNotificationSource(options);
    const source = resolution.source;
    if (resolution.error) {
      summary.errors += 1;
      if (source) {
        summary.sources = 1;
        const safeError = safeRuntimeError(new Error(resolution.error));
        this.pollDiagnostics.set(source.id, {
          status: "failed",
          finishedAt: this.now().toISOString(),
          stage: "client_create",
          errors: 1,
          error: safeError,
        });
        this.deps.logger?.error?.("gmail-intake-firewall Gmail notification rejected", {
          sourceId: source.id,
          stage: "client_create",
          error: safeError.message,
        });
      }
      return summary;
    }
    if (!source || !source.enabled || !this.config.enabled) {
      summary.skipped += 1;
      return summary;
    }
    summary.sources = 1;
    if (this.inFlightSources.has(source.id)) {
      summary.skipped += 1;
      this.pollDiagnostics.set(source.id, {
        status: "skipped",
        finishedAt: this.now().toISOString(),
        stage: "candidate_list",
        skipped: 1,
        errors: 0,
      });
      this.deps.logger?.warn?.("gmail-intake-firewall Gmail notification skipped because source is already running", {
        sourceId: source.id,
      });
      return summary;
    }
    this.inFlightSources.add(source.id);
    const observedAt = this.now();
    const startedAt = observedAt.toISOString();
    let stage: PollStage = "client_create";
    this.pollDiagnostics.set(source.id, { status: "running", startedAt, stage });
    try {
      const cursor = this.deps.stateStore.getSourceCursor(source.id) ?? {};
      const startHistoryId = typeof cursor.historyId === "string" ? cursor.historyId : undefined;
      if (!startHistoryId) {
        this.deps.stateStore.setSourceCursor(source.id, {
          ...cursor,
          mode: "watch",
          historyId: options.historyId,
          lastNotificationAt: observedAt.toISOString(),
          notificationHistoryId: options.historyId,
        }, observedAt.toISOString());
        summary.skipped += 1;
        this.pollDiagnostics.set(source.id, {
          status: "skipped",
          startedAt,
          finishedAt: this.now().toISOString(),
          stage: "cursor_update",
          eventCount: 0,
          fetched: 0,
          processed: 0,
          skipped: summary.skipped,
          errors: 0,
        });
        return summary;
      }
      const client = await this.deps.gmailClientFactory(source);
      stage = "candidate_list";
      this.pollDiagnostics.set(source.id, { status: "running", startedAt, stage });
      const page = await this.listHistoryOrRepair(source, client, startHistoryId);
      const candidates = page.candidates;
      const batch = await this.processCandidateEvents(source, client, candidates, observedAt, "gmail_watch", {
        force: options.force ?? false,
        ...(typeof options.dryRun === "boolean" ? { dryRun: options.dryRun } : {}),
      });
      stage = batch.stage;
      summary.events += batch.events;
      summary.fetched += batch.fetched;
      summary.processed += batch.processed;
      summary.skipped += batch.skipped;
      summary.errors += batch.errors;
      stage = "cursor_update";
      const nextCursor: Record<string, unknown> = {
        ...cursor,
        mode: "watch",
        lastHistoryAt: observedAt.toISOString(),
        lastNotificationAt: observedAt.toISOString(),
        notificationHistoryId: options.historyId,
        candidateCount: candidates.length,
      };
      if (summary.errors === 0) {
        nextCursor.historyId = page.historyId ?? options.historyId;
      }
      this.deps.stateStore.setSourceCursor(source.id, nextCursor, observedAt.toISOString());
      this.pollDiagnostics.set(source.id, {
        status: summary.errors > 0 ? "completed_with_errors" : "succeeded",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        eventCount: summary.events,
        fetched: summary.fetched,
        processed: summary.processed,
        skipped: summary.skipped,
        errors: summary.errors,
        ...(batch.lastEventDiagnostic ? {
          stage: batch.lastEventDiagnostic.stage,
          error: batch.lastEventDiagnostic.error,
        } : {}),
      });
    } catch (error) {
      summary.errors += 1;
      const safeError = safeRuntimeError(error);
      this.pollDiagnostics.set(source.id, {
        status: "failed",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        eventCount: summary.events,
        fetched: summary.fetched,
        processed: summary.processed,
        skipped: summary.skipped,
        errors: summary.errors,
        error: safeError,
      });
      this.deps.logger?.error?.("gmail-intake-firewall Gmail notification processing failed", {
        sourceId: source.id,
        stage,
        error: safeError.message,
        ...(safeError.code !== undefined ? { code: safeError.code } : {}),
        ...(safeError.status !== undefined ? { status: safeError.status } : {}),
      });
    } finally {
      this.inFlightSources.delete(source.id);
    }
    return summary;
  }

  async setupWatch(options: WatchLifecycleOptions = {}): Promise<Record<string, unknown>> {
    return this.runWatchLifecycle("setup", options);
  }

  async renewWatch(options: WatchLifecycleOptions = {}): Promise<Record<string, unknown>> {
    return this.runWatchLifecycle("renew", options);
  }

  async repairWatch(options: WatchLifecycleOptions = {}): Promise<Record<string, unknown>> {
    return this.runWatchLifecycle("repair", options);
  }

  private async runWatchLifecycle(
    operation: "setup" | "renew" | "repair",
    options: WatchLifecycleOptions,
  ): Promise<Record<string, unknown>> {
    const sources = this.watchSources(options.sourceId);
    const results: Record<string, unknown>[] = [];
    for (const source of sources) {
      if (operation === "repair") {
        results.push(await this.repairWatchSource(source, Boolean(options.force)));
      } else {
        results.push(await this.setupOrRenewWatchSource(source, {
          force: Boolean(options.force),
          setupOnly: operation === "setup",
        }));
      }
    }
    return {
      operation,
      sources: sources.length,
      results,
    };
  }

  private watchSources(sourceId?: string): GmailSourceConfig[] {
    const sources = sourceId
      ? this.config.sources.filter((source) => source.id === sourceId)
      : this.config.sources.filter((source) => source.enabled && source.intakeMode === "watch");
    return sources.filter((source) => source.enabled && source.intakeMode === "watch");
  }

  private async runSource(source: GmailSourceConfig): Promise<PollingRunSummary> {
    const summary = this.emptySummary();
    summary.sources = 1;
    if (this.inFlightSources.has(source.id)) {
      summary.skipped += 1;
      this.pollDiagnostics.set(source.id, {
        status: "skipped",
        finishedAt: this.now().toISOString(),
        stage: "candidate_list",
        skipped: 1,
        errors: 0,
      });
      this.deps.logger?.warn?.("gmail-intake-firewall poll skipped because source is already running", {
        sourceId: source.id,
      });
      return summary;
    }
    this.inFlightSources.add(source.id);
    const observedAt = this.now();
    const startedAt = observedAt.toISOString();
    let stage: PollStage = "client_create";
    this.pollDiagnostics.set(source.id, { status: "running", startedAt, stage });
    try {
      const client = await this.deps.gmailClientFactory(source);
      stage = "candidate_list";
      this.pollDiagnostics.set(source.id, { status: "running", startedAt, stage });
      const candidates = await this.listSourceCandidates(source, client);
      const limitedCandidates = source.intakeMode === "history" || source.intakeMode === "watch"
        ? candidates
        : candidates.slice(0, source.polling.maxResults);
      const eventType: IntakeEvent["eventType"] = source.intakeMode === "history" || source.intakeMode === "watch" ? "gmail_history" : "poll_candidate";
      const batch = await this.processCandidateEvents(source, client, limitedCandidates, observedAt, eventType);
      stage = batch.stage;
      summary.events += batch.events;
      summary.fetched += batch.fetched;
      summary.processed += batch.processed;
      summary.skipped += batch.skipped;
      summary.errors += batch.errors;
      stage = "cursor_update";
      const existingCursor = this.deps.stateStore.getSourceCursor(source.id) ?? {};
      this.deps.stateStore.setSourceCursor(source.id, {
        ...existingCursor,
        mode: source.intakeMode ?? "poll",
        lastPolledAt: observedAt.toISOString(),
        candidateCount: limitedCandidates.length,
      }, observedAt.toISOString());
      this.pollDiagnostics.set(source.id, {
        status: summary.errors > 0 ? "completed_with_errors" : "succeeded",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        eventCount: summary.events,
        fetched: summary.fetched,
        processed: summary.processed,
        skipped: summary.skipped,
        errors: summary.errors,
        ...(batch.lastEventDiagnostic ? {
          stage: batch.lastEventDiagnostic.stage,
          error: batch.lastEventDiagnostic.error,
        } : {}),
      });
    } catch (error) {
      summary.errors += 1;
      const safeError = safeRuntimeError(error);
      this.pollDiagnostics.set(source.id, {
        status: "failed",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        eventCount: summary.events,
        fetched: summary.fetched,
        processed: summary.processed,
        skipped: summary.skipped,
        errors: summary.errors,
        error: safeError,
      });
      this.deps.logger?.error?.("gmail-intake-firewall poll source failed", {
        sourceId: source.id,
        stage,
        error: safeError.message,
        ...(safeError.code !== undefined ? { code: safeError.code } : {}),
        ...(safeError.status !== undefined ? { status: safeError.status } : {}),
      });
    } finally {
      this.inFlightSources.delete(source.id);
    }
    return summary;
  }

  private async processCandidateEvents(
    source: GmailSourceConfig,
    client: GmailClient,
    candidates: GmailCandidate[],
    observedAt: Date,
    eventType: IntakeEvent["eventType"],
    options: { force?: boolean; dryRun?: boolean } = {},
  ): Promise<ProcessCandidateEventsResult> {
    const summary: ProcessCandidateEventsResult = {
      events: 0,
      fetched: 0,
      processed: 0,
      skipped: 0,
      errors: 0,
      stage: "event_record",
    };
    const events = candidates.map((candidate) => ({
      ...candidateToIntakeEvent(source, candidate, observedAt),
      eventType,
    }));
    summary.events = events.length;
    for (const event of events) {
      summary.stage = "event_record";
      this.deps.stateStore.recordEvent(event);
      const result = await this.processEvent(client, event, options);
      if (result.diagnostic) {
        summary.lastEventDiagnostic = result.diagnostic;
        summary.stage = result.diagnostic.stage;
      }
      summary.fetched += result.fetched;
      summary.processed += result.processed;
      summary.skipped += result.skipped;
      summary.errors += result.errors;
    }
    return summary;
  }

  private async processEvent(
    client: GmailClient,
    event: IntakeEvent,
    options: { force?: boolean; dryRun?: boolean } = {},
  ): Promise<ProcessEventResult> {
    const summary: ProcessEventResult = { fetched: 0, processed: 0, skipped: 0, errors: 0 };
    const source = this.config.sources.find((candidate) => candidate.id === event.sourceId);
    if (!options.force && this.deps.stateStore.isProcessed(event.sourceId, event.messageId)) {
      summary.skipped += 1;
      return summary;
    }
    let stage: PollStage = "message_fetch";
    try {
      stage = "message_fetch";
      const message = await client.fetchMessage({
        id: event.messageId,
        threadId: event.threadId ?? "",
      });
      if (client.fetchThreadContext && message.threadId) {
        try {
          stage = "thread_context";
          const threadContext = await client.fetchThreadContext(message.threadId);
          if (threadContext) {
            message.threadContext = threadContext;
          }
        } catch (error) {
          const safeError = safeRuntimeError(error);
          this.deps.logger?.warn?.("gmail-intake-firewall thread context fetch failed", {
            sourceId: event.sourceId,
            messageId: event.messageId,
            threadId: message.threadId,
            stage: "thread_context",
            error: safeError.message,
          });
        }
      }
      summary.fetched += 1;
      stage = "classification";
      const processDeps: ProcessMessageDeps = {
        securityClassifier: this.deps.securityClassifier ?? createUnavailableSecurityClassifier(),
        routerClassifier: this.deps.routerClassifier ?? createNoopRouterClassifier(),
        routingPreferences: this.deps.stateStore.listRoutingPreferences(event.sourceId),
      };
      if (this.deps.now) {
        processDeps.now = this.deps.now;
      }
      const result = await processMessage(message, this.config, createEmptyState(), processDeps);
      if (result.decision) {
        this.deps.stateStore.recordDecisionPlan(result.decision);
        stage = "action_execute";
        const actionResults = await executePlannedActions(result.decision.actions, {
          dryRun: options.dryRun ?? this.config.dryRun,
          actions: this.config.actions,
          source,
        }, {
          ...(this.deps.actionDeps ?? {}),
          gmail: this.deps.actionDeps?.gmail ?? client,
        });
        const attemptedAt = this.now().toISOString();
        for (const actionResult of actionResults) {
          this.deps.stateStore.recordActionStatus(result.decision, actionResult, attemptedAt);
        }
        if (!requiredActionsSucceeded(actionResults)) {
          throw new Error(buildRequiredActionFailureMessage(actionResults));
        }
        this.deps.stateStore.markProcessed(result.decision.sourceId, result.decision.messageId, result.decision.processedAt);
        summary.processed += 1;
      } else {
        summary.skipped += 1;
      }
    } catch (error) {
      summary.errors += 1;
      const safeError = safeRuntimeError(error);
      summary.diagnostic = { stage, error: safeError };
      this.deps.logger?.error?.("gmail-intake-firewall process event failed", {
        sourceId: event.sourceId,
        messageId: event.messageId,
        stage,
        error: safeError.message,
        ...(safeError.code !== undefined ? { code: safeError.code } : {}),
        ...(safeError.status !== undefined ? { status: safeError.status } : {}),
      });
    }
    return summary;
  }

  private enabledSources(): GmailSourceConfig[] {
    return this.config.sources.filter((source) => source.enabled);
  }

  private findNotificationSource(options: GmailNotificationOptions): NotificationSourceResolution {
    if (options.sourceId) {
      const source = this.config.sources.find((candidate) => candidate.id === options.sourceId);
      if (!source) {
        return { error: `Unknown source: ${options.sourceId}` };
      }
      if (options.accountEmail && source.accountEmail.toLowerCase() !== options.accountEmail.toLowerCase()) {
        return {
          source,
          error: `Gmail notification accountEmail ${options.accountEmail} does not match source ${source.id}`,
        };
      }
      if (source.intakeMode !== "watch" || !source.watchTopicName) {
        return {
          source,
          error: `Gmail notification source must use watch intakeMode: ${source.id}`,
        };
      }
      return { source };
    }
    if (options.accountEmail) {
      const accountEmail = options.accountEmail.toLowerCase();
      const matches = this.config.sources.filter((source) => source.accountEmail.toLowerCase() === accountEmail);
      if (matches.length === 0) {
        return { error: `No source configured for Gmail account: ${options.accountEmail}` };
      }
      if (matches.length > 1) {
        return { error: `Multiple sources configured for Gmail account: ${options.accountEmail}` };
      }
      const source = matches[0]!;
      if (source.intakeMode !== "watch" || !source.watchTopicName) {
        return {
          source,
          error: `Gmail notification source must use watch intakeMode: ${source.id}`,
        };
      }
      return { source };
    }
    return { error: "Gmail notification requires sourceId or accountEmail" };
  }

  private async listSourceCandidates(source: GmailSourceConfig, client: GmailClient): Promise<GmailCandidate[]> {
    if (source.intakeMode === "watch" && source.watchTopicName) {
      const cursor = this.deps.stateStore.getSourceCursor(source.id);
      const expiresAt = typeof cursor?.watchExpiresAt === "string" ? Date.parse(cursor.watchExpiresAt) : 0;
      const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
      const needsRenewal = !historyId || expiresAt <= this.now().getTime() + this.config.watch.renewBeforeMs;
      if (needsRenewal && this.config.watch.autoSetup) {
        const renewal = await this.setupOrRenewWatchSource(source, { client });
        const page = renewal.historyPage;
        if (page?.candidates) {
          return page.candidates;
        }
        if (!historyId) {
          return [];
        }
      }
    }
    if ((source.intakeMode === "history" || source.intakeMode === "watch") && client.listHistory) {
      const cursor = this.deps.stateStore.getSourceCursor(source.id);
      const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
      if (historyId) {
        const page = await this.listHistoryOrRepair(source, client, historyId);
        if (page.historyId) {
          this.deps.stateStore.setSourceCursor(source.id, {
            ...(cursor ?? {}),
            mode: source.intakeMode,
            historyId: page.historyId,
            lastHistoryAt: this.now().toISOString(),
          });
        }
        return page.candidates;
      }
    }
    return client.listCandidates(buildCandidateQuery(source));
  }

  private async listHistoryOrRepair(source: GmailSourceConfig, client: GmailClient, historyId: string): Promise<GmailHistoryPage> {
    try {
      return await client.listHistory!(historyId);
    } catch (error) {
      if (!isStaleHistoryError(error)) {
        throw error;
      }
      this.deps.logger?.warn?.("gmail-intake-firewall stale Gmail history cursor; using bounded repair poll", {
        sourceId: source.id,
        error: error instanceof Error ? error.message : String(error),
      });
      return {
        candidates: await client.listCandidates(buildHistoryRepairQuery(source)),
      };
    }
  }

  private async setupOrRenewWatchSource(
    source: GmailSourceConfig,
    options: { force?: boolean; setupOnly?: boolean; client?: GmailClient } = {},
  ): Promise<Record<string, unknown> & { historyPage?: GmailHistoryPage }> {
    if (!source.watchTopicName) {
      return { sourceId: source.id, ok: false, error: "watchTopicName is required" };
    }
    if (this.inFlightSources.has(source.id) && !options.client) {
      return { sourceId: source.id, ok: false, skipped: true, error: "source is already running" };
    }
    const releaseLock = !options.client;
    if (releaseLock) {
      this.inFlightSources.add(source.id);
    }
    const observedAt = this.now();
    const startedAt = observedAt.toISOString();
    let stage: PollStage = "client_create";
    try {
      const cursor = this.deps.stateStore.getSourceCursor(source.id) ?? {};
      const historyId = typeof cursor.historyId === "string" ? cursor.historyId : undefined;
      const expiresAt = typeof cursor.watchExpiresAt === "string" ? Date.parse(cursor.watchExpiresAt) : 0;
      const needsRenewal = !historyId || expiresAt <= observedAt.getTime() + this.config.watch.renewBeforeMs;
      if (!options.force && !needsRenewal && !options.setupOnly) {
        return { sourceId: source.id, ok: true, skipped: true, reason: "watch_not_due" };
      }
      if (!options.force && historyId && options.setupOnly) {
        return { sourceId: source.id, ok: true, skipped: true, reason: "watch_cursor_exists" };
      }
      const client = options.client ?? await this.deps.gmailClientFactory(source);
      let historyPage: GmailHistoryPage | undefined;
      if (historyId && client.listHistory) {
        stage = "candidate_list";
        historyPage = await this.listHistoryOrRepair(source, client, historyId);
      }
      stage = "cursor_update";
      const registration = await client.setupWatch?.(source.watchTopicName, this.config.watch.labelIds, this.config.watch.labelFilterBehavior);
      if (!registration?.historyId) {
        const nextCursor: Record<string, unknown> = {
          ...cursor,
          mode: "watch",
          ...(historyPage?.historyId ? { historyId: historyPage.historyId, lastHistoryAt: observedAt.toISOString() } : {}),
          lastWatchAttemptAt: observedAt.toISOString(),
        };
        this.deps.stateStore.setSourceCursor(source.id, nextCursor, observedAt.toISOString());
        return {
          sourceId: source.id,
          ok: false,
          stage,
          error: "Gmail watch registration did not return historyId",
          ...(historyPage ? { historyPage } : {}),
        };
      }
      const nextCursor: Record<string, unknown> = {
        ...cursor,
        mode: "watch",
        historyId: registration.historyId,
        lastWatchAttemptAt: observedAt.toISOString(),
        lastWatchRenewalAt: observedAt.toISOString(),
        watchLabelIds: this.config.watch.labelIds,
        watchLabelFilterBehavior: this.config.watch.labelFilterBehavior,
      };
      if (registration.expiration) {
        nextCursor.watchExpiresAt = registration.expiration;
      }
      this.deps.stateStore.setSourceCursor(source.id, nextCursor, observedAt.toISOString());
      this.pollDiagnostics.set(source.id, {
        status: "succeeded",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        eventCount: historyPage?.candidates.length ?? 0,
        fetched: 0,
        processed: 0,
        skipped: 0,
        errors: 0,
      });
      return {
        sourceId: source.id,
        ok: true,
        stage,
        historyId: registration.historyId,
        ...(registration.expiration ? { watchExpiresAt: registration.expiration } : {}),
        drainedCandidatesBeforeRenewal: historyPage?.candidates.length ?? 0,
        ...(historyPage ? { historyPage } : {}),
      };
    } catch (error) {
      const safeError = safeRuntimeError(error);
      this.pollDiagnostics.set(source.id, {
        status: "failed",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        errors: 1,
        error: safeError,
      });
      this.deps.logger?.error?.("gmail-intake-firewall watch lifecycle failed", {
        sourceId: source.id,
        stage,
        error: safeError.message,
      });
      return { sourceId: source.id, ok: false, stage, error: safeError };
    } finally {
      if (releaseLock) {
        this.inFlightSources.delete(source.id);
      }
    }
  }

  private async repairWatchSource(source: GmailSourceConfig, force: boolean): Promise<Record<string, unknown>> {
    if (this.inFlightSources.has(source.id)) {
      return { sourceId: source.id, ok: false, skipped: true, error: "source is already running" };
    }
    this.inFlightSources.add(source.id);
    const observedAt = this.now();
    const startedAt = observedAt.toISOString();
    let stage: PollStage = "client_create";
    try {
      const cursor = this.deps.stateStore.getSourceCursor(source.id) ?? {};
      const historyId = typeof cursor.historyId === "string" ? cursor.historyId : undefined;
      if (!historyId) {
        return { sourceId: source.id, ok: false, skipped: true, error: "history cursor is missing" };
      }
      if (!force && !watchRepairDue(cursor, this.config.watch.repairOnNoNotificationMs, observedAt)) {
        return { sourceId: source.id, ok: true, skipped: true, reason: "repair_not_due" };
      }
      const client = await this.deps.gmailClientFactory(source);
      stage = "candidate_list";
      const page = await this.listHistoryOrRepair(source, client, historyId);
      const batch = await this.processCandidateEvents(source, client, page.candidates, observedAt, "gmail_history");
      stage = "cursor_update";
      const nextCursor: Record<string, unknown> = {
        ...cursor,
        mode: "watch",
        lastRepairAt: observedAt.toISOString(),
        candidateCount: page.candidates.length,
      };
      if (batch.errors === 0) {
        nextCursor.historyId = page.historyId ?? historyId;
        nextCursor.lastHistoryAt = observedAt.toISOString();
      }
      this.deps.stateStore.setSourceCursor(source.id, nextCursor, observedAt.toISOString());
      this.pollDiagnostics.set(source.id, {
        status: batch.errors > 0 ? "completed_with_errors" : "succeeded",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        eventCount: batch.events,
        fetched: batch.fetched,
        processed: batch.processed,
        skipped: batch.skipped,
        errors: batch.errors,
        ...(batch.lastEventDiagnostic ? {
          stage: batch.lastEventDiagnostic.stage,
          error: batch.lastEventDiagnostic.error,
        } : {}),
      });
      return {
        sourceId: source.id,
        ok: batch.errors === 0,
        ...batch,
      };
    } catch (error) {
      const safeError = safeRuntimeError(error);
      this.pollDiagnostics.set(source.id, {
        status: "failed",
        startedAt,
        finishedAt: this.now().toISOString(),
        stage,
        errors: 1,
        error: safeError,
      });
      this.deps.logger?.error?.("gmail-intake-firewall watch repair failed", {
        sourceId: source.id,
        stage,
        error: safeError.message,
      });
      return { sourceId: source.id, ok: false, stage, error: safeError };
    } finally {
      this.inFlightSources.delete(source.id);
    }
  }

  private emptySummary(): PollingRunSummary {
    return {
      sources: 0,
      events: 0,
      fetched: 0,
      processed: 0,
      skipped: 0,
      errors: 0,
    };
  }

  private now(): Date {
    return (this.deps.now ?? (() => new Date()))();
  }
}

function buildSourceReadiness(source: GmailSourceConfig, cursor: Record<string, unknown> | undefined, watchConfig: PluginConfig["watch"], now: Date): Record<string, unknown> {
  const mode = source.intakeMode ?? "poll";
  const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
  const watchExpiresAt = typeof cursor?.watchExpiresAt === "string" ? cursor.watchExpiresAt : undefined;
  const watchExpiresMs = watchExpiresAt ? Date.parse(watchExpiresAt) : Number.NaN;
  const watchActive = Number.isFinite(watchExpiresMs) && watchExpiresMs > now.getTime();
  const watchNeedsRenewal = mode === "watch" && (!watchActive || watchExpiresMs <= now.getTime() + watchConfig.renewBeforeMs);
  const lastNotificationAt = typeof cursor?.lastNotificationAt === "string" ? cursor.lastNotificationAt : undefined;
  const lastHistoryAt = typeof cursor?.lastHistoryAt === "string" ? cursor.lastHistoryAt : undefined;
  const lastWatchRenewalAt = typeof cursor?.lastWatchRenewalAt === "string" ? cursor.lastWatchRenewalAt : undefined;
  const lastRepairAt = typeof cursor?.lastRepairAt === "string" ? cursor.lastRepairAt : undefined;
  const missedNotificationRepairDue = mode === "watch" && Boolean(historyId) && watchRepairDue(cursor, watchConfig.repairOnNoNotificationMs, now);
  const configuredModifyScope = source.gmailActions.hasModifyScope;
  const credentialScopes = Array.isArray(cursor?.credentialScopes)
    ? cursor.credentialScopes.filter((scope): scope is string => typeof scope === "string")
    : undefined;
  const credentialModifyScope = gmailScopesAllowModify(credentialScopes);
  const suggestedOperations: string[] = [];
  if (mode === "watch") {
    if (!source.watchTopicName) {
      suggestedOperations.push("configure_watch_topic");
    }
    if (!historyId) {
      suggestedOperations.push("setupWatch");
    }
    if (watchNeedsRenewal) {
      suggestedOperations.push("renewWatch");
    }
    if (missedNotificationRepairDue) {
      suggestedOperations.push("repairWatch");
    }
  }
  return {
    mode,
    authConfigured: Boolean(source.authRef ?? source.credentialRef),
    configuredModifyScope,
    ...(credentialModifyScope !== undefined ? { credentialModifyScope } : {}),
    canModifyGmail: configuredModifyScope && credentialModifyScope !== false,
    cursorPresent: Boolean(cursor),
    historyCursorPresent: Boolean(historyId),
    ...(historyId ? { historyId } : {}),
    ...(watchExpiresAt ? { watchExpiresAt } : {}),
    ...(mode === "watch" ? {
      watchTopicConfigured: Boolean(source.watchTopicName),
      watchActive,
      watchNeedsRenewal,
      watchAutoSetup: watchConfig.autoSetup,
      watchLabelIds: watchConfig.labelIds,
      watchLabelFilterBehavior: watchConfig.labelFilterBehavior,
      missedNotificationRepairDue,
      ...(lastNotificationAt ? { lastNotificationAt } : {}),
      ...(lastHistoryAt ? { lastHistoryAt } : {}),
      ...(lastWatchRenewalAt ? { lastWatchRenewalAt } : {}),
      ...(lastRepairAt ? { lastRepairAt } : {}),
      suggestedOperations,
    } : {}),
  };
}

function watchRepairDue(cursor: Record<string, unknown> | undefined, repairOnNoNotificationMs: number, now: Date): boolean {
  if (!cursor) {
    return false;
  }
  const lastNotificationAt = typeof cursor.lastNotificationAt === "string" ? Date.parse(cursor.lastNotificationAt) : Number.NaN;
  const lastHistoryAt = typeof cursor.lastHistoryAt === "string" ? Date.parse(cursor.lastHistoryAt) : Number.NaN;
  const lastRepairAt = typeof cursor.lastRepairAt === "string" ? Date.parse(cursor.lastRepairAt) : Number.NaN;
  const newestObserved = Math.max(
    Number.isFinite(lastNotificationAt) ? lastNotificationAt : 0,
    Number.isFinite(lastHistoryAt) ? lastHistoryAt : 0,
    Number.isFinite(lastRepairAt) ? lastRepairAt : 0,
  );
  return newestObserved === 0 || newestObserved <= now.getTime() - repairOnNoNotificationMs;
}

function safeQuarantineItem(
  decision: Record<string, unknown>,
  options: {
    feedback?: Array<Record<string, unknown>>;
    actionStatuses?: Array<Record<string, unknown>>;
    actionAttempts?: Array<Record<string, unknown>>;
    compact?: boolean;
  } = {},
): Record<string, unknown> {
  const alertPayload = suspiciousPayloadFromDecision(decision);
  const item: Record<string, unknown> = {
    sourceId: decision.sourceId,
    accountEmail: decision.accountEmail,
    messageId: decision.messageId,
    threadId: decision.threadId,
    processedAt: decision.processedAt,
    dryRun: decision.dryRun,
    security: decision.security,
    sender: alertPayload?.sender,
    replyTo: alertPayload?.replyTo,
    recipients: alertPayload?.recipients,
    cc: alertPayload?.cc,
    subject: alertPayload?.subject,
    date: alertPayload?.date,
    gmailLink: alertPayload?.gmailLink,
    labels: alertPayload?.labels,
    authHeaders: alertPayload?.authHeaders,
    linkDomains: alertPayload?.linkDomains,
    links: alertPayload?.links,
    linkRiskHints: alertPayload?.linkRiskHints,
    attachments: alertPayload?.attachments,
    attachmentRiskHints: alertPayload?.attachmentRiskHints,
    artifactNotes: alertPayload?.artifactNotes,
    artifactAnalysis: decision.artifactAnalysis,
    riskReasons: alertPayload?.riskReasons,
    suspiciousSignals: alertPayload?.suspiciousSignals,
    sanitizedSummary: alertPayload?.sanitizedSummary ?? (decision.security as Record<string, unknown> | undefined)?.safeSummary,
    feedback: options.feedback ?? [],
  };
  if (!options.compact) {
    item.actions = decision.actions;
    item.latestActionStatuses = options.actionStatuses ?? [];
    item.actionAttempts = options.actionAttempts ?? [];
  }
  return removeUndefined(item);
}

function suspiciousPayloadFromDecision(decision: Record<string, unknown>): Record<string, unknown> | undefined {
  const actions = Array.isArray(decision.actions) ? decision.actions : [];
  for (const action of actions) {
    if (!action || typeof action !== "object") {
      continue;
    }
    const payload = (action as Record<string, unknown>).payload;
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      return payload as Record<string, unknown>;
    }
  }
  return undefined;
}

function senderFromDecision(decision: Record<string, unknown> | undefined): string | undefined {
  if (!decision) {
    return undefined;
  }
  const payload = suspiciousPayloadFromDecision(decision);
  return typeof payload?.sender === "string" ? payload.sender : undefined;
}

function normalizeEmailAddress(value: string | undefined): string | undefined {
  const normalized = value?.trim().toLowerCase();
  return normalized || undefined;
}

function domainFromSender(sender: string | undefined): string | undefined {
  return sender?.split("@").pop();
}

function normalizeDomain(value: string | undefined): string | undefined {
  const normalized = value?.trim().toLowerCase();
  return normalized || undefined;
}

function subjectFromDecision(decision: Record<string, unknown>): string | undefined {
  const payload = suspiciousPayloadFromDecision(decision);
  return typeof payload?.subject === "string" ? payload.subject : undefined;
}

function removeUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

function aggregateItemDue(queuedAt: string, cadence: string | undefined, now: Date, timezone: string): boolean {
  const queued = Date.parse(queuedAt);
  if (!Number.isFinite(queued)) {
    return true;
  }
  if (now.getTime() < queued) {
    return false;
  }
  const elapsed = now.getTime() - queued;
  if (cadence === "hourly") {
    return elapsed >= 60 * 60 * 1000;
  }
  if (cadence === "weekly") {
    return zonedWeekKey(new Date(queued), timezone) !== zonedWeekKey(now, timezone);
  }
  if (cadence === "daily" || !cadence) {
    return zonedDateKey(new Date(queued), timezone) !== zonedDateKey(now, timezone);
  }
  return elapsed >= 24 * 60 * 60 * 1000;
}

function zonedDateKey(date: Date, timezone: string): string {
  const parts = zonedDateParts(date, timezone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function zonedWeekKey(date: Date, timezone: string): string {
  const parts = zonedDateParts(date, timezone);
  return `${parts.year}-W${weekNumber(parts.year, parts.month, parts.day)}`;
}

function zonedDateParts(date: Date, timezone: string): { year: number; month: number; day: number } {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: validTimezone(timezone),
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });
  const values = Object.fromEntries(formatter.formatToParts(date).map((part) => [part.type, part.value]));
  return {
    year: Number(values.year),
    month: Number(values.month),
    day: Number(values.day),
  };
}

function validTimezone(timezone: string): string {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: timezone });
    return timezone;
  } catch {
    return "UTC";
  }
}

function weekNumber(year: number, month: number, day: number): number {
  const date = new Date(Date.UTC(year, month - 1, day));
  const start = new Date(Date.UTC(year, 0, 1));
  return Math.floor((date.getTime() - start.getTime()) / (7 * 24 * 60 * 60 * 1000));
}

function buildHistoryRepairQuery(source: GmailSourceConfig): string | undefined {
  const baseQuery = buildCandidateQuery(source);
  if (!source.historyLookback) {
    return baseQuery;
  }
  return [baseQuery, `newer_than:${source.historyLookback}`].filter(Boolean).join(" ");
}

function isStaleHistoryError(error: unknown): boolean {
  const raw = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const code = raw.code ?? raw.status;
  if (code === 404 || code === "404") {
    return true;
  }
  const message = error instanceof Error ? error.message : String(error);
  return /history/i.test(message) && /(stale|expired|too old|not found|invalid)/i.test(message);
}

function safeRuntimeError(error: unknown): SafeRuntimeError {
  if (error instanceof Error) {
    const raw = error as Error & { code?: unknown; status?: unknown; response?: { status?: unknown } };
    return {
      name: error.name,
      message: redactSecretLikeValues(error.message),
      ...(typeof raw.code === "string" || typeof raw.code === "number" ? { code: raw.code } : {}),
      ...(typeof raw.status === "string" || typeof raw.status === "number"
        ? { status: raw.status }
        : typeof raw.response?.status === "string" || typeof raw.response?.status === "number"
          ? { status: raw.response.status }
          : {}),
    };
  }
  return { message: redactSecretLikeValues(String(error)) };
}

function redactSecretLikeValues(value: string): string {
  return value
    .replace(/(["'])(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|authorization)\1\s*:\s*(["'])[^"']*\3/gi, "$1$2$1: $3[redacted]$3")
    .replace(/(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|authorization)\s*(=|:)\s*[^,\s)}]+/gi, "$1$2 [redacted]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]");
}

function buildRequiredActionFailureMessage(results: ActionExecutionStatus[]): string {
  const failed = results.filter((result) => result.required && result.status === "failed");
  if (failed.length === 0) {
    return "One or more required actions failed; message left pending for retry";
  }
  const details = failed.map((result) => {
    const actionType = result.action.type;
    const error = result.error ? `: ${redactSecretLikeValues(result.error)}` : "";
    return `${actionType}[${result.actionIndex}]${error}`;
  });
  return `Required action failed: ${details.join(", ")}; message left pending for retry`;
}

function groupAggregateItems(items: import("./types.js").AggregateItem[]): Array<{ key: string; wakeTarget?: string; items: import("./types.js").AggregateItem[] }> {
  const groups = new Map<string, { key: string; wakeTarget?: string; items: import("./types.js").AggregateItem[] }>();
  for (const item of items) {
    const key = [item.wakeTarget ?? "", item.cadence ?? "", item.sourceId].join("|");
    const existing = groups.get(key);
    if (existing) {
      existing.items.push(item);
    } else {
      groups.set(key, { key, ...(item.wakeTarget ? { wakeTarget: item.wakeTarget } : {}), items: [item] });
    }
  }
  return Array.from(groups.values());
}

export function createUnavailableGmailClientFactory(): GmailClientFactory {
  return () => {
    throw new Error("Gmail client factory is not configured");
  };
}
