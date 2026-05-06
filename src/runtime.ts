import { buildDigestWake } from "./aggregate.js";
import { executePlannedActions, requiredActionsSucceeded, type ActionExecutorDeps } from "./actions.js";
import { buildCandidateQuery, candidateToIntakeEvent, type GmailCandidate, type GmailClient, type GmailHistoryPage } from "./gmail.js";
import { gmailScopesAllowModify } from "./googleAuth.js";
import { processMessage, type ProcessMessageDeps } from "./engine.js";
import { createNoopRouterClassifier } from "./routerClassifier.js";
import { createUnavailableSecurityClassifier } from "./securityClassifier.js";
import { createEmptyState, type FirewallState, type SqliteStateStore } from "./state.js";
import type { GmailSourceConfig, IntakeEvent, PluginConfig } from "./types.js";

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

type TimerHandle = ReturnType<typeof setInterval>;

export class GmailIntakePollingRuntime {
  private readonly timers = new Map<string, TimerHandle>();
  private readonly inFlightSources = new Set<string>();
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
      this.deps.logger?.error?.("gmail-intake-firewall backfill list failed", {
        sourceId: source.id,
        error: error instanceof Error ? error.message : String(error),
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
        const wakeExecutor = this.deps.actionDeps?.wake;
        if (!wakeExecutor && !this.config.dryRun) {
          throw new Error("Detached wake executor is not configured");
        }
        if (this.config.dryRun) {
          this.deps.logger?.info?.("gmail-intake-firewall dry-run aggregate wake", {
            group: group.key,
            itemCount: group.items.length,
            wake,
          });
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
          enabled: source.gmailActions.enabled,
          applyLabels: source.gmailActions.applyLabels,
          archive: source.gmailActions.archive,
          hasModifyScope: source.gmailActions.hasModifyScope,
        },
        readiness: buildSourceReadiness(source, cursor, this.now()),
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
      this.deps.logger?.error?.("gmail-intake-firewall replay client creation failed", {
        sourceId: source.id,
        messageId: options.messageId,
        error: error instanceof Error ? error.message : String(error),
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

  private async runSource(source: GmailSourceConfig): Promise<PollingRunSummary> {
    const summary = this.emptySummary();
    summary.sources = 1;
    if (this.inFlightSources.has(source.id)) {
      summary.skipped += 1;
      this.deps.logger?.warn?.("gmail-intake-firewall poll skipped because source is already running", {
        sourceId: source.id,
      });
      return summary;
    }
    this.inFlightSources.add(source.id);
    const observedAt = this.now();
    try {
      const client = await this.deps.gmailClientFactory(source);
      const candidates = await this.listSourceCandidates(source, client);
      const limitedCandidates = candidates.slice(0, source.polling.maxResults);
      const eventType: IntakeEvent["eventType"] = source.intakeMode === "history" || source.intakeMode === "watch" ? "gmail_history" : "poll_candidate";
      const events = limitedCandidates.map((candidate) => ({
        ...candidateToIntakeEvent(source, candidate, observedAt),
        eventType,
      }));
      summary.events = events.length;
      for (const event of events) {
        this.deps.stateStore.recordEvent(event);
        const result = await this.processEvent(client, event);
        summary.fetched += result.fetched;
        summary.processed += result.processed;
        summary.skipped += result.skipped;
        summary.errors += result.errors;
      }
      const existingCursor = this.deps.stateStore.getSourceCursor(source.id) ?? {};
      this.deps.stateStore.setSourceCursor(source.id, {
        ...existingCursor,
        mode: source.intakeMode ?? "poll",
        lastPolledAt: observedAt.toISOString(),
        candidateCount: limitedCandidates.length,
      }, observedAt.toISOString());
    } catch (error) {
      summary.errors += 1;
      this.deps.logger?.error?.("gmail-intake-firewall poll source failed", {
        sourceId: source.id,
        error: error instanceof Error ? error.message : String(error),
      });
    } finally {
      this.inFlightSources.delete(source.id);
    }
    return summary;
  }

  private async processEvent(
    client: GmailClient,
    event: IntakeEvent,
    options: { force?: boolean; dryRun?: boolean } = {},
  ): Promise<Pick<PollingRunSummary, "fetched" | "processed" | "skipped" | "errors">> {
    const summary = { fetched: 0, processed: 0, skipped: 0, errors: 0 };
    if (!options.force && this.deps.stateStore.isProcessed(event.sourceId, event.messageId)) {
      summary.skipped += 1;
      return summary;
    }
    try {
      const message = await client.fetchMessage({
        id: event.messageId,
        threadId: event.threadId ?? "",
      });
      if (client.fetchThreadContext && message.threadId) {
        try {
          const threadContext = await client.fetchThreadContext(message.threadId);
          if (threadContext) {
            message.threadContext = threadContext;
          }
        } catch (error) {
          this.deps.logger?.warn?.("gmail-intake-firewall thread context fetch failed", {
            sourceId: event.sourceId,
            messageId: event.messageId,
            threadId: message.threadId,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
      summary.fetched += 1;
      const processDeps: ProcessMessageDeps = {
        securityClassifier: this.deps.securityClassifier ?? createUnavailableSecurityClassifier(),
        routerClassifier: this.deps.routerClassifier ?? createNoopRouterClassifier(),
      };
      if (this.deps.now) {
        processDeps.now = this.deps.now;
      }
      const result = await processMessage(message, this.config, createEmptyState(), processDeps);
      if (result.decision) {
        this.deps.stateStore.recordDecisionPlan(result.decision);
        const actionResults = await executePlannedActions(result.decision.actions, options.dryRun ?? this.config.dryRun, {
          ...(this.deps.actionDeps ?? {}),
          gmail: this.deps.actionDeps?.gmail ?? client,
        });
        const attemptedAt = this.now().toISOString();
        for (const actionResult of actionResults) {
          this.deps.stateStore.recordActionStatus(result.decision, actionResult, attemptedAt);
        }
        if (!requiredActionsSucceeded(actionResults)) {
          throw new Error("One or more required actions failed; message left pending for retry");
        }
        this.deps.stateStore.markProcessed(result.decision.sourceId, result.decision.messageId, result.decision.processedAt);
        summary.processed += 1;
      } else {
        summary.skipped += 1;
      }
    } catch (error) {
      summary.errors += 1;
      this.deps.logger?.error?.("gmail-intake-firewall process event failed", {
        sourceId: event.sourceId,
        messageId: event.messageId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    return summary;
  }

  private enabledSources(): GmailSourceConfig[] {
    return this.config.sources.filter((source) => source.enabled);
  }

  private async listSourceCandidates(source: GmailSourceConfig, client: GmailClient): Promise<GmailCandidate[]> {
    if (source.intakeMode === "watch" && source.watchTopicName) {
      const cursor = this.deps.stateStore.getSourceCursor(source.id);
      const expiresAt = typeof cursor?.watchExpiresAt === "string" ? Date.parse(cursor.watchExpiresAt) : 0;
      const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
      const needsRenewal = !historyId || expiresAt <= this.now().getTime() + 3600000;
      if (needsRenewal) {
        let page: GmailHistoryPage | undefined;
        if (historyId && client.listHistory) {
          page = await this.listHistoryOrRepair(source, client, historyId);
        }
        const registration = await client.setupWatch?.(source.watchTopicName, ["INBOX"]);
        if (registration?.historyId) {
          const nextCursor: Record<string, unknown> = {
            ...(cursor ?? {}),
            mode: "watch",
            historyId: registration.historyId,
          };
          if (registration.expiration) {
            nextCursor.watchExpiresAt = registration.expiration;
          }
          this.deps.stateStore.setSourceCursor(source.id, {
            ...nextCursor,
          });
          return page?.candidates ?? [];
        }
        if (page?.historyId) {
          this.deps.stateStore.setSourceCursor(source.id, {
            ...(cursor ?? {}),
            mode: "watch",
            historyId: page.historyId,
            lastHistoryAt: this.now().toISOString(),
          });
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

function buildSourceReadiness(source: GmailSourceConfig, cursor: Record<string, unknown> | undefined, now: Date): Record<string, unknown> {
  const mode = source.intakeMode ?? "poll";
  const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
  const watchExpiresAt = typeof cursor?.watchExpiresAt === "string" ? cursor.watchExpiresAt : undefined;
  const watchExpiresMs = watchExpiresAt ? Date.parse(watchExpiresAt) : Number.NaN;
  const watchActive = Number.isFinite(watchExpiresMs) && watchExpiresMs > now.getTime();
  const watchNeedsRenewal = mode === "watch" && (!watchActive || watchExpiresMs <= now.getTime() + 3600000);
  const configuredModifyScope = source.gmailActions.enabled && source.gmailActions.hasModifyScope;
  const credentialScopes = Array.isArray(cursor?.credentialScopes)
    ? cursor.credentialScopes.filter((scope): scope is string => typeof scope === "string")
    : undefined;
  const credentialModifyScope = gmailScopesAllowModify(credentialScopes);
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
    } : {}),
  };
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
