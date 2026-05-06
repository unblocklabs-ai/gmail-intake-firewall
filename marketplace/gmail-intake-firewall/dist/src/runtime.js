import { buildDigestWake } from "./aggregate.js";
import { executePlannedActions, requiredActionsSucceeded } from "./actions.js";
import { buildCandidateQuery, candidateToIntakeEvent } from "./gmail.js";
import { gmailScopesAllowModify } from "./googleAuth.js";
import { processMessage } from "./engine.js";
import { createNoopRouterClassifier } from "./routerClassifier.js";
import { createUnavailableSecurityClassifier } from "./securityClassifier.js";
import { createEmptyState } from "./state.js";
export class GmailIntakePollingRuntime {
    config;
    deps;
    timers = new Map();
    inFlightSources = new Set();
    pollDiagnostics = new Map();
    running = false;
    constructor(config, deps) {
        this.config = config;
        this.deps = deps;
    }
    start() {
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
    stop() {
        const clearTimer = this.deps.clearInterval ?? clearInterval;
        for (const timer of this.timers.values()) {
            clearTimer(timer);
        }
        this.timers.clear();
        this.running = false;
    }
    async runOnce() {
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
    async runBackfill(options) {
        const source = this.config.sources.find((candidate) => candidate.id === options.sourceId);
        const summary = this.emptySummary();
        if (!source || !source.enabled || !this.config.enabled) {
            summary.skipped += 1;
            return summary;
        }
        summary.sources = 1;
        let client;
        let candidates;
        try {
            client = await this.deps.gmailClientFactory(source);
            candidates = await client.listCandidates(options.query ?? buildCandidateQuery(source));
        }
        catch (error) {
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
            const processOptions = { force: options.force ?? false };
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
    async drainAggregates(now = this.now()) {
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
                }
                else {
                    await wakeExecutor.startDetachedAgentTurn(wake);
                    this.deps.stateStore.markAggregateDelivered(group.items, now.toISOString());
                }
                summary.processed += group.items.length;
            }
            catch (error) {
                summary.errors += 1;
                this.deps.logger?.error?.("gmail-intake-firewall aggregate drain failed", {
                    group: group.key,
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        }
        return summary;
    }
    probe() {
        return {
            running: this.running,
            configuredSources: this.config.sources.length,
            enabledSources: this.enabledSources().length,
            sqlitePath: this.config.sqlitePath,
        };
    }
    status() {
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
                lastPoll: this.pollDiagnostics.get(source.id),
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
    inspectMessage(sourceId, messageId) {
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
    listQuarantine(limit = 25) {
        return {
            items: this.deps.stateStore.listQuarantine(limit).map((decision) => safeQuarantineItem(decision, {
                feedback: this.deps.stateStore.listFeedbackForMessage(String(decision.sourceId), String(decision.messageId), 10),
                compact: true,
            })),
        };
    }
    getQuarantineItem(sourceId, messageId) {
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
    recordReviewFeedback(input) {
        const decision = this.deps.stateStore.listDecisions(input.sourceId, input.messageId, 1)[0];
        const event = {
            createdAt: this.now().toISOString(),
            sourceId: input.sourceId,
            messageId: input.messageId,
            threadId: typeof decision?.threadId === "string" ? decision.threadId : undefined,
            feedbackType: input.feedbackType,
            actor: input.actor,
            reason: input.reason,
            sender: input.sender ?? senderFromDecision(decision),
        };
        this.deps.stateStore.recordFeedback(event);
        return { recorded: true, feedback: event };
    }
    async wakeReviewedMessage(input) {
        const decision = this.deps.stateStore.listDecisions(input.sourceId, input.messageId, 1)[0];
        if (!decision) {
            return { found: false, executed: false };
        }
        const wakeTargetId = input.wakeTarget ?? firstWakeTargetId(this.config);
        if (!wakeTargetId) {
            return { found: true, executed: false, error: "No wake target is configured." };
        }
        const wakeTarget = this.config.wakeTargets.find((target) => target.id === wakeTargetId);
        if (!wakeTarget) {
            return { found: true, executed: false, error: `Unknown wake target: ${wakeTargetId}` };
        }
        const security = decision.security;
        const payload = {
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
        const action = {
            type: "agent_wake",
            target: wakeTargetId,
            payload,
        };
        const actionResults = await executePlannedActions([action], input.dryRun ?? this.config.dryRun, this.deps.actionDeps ?? {});
        const feedbackInput = {
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
    async replayEvent(options) {
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
        let client;
        try {
            client = await this.deps.gmailClientFactory(source);
        }
        catch (error) {
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
    async handleGmailNotification(options) {
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
        let stage = "client_create";
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
            const nextCursor = {
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
        }
        catch (error) {
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
        }
        finally {
            this.inFlightSources.delete(source.id);
        }
        return summary;
    }
    async runSource(source) {
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
        let stage = "client_create";
        this.pollDiagnostics.set(source.id, { status: "running", startedAt, stage });
        try {
            const client = await this.deps.gmailClientFactory(source);
            stage = "candidate_list";
            this.pollDiagnostics.set(source.id, { status: "running", startedAt, stage });
            const candidates = await this.listSourceCandidates(source, client);
            const limitedCandidates = source.intakeMode === "history" || source.intakeMode === "watch"
                ? candidates
                : candidates.slice(0, source.polling.maxResults);
            const eventType = source.intakeMode === "history" || source.intakeMode === "watch" ? "gmail_history" : "poll_candidate";
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
        }
        catch (error) {
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
        }
        finally {
            this.inFlightSources.delete(source.id);
        }
        return summary;
    }
    async processCandidateEvents(source, client, candidates, observedAt, eventType, options = {}) {
        const summary = {
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
    async processEvent(client, event, options = {}) {
        const summary = { fetched: 0, processed: 0, skipped: 0, errors: 0 };
        if (!options.force && this.deps.stateStore.isProcessed(event.sourceId, event.messageId)) {
            summary.skipped += 1;
            return summary;
        }
        let stage = "message_fetch";
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
                }
                catch (error) {
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
            const processDeps = {
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
                const actionResults = await executePlannedActions(result.decision.actions, options.dryRun ?? this.config.dryRun, {
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
            }
            else {
                summary.skipped += 1;
            }
        }
        catch (error) {
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
    enabledSources() {
        return this.config.sources.filter((source) => source.enabled);
    }
    findNotificationSource(options) {
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
            const source = matches[0];
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
    async listSourceCandidates(source, client) {
        if (source.intakeMode === "watch" && source.watchTopicName) {
            const cursor = this.deps.stateStore.getSourceCursor(source.id);
            const expiresAt = typeof cursor?.watchExpiresAt === "string" ? Date.parse(cursor.watchExpiresAt) : 0;
            const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
            const needsRenewal = !historyId || expiresAt <= this.now().getTime() + 3600000;
            if (needsRenewal) {
                let page;
                if (historyId && client.listHistory) {
                    page = await this.listHistoryOrRepair(source, client, historyId);
                }
                const registration = await client.setupWatch?.(source.watchTopicName, ["INBOX"]);
                if (registration?.historyId) {
                    const nextCursor = {
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
    async listHistoryOrRepair(source, client, historyId) {
        try {
            return await client.listHistory(historyId);
        }
        catch (error) {
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
    emptySummary() {
        return {
            sources: 0,
            events: 0,
            fetched: 0,
            processed: 0,
            skipped: 0,
            errors: 0,
        };
    }
    now() {
        return (this.deps.now ?? (() => new Date()))();
    }
}
function buildSourceReadiness(source, cursor, now) {
    const mode = source.intakeMode ?? "poll";
    const historyId = typeof cursor?.historyId === "string" ? cursor.historyId : undefined;
    const watchExpiresAt = typeof cursor?.watchExpiresAt === "string" ? cursor.watchExpiresAt : undefined;
    const watchExpiresMs = watchExpiresAt ? Date.parse(watchExpiresAt) : Number.NaN;
    const watchActive = Number.isFinite(watchExpiresMs) && watchExpiresMs > now.getTime();
    const watchNeedsRenewal = mode === "watch" && (!watchActive || watchExpiresMs <= now.getTime() + 3600000);
    const configuredModifyScope = source.gmailActions.enabled && source.gmailActions.hasModifyScope;
    const credentialScopes = Array.isArray(cursor?.credentialScopes)
        ? cursor.credentialScopes.filter((scope) => typeof scope === "string")
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
function safeQuarantineItem(decision, options = {}) {
    const alertPayload = suspiciousPayloadFromDecision(decision);
    const item = {
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
        attachments: alertPayload?.attachments,
        riskReasons: alertPayload?.riskReasons,
        suspiciousSignals: alertPayload?.suspiciousSignals,
        sanitizedSummary: alertPayload?.sanitizedSummary ?? decision.security?.safeSummary,
        feedback: options.feedback ?? [],
    };
    if (!options.compact) {
        item.actions = decision.actions;
        item.latestActionStatuses = options.actionStatuses ?? [];
        item.actionAttempts = options.actionAttempts ?? [];
    }
    return removeUndefined(item);
}
function suspiciousPayloadFromDecision(decision) {
    const actions = Array.isArray(decision.actions) ? decision.actions : [];
    for (const action of actions) {
        if (!action || typeof action !== "object") {
            continue;
        }
        const payload = action.payload;
        if (payload && typeof payload === "object" && !Array.isArray(payload)) {
            return payload;
        }
    }
    return undefined;
}
function senderFromDecision(decision) {
    if (!decision) {
        return undefined;
    }
    const payload = suspiciousPayloadFromDecision(decision);
    return typeof payload?.sender === "string" ? payload.sender : undefined;
}
function subjectFromDecision(decision) {
    const payload = suspiciousPayloadFromDecision(decision);
    return typeof payload?.subject === "string" ? payload.subject : undefined;
}
function firstWakeTargetId(config) {
    return config.wakeTargets[0]?.id;
}
function removeUndefined(value) {
    return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}
function aggregateItemDue(queuedAt, cadence, now, timezone) {
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
function zonedDateKey(date, timezone) {
    const parts = zonedDateParts(date, timezone);
    return `${parts.year}-${parts.month}-${parts.day}`;
}
function zonedWeekKey(date, timezone) {
    const parts = zonedDateParts(date, timezone);
    return `${parts.year}-W${weekNumber(parts.year, parts.month, parts.day)}`;
}
function zonedDateParts(date, timezone) {
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
function validTimezone(timezone) {
    try {
        new Intl.DateTimeFormat("en-US", { timeZone: timezone });
        return timezone;
    }
    catch {
        return "UTC";
    }
}
function weekNumber(year, month, day) {
    const date = new Date(Date.UTC(year, month - 1, day));
    const start = new Date(Date.UTC(year, 0, 1));
    return Math.floor((date.getTime() - start.getTime()) / (7 * 24 * 60 * 60 * 1000));
}
function buildHistoryRepairQuery(source) {
    const baseQuery = buildCandidateQuery(source);
    if (!source.historyLookback) {
        return baseQuery;
    }
    return [baseQuery, `newer_than:${source.historyLookback}`].filter(Boolean).join(" ");
}
function isStaleHistoryError(error) {
    const raw = error && typeof error === "object" ? error : {};
    const code = raw.code ?? raw.status;
    if (code === 404 || code === "404") {
        return true;
    }
    const message = error instanceof Error ? error.message : String(error);
    return /history/i.test(message) && /(stale|expired|too old|not found|invalid)/i.test(message);
}
function safeRuntimeError(error) {
    if (error instanceof Error) {
        const raw = error;
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
function redactSecretLikeValues(value) {
    return value
        .replace(/(["'])(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|authorization)\1\s*:\s*(["'])[^"']*\3/gi, "$1$2$1: $3[redacted]$3")
        .replace(/(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|authorization)\s*(=|:)\s*[^,\s)}]+/gi, "$1$2 [redacted]")
        .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]");
}
function buildRequiredActionFailureMessage(results) {
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
function groupAggregateItems(items) {
    const groups = new Map();
    for (const item of items) {
        const key = [item.wakeTarget ?? "", item.cadence ?? "", item.sourceId].join("|");
        const existing = groups.get(key);
        if (existing) {
            existing.items.push(item);
        }
        else {
            groups.set(key, { key, ...(item.wakeTarget ? { wakeTarget: item.wakeTarget } : {}), items: [item] });
        }
    }
    return Array.from(groups.values());
}
export function createUnavailableGmailClientFactory() {
    return () => {
        throw new Error("Gmail client factory is not configured");
    };
}
