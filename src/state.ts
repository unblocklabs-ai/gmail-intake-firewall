import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { ActionExecutionStatus } from "./actions.js";
import type { AggregateItem, DecisionLogEntry, IntakeEvent } from "./types.js";

export type FirewallState = {
  processed: Record<string, string>;
  decisions: DecisionLogEntry[];
  aggregateQueue: AggregateItem[];
};

export function processedKey(sourceId: string, messageId: string): string {
  return `${sourceId}:${messageId}`;
}

export function createEmptyState(): FirewallState {
  return {
    processed: {},
    decisions: [],
    aggregateQueue: [],
  };
}

export function isProcessed(state: FirewallState, sourceId: string, messageId: string): boolean {
  return Boolean(state.processed[processedKey(sourceId, messageId)]);
}

export function recordDecision(state: FirewallState, decision: DecisionLogEntry): FirewallState {
  const key = processedKey(decision.sourceId, decision.messageId);
  return {
    processed: {
      ...state.processed,
      [key]: decision.processedAt,
    },
    decisions: [...state.decisions, decision],
    aggregateQueue: [
      ...state.aggregateQueue,
      ...decision.actions.flatMap((action) => action.type === "aggregate_enqueue" ? [action.item] : []),
    ],
  };
}

export async function loadState(path: string): Promise<FirewallState> {
  try {
    const parsed = JSON.parse(await readFile(expandHome(path), "utf8")) as Partial<FirewallState>;
    return {
      processed: parsed.processed ?? {},
      decisions: parsed.decisions ?? [],
      aggregateQueue: parsed.aggregateQueue ?? [],
    };
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return createEmptyState();
    }
    throw error;
  }
}

export async function saveState(path: string, state: FirewallState): Promise<void> {
  const expandedPath = expandHome(path);
  await mkdir(dirname(expandedPath), { recursive: true });
  await writeFile(expandedPath, `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

type SqliteStatement = {
  run: (...args: unknown[]) => unknown;
  get?: (...args: unknown[]) => unknown;
  all?: (...args: unknown[]) => unknown[];
};

type SqliteDatabase = {
  exec: (sql: string) => unknown;
  prepare: (sql: string) => SqliteStatement;
  close?: () => unknown;
};

export type SqliteStateStore = {
  readonly path: string;
  isProcessed(sourceId: string, messageId: string): boolean;
  recordDecision(decision: DecisionLogEntry): void;
  recordDecisionPlan(decision: DecisionLogEntry): void;
  markProcessed(sourceId: string, messageId: string, processedAt: string): void;
  recordActionStatus(decision: DecisionLogEntry, status: ActionExecutionStatus, attemptedAt?: string): void;
  listActionStatuses(sourceId: string, messageId: string): Array<Record<string, unknown>>;
  listActionAttempts(sourceId: string, messageId: string): Array<Record<string, unknown>>;
  countPendingAggregates(): number;
  enqueueAggregate(item: AggregateItem): void;
  listAggregateQueue(limit?: number): AggregateItem[];
  markAggregateDelivered(items: AggregateItem[], deliveredAt?: string): void;
  recordEvent(event: IntakeEvent): void;
  recordFeedback(event: Record<string, unknown>): void;
  listFeedbackEvents(limit?: number): Array<Record<string, unknown>>;
  listEvents(sourceId: string, messageId: string, limit?: number): Array<Record<string, unknown>>;
  findLatestEvent(sourceId: string, messageId: string): IntakeEvent | undefined;
  listDecisions(sourceId: string, messageId: string, limit?: number): Array<Record<string, unknown>>;
  getSourceStats(sourceId: string): Record<string, unknown>;
  getSourceCursor(sourceId: string): Record<string, unknown> | undefined;
  setSourceCursor(sourceId: string, cursor: Record<string, unknown>, updatedAt?: string): void;
  close(): void;
};

export function openSqliteStateStore(path: string): SqliteStateStore {
  const normalizedPath = expandHome(path);
  const db = openDatabase(normalizedPath);
  initializeSchema(db);
  return {
    path: normalizedPath,
    isProcessed(sourceId: string, messageId: string): boolean {
      return Boolean(db.prepare(
        "SELECT 1 FROM processed_messages WHERE source_id = ? AND message_id = ? LIMIT 1",
      ).get?.(sourceId, messageId));
    },
    recordDecision(decision: DecisionLogEntry): void {
      this.recordDecisionPlan(decision);
      this.markProcessed(decision.sourceId, decision.messageId, decision.processedAt);
    },
    recordDecisionPlan(decision: DecisionLogEntry): void {
      db.prepare(
        `INSERT INTO decisions (
          processed_at, source_id, account_email, message_id, thread_id, security_json,
          routing_json, actions_json, dry_run
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        decision.processedAt,
        decision.sourceId,
        decision.accountEmail,
        decision.messageId,
        decision.threadId,
        JSON.stringify(decision.security),
        decision.routing ? JSON.stringify(decision.routing) : null,
        JSON.stringify(decision.actions),
        decision.dryRun ? 1 : 0,
      );
      for (const action of decision.actions) {
        if (action.type === "aggregate_enqueue") {
          this.enqueueAggregate(action.item);
        }
      }
    },
    markProcessed(sourceId: string, messageId: string, processedAt: string): void {
      db.prepare(
        `INSERT OR IGNORE INTO processed_messages (source_id, message_id, processed_at)
         VALUES (?, ?, ?)`,
      ).run(sourceId, messageId, processedAt);
    },
    recordActionStatus(decision: DecisionLogEntry, status: ActionExecutionStatus, attemptedAt = new Date().toISOString()): void {
      db.prepare(
        `INSERT INTO action_attempts (
          source_id, message_id, processed_at, action_index, action_type, required,
          status, error, attempted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        decision.sourceId,
        decision.messageId,
        decision.processedAt,
        status.actionIndex,
        status.action.type,
        status.required ? 1 : 0,
        status.status,
        status.error ?? null,
        attemptedAt,
      );
      db.prepare(
        `INSERT INTO action_statuses (
          source_id, message_id, action_index, action_type, required, status, error, attempted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_id, message_id, action_index) DO UPDATE SET
          action_type = excluded.action_type,
          required = excluded.required,
          status = excluded.status,
          error = excluded.error,
          attempted_at = excluded.attempted_at`,
      ).run(
        decision.sourceId,
        decision.messageId,
        status.actionIndex,
        status.action.type,
        status.required ? 1 : 0,
        status.status,
        status.error ?? null,
        attemptedAt,
      );
    },
    listActionStatuses(sourceId: string, messageId: string): Array<Record<string, unknown>> {
      return db.prepare(
        `SELECT action_index, action_type, required, status, error, attempted_at
         FROM action_statuses
         WHERE source_id = ? AND message_id = ?
         ORDER BY action_index ASC`,
      ).all?.(sourceId, messageId) as Array<Record<string, unknown>> ?? [];
    },
    listActionAttempts(sourceId: string, messageId: string): Array<Record<string, unknown>> {
      return db.prepare(
        `SELECT id, processed_at, action_index, action_type, required, status, error, attempted_at
         FROM action_attempts
         WHERE source_id = ? AND message_id = ?
         ORDER BY id ASC`,
      ).all?.(sourceId, messageId) as Array<Record<string, unknown>> ?? [];
    },
    countPendingAggregates(): number {
      const row = db.prepare(
        "SELECT COUNT(*) AS count FROM aggregate_queue WHERE delivered_at IS NULL",
      ).get?.() as Record<string, unknown> | undefined;
      return numberValue(row?.count);
    },
    enqueueAggregate(item: AggregateItem): void {
      db.prepare(
        `INSERT OR IGNORE INTO aggregate_queue (
          source_id, message_id, thread_id, account_email, tags_json, sanitized_summary,
          queued_at, wake_target, cadence, delivered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(source_id, message_id) DO UPDATE SET
          tags_json = excluded.tags_json,
          sanitized_summary = excluded.sanitized_summary,
          queued_at = excluded.queued_at,
          wake_target = excluded.wake_target,
          cadence = excluded.cadence`,
      ).run(
        item.sourceId,
        item.messageId,
        item.threadId,
        item.accountEmail,
        JSON.stringify(item.tags),
        item.sanitizedSummary,
        item.queuedAt,
        item.wakeTarget ?? null,
        item.cadence ?? null,
      );
    },
    listAggregateQueue(limit = 100): AggregateItem[] {
      const rows = db.prepare(
        `SELECT source_id, message_id, thread_id, account_email, tags_json, sanitized_summary,
          queued_at, wake_target, cadence
         FROM aggregate_queue
         WHERE delivered_at IS NULL
         ORDER BY queued_at ASC
         LIMIT ?`,
      ).all?.(limit) ?? [];
      return rows.map((row) => {
        const raw = row as Record<string, unknown>;
        const item: AggregateItem = {
          sourceId: String(raw.source_id),
          messageId: String(raw.message_id),
          threadId: String(raw.thread_id),
          accountEmail: String(raw.account_email),
          tags: parseStringArray(raw.tags_json),
          sanitizedSummary: String(raw.sanitized_summary),
          queuedAt: String(raw.queued_at),
        };
        if (typeof raw.wake_target === "string" && raw.wake_target) {
          item.wakeTarget = raw.wake_target;
        }
        if (typeof raw.cadence === "string" && raw.cadence) {
          item.cadence = raw.cadence;
        }
        return item;
      });
    },
    markAggregateDelivered(items: AggregateItem[], deliveredAt = new Date().toISOString()): void {
      const statement = db.prepare(
        `UPDATE aggregate_queue
         SET delivered_at = ?
         WHERE source_id = ? AND message_id = ?`,
      );
      for (const item of items) {
        statement.run(deliveredAt, item.sourceId, item.messageId);
      }
    },
    recordEvent(event: IntakeEvent): void {
      db.prepare(
        `INSERT INTO intake_events (
          source_id, account_email, message_id, thread_id, event_type, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(
        event.sourceId,
        event.accountEmail,
        event.messageId,
        event.threadId ?? null,
        event.eventType,
        event.observedAt,
      );
    },
    recordFeedback(event: Record<string, unknown>): void {
      db.prepare(
        `INSERT INTO feedback_events (
          created_at, source_id, message_id, thread_id, feedback_type, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(
        typeof event.createdAt === "string" ? event.createdAt : new Date().toISOString(),
        typeof event.sourceId === "string" ? event.sourceId : null,
        typeof event.messageId === "string" ? event.messageId : null,
        typeof event.threadId === "string" ? event.threadId : null,
        typeof event.feedbackType === "string" ? event.feedbackType : "unknown",
        JSON.stringify(event),
      );
    },
    listFeedbackEvents(limit = 100): Array<Record<string, unknown>> {
      return db.prepare(
        `SELECT created_at, source_id, message_id, thread_id, feedback_type, payload_json
         FROM feedback_events
         ORDER BY created_at DESC
         LIMIT ?`,
      ).all?.(limit) as Array<Record<string, unknown>> ?? [];
    },
    listEvents(sourceId: string, messageId: string, limit = 25): Array<Record<string, unknown>> {
      return db.prepare(
        `SELECT id, source_id, account_email, message_id, thread_id, event_type, observed_at
         FROM intake_events
         WHERE source_id = ? AND message_id = ?
         ORDER BY id DESC
         LIMIT ?`,
      ).all?.(sourceId, messageId, limit) as Array<Record<string, unknown>> ?? [];
    },
    findLatestEvent(sourceId: string, messageId: string): IntakeEvent | undefined {
      const row = db.prepare(
        `SELECT source_id, account_email, message_id, thread_id, event_type, observed_at
         FROM intake_events
         WHERE source_id = ? AND message_id = ?
         ORDER BY id DESC
         LIMIT 1`,
      ).get?.(sourceId, messageId) as Record<string, unknown> | undefined;
      if (!row) {
        return undefined;
      }
      return {
        sourceId: String(row.source_id),
        accountEmail: String(row.account_email),
        messageId: String(row.message_id),
        ...(typeof row.thread_id === "string" ? { threadId: row.thread_id } : {}),
        eventType: eventTypeValue(row.event_type),
        observedAt: String(row.observed_at),
      };
    },
    listDecisions(sourceId: string, messageId: string, limit = 10): Array<Record<string, unknown>> {
      const rows = db.prepare(
        `SELECT id, processed_at, source_id, account_email, message_id, thread_id,
          security_json, routing_json, actions_json, dry_run
         FROM decisions
         WHERE source_id = ? AND message_id = ?
         ORDER BY id DESC
         LIMIT ?`,
      ).all?.(sourceId, messageId, limit) ?? [];
      return rows.map((row) => normalizeDecisionRow(row as Record<string, unknown>));
    },
    getSourceStats(sourceId: string): Record<string, unknown> {
      const decisionStats = db.prepare(
        `SELECT
          COUNT(*) AS decisions,
          MAX(processed_at) AS last_decision_at,
          SUM(CASE WHEN routing_json IS NULL THEN 1 ELSE 0 END) AS quarantined
         FROM decisions
         WHERE source_id = ?`,
      ).get?.(sourceId) as Record<string, unknown> | undefined;
      const processedStats = db.prepare(
        `SELECT COUNT(*) AS processed, MAX(processed_at) AS last_processed_at
         FROM processed_messages
         WHERE source_id = ?`,
      ).get?.(sourceId) as Record<string, unknown> | undefined;
      const eventStats = db.prepare(
        `SELECT COUNT(*) AS events, MAX(observed_at) AS last_event_at
         FROM intake_events
         WHERE source_id = ?`,
      ).get?.(sourceId) as Record<string, unknown> | undefined;
      const actionStats = db.prepare(
        `SELECT
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_actions,
          MAX(attempted_at) AS last_action_at
         FROM action_attempts
         WHERE source_id = ?`,
      ).get?.(sourceId) as Record<string, unknown> | undefined;
      const aggregateStats = db.prepare(
        `SELECT COUNT(*) AS pending_aggregates
         FROM aggregate_queue
         WHERE source_id = ? AND delivered_at IS NULL`,
      ).get?.(sourceId) as Record<string, unknown> | undefined;
      return {
        decisions: numberValue(decisionStats?.decisions),
        processed: numberValue(processedStats?.processed),
        events: numberValue(eventStats?.events),
        quarantined: numberValue(decisionStats?.quarantined),
        failedActions: numberValue(actionStats?.failed_actions),
        pendingAggregates: numberValue(aggregateStats?.pending_aggregates),
        ...(typeof decisionStats?.last_decision_at === "string" ? { lastDecisionAt: decisionStats.last_decision_at } : {}),
        ...(typeof processedStats?.last_processed_at === "string" ? { lastProcessedAt: processedStats.last_processed_at } : {}),
        ...(typeof eventStats?.last_event_at === "string" ? { lastEventAt: eventStats.last_event_at } : {}),
        ...(typeof actionStats?.last_action_at === "string" ? { lastActionAt: actionStats.last_action_at } : {}),
      };
    },
    getSourceCursor(sourceId: string): Record<string, unknown> | undefined {
      const row = db.prepare(
        "SELECT cursor_json FROM source_cursors WHERE source_id = ?",
      ).get?.(sourceId) as Record<string, unknown> | undefined;
      const cursorJson = row?.cursor_json;
      if (typeof cursorJson !== "string") {
        return undefined;
      }
      try {
        const parsed = JSON.parse(cursorJson) as unknown;
        return parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? parsed as Record<string, unknown>
          : undefined;
      } catch {
        return undefined;
      }
    },
    setSourceCursor(sourceId: string, cursor: Record<string, unknown>, updatedAt = new Date().toISOString()): void {
      db.prepare(
        `INSERT INTO source_cursors (source_id, cursor_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(source_id) DO UPDATE SET
           cursor_json = excluded.cursor_json,
           updated_at = excluded.updated_at`,
      ).run(sourceId, JSON.stringify(cursor), updatedAt);
    },
    close(): void {
      db.close?.();
    },
  };
}

function initializeSchema(db: SqliteDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS processed_messages (
      source_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      processed_at TEXT NOT NULL,
      PRIMARY KEY (source_id, message_id)
    );

    CREATE TABLE IF NOT EXISTS decisions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      processed_at TEXT NOT NULL,
      source_id TEXT NOT NULL,
      account_email TEXT NOT NULL,
      message_id TEXT NOT NULL,
      thread_id TEXT NOT NULL,
      security_json TEXT NOT NULL,
      routing_json TEXT,
      actions_json TEXT NOT NULL,
      dry_run INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS decisions_source_message_idx
      ON decisions (source_id, message_id);

    CREATE TABLE IF NOT EXISTS action_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      processed_at TEXT NOT NULL,
      action_index INTEGER NOT NULL,
      action_type TEXT NOT NULL,
      required INTEGER NOT NULL,
      status TEXT NOT NULL,
      error TEXT,
      attempted_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS action_attempts_source_message_idx
      ON action_attempts (source_id, message_id, id);

    CREATE TABLE IF NOT EXISTS action_statuses (
      source_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      action_index INTEGER NOT NULL,
      action_type TEXT NOT NULL,
      required INTEGER NOT NULL,
      status TEXT NOT NULL,
      error TEXT,
      attempted_at TEXT NOT NULL,
      PRIMARY KEY (source_id, message_id, action_index)
    );

    CREATE TABLE IF NOT EXISTS aggregate_queue (
      source_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      thread_id TEXT NOT NULL,
      account_email TEXT NOT NULL,
      tags_json TEXT NOT NULL,
      sanitized_summary TEXT NOT NULL,
      queued_at TEXT NOT NULL,
      wake_target TEXT,
      cadence TEXT,
      delivered_at TEXT,
      PRIMARY KEY (source_id, message_id)
    );

    CREATE TABLE IF NOT EXISTS feedback_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      source_id TEXT,
      message_id TEXT,
      thread_id TEXT,
      feedback_type TEXT NOT NULL,
      payload_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS source_cursors (
      source_id TEXT PRIMARY KEY,
      cursor_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS intake_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_id TEXT NOT NULL,
      account_email TEXT NOT NULL,
      message_id TEXT NOT NULL,
      thread_id TEXT,
      event_type TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );
  `);
  try {
    db.exec("ALTER TABLE aggregate_queue ADD COLUMN cadence TEXT;");
  } catch {
    // Existing databases may already have the Phase 2 cadence column.
  }
  db.exec(`
    INSERT INTO action_attempts (
      source_id, message_id, processed_at, action_index, action_type, required,
      status, error, attempted_at
    )
    SELECT source_id, message_id, attempted_at, action_index, action_type, required,
      status, error, attempted_at
    FROM action_statuses AS latest
    WHERE NOT EXISTS (
      SELECT 1
      FROM action_attempts AS attempt
      WHERE attempt.source_id = latest.source_id
        AND attempt.message_id = latest.message_id
        AND attempt.action_index = latest.action_index
        AND attempt.attempted_at = latest.attempted_at
    );
  `);
}

function openDatabase(path: string): SqliteDatabase {
  mkdirSyncForFile(path);
  const require = createRequire(import.meta.url);
  try {
    const sqlite = require("better-sqlite3") as { default?: new (path: string) => SqliteDatabase } & (new (path: string) => SqliteDatabase);
    const Database = sqlite.default ?? sqlite;
    return new Database(path);
  } catch (betterSqliteError) {
    try {
      const sqlite = require("node:sqlite") as { DatabaseSync: new (path: string) => SqliteDatabase };
      return new sqlite.DatabaseSync(path);
    } catch {
      throw betterSqliteError;
    }
  }
}

function mkdirSyncForFile(path: string): void {
  const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
  fs.mkdirSync(dirname(path), { recursive: true });
}

function expandHome(path: string): string {
  if (path === "~") {
    return process.env.HOME ?? dirname(fileURLToPath(import.meta.url));
  }
  if (path.startsWith("~/")) {
    return `${process.env.HOME ?? dirname(fileURLToPath(import.meta.url))}${path.slice(1)}`;
  }
  return path;
}

function parseStringArray(value: unknown): string[] {
  if (typeof value !== "string") {
    return [];
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === "string") : [];
  } catch {
    return [];
  }
}

function normalizeDecisionRow(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    processedAt: row.processed_at,
    sourceId: row.source_id,
    accountEmail: row.account_email,
    messageId: row.message_id,
    threadId: row.thread_id,
    security: parseJson(row.security_json),
    routing: parseJson(row.routing_json),
    actions: parseJson(row.actions_json),
    dryRun: Boolean(row.dry_run),
  };
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") {
    return undefined;
  }
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function eventTypeValue(value: unknown): IntakeEvent["eventType"] {
  return value === "gmail_history" || value === "gmail_watch" || value === "poll_candidate"
    ? value
    : "poll_candidate";
}
