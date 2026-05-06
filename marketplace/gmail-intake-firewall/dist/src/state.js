import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
export function processedKey(sourceId, messageId) {
    return `${sourceId}:${messageId}`;
}
export function createEmptyState() {
    return {
        processed: {},
        decisions: [],
        aggregateQueue: [],
    };
}
export function isProcessed(state, sourceId, messageId) {
    return Boolean(state.processed[processedKey(sourceId, messageId)]);
}
export function recordDecision(state, decision) {
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
export async function loadState(path) {
    try {
        const parsed = JSON.parse(await readFile(expandHome(path), "utf8"));
        return {
            processed: parsed.processed ?? {},
            decisions: parsed.decisions ?? [],
            aggregateQueue: parsed.aggregateQueue ?? [],
        };
    }
    catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
            return createEmptyState();
        }
        throw error;
    }
}
export async function saveState(path, state) {
    const expandedPath = expandHome(path);
    await mkdir(dirname(expandedPath), { recursive: true });
    await writeFile(expandedPath, `${JSON.stringify(state, null, 2)}\n`, "utf8");
}
export function openSqliteStateStore(path) {
    const normalizedPath = expandHome(path);
    const db = openDatabase(normalizedPath);
    initializeSchema(db);
    return {
        path: normalizedPath,
        isProcessed(sourceId, messageId) {
            return Boolean(db.prepare("SELECT 1 FROM processed_messages WHERE source_id = ? AND message_id = ? LIMIT 1").get?.(sourceId, messageId));
        },
        recordDecision(decision) {
            this.recordDecisionPlan(decision);
            this.markProcessed(decision.sourceId, decision.messageId, decision.processedAt);
        },
        recordDecisionPlan(decision) {
            db.prepare(`INSERT INTO decisions (
          processed_at, source_id, account_email, message_id, thread_id, security_json,
          routing_json, actions_json, dry_run
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(decision.processedAt, decision.sourceId, decision.accountEmail, decision.messageId, decision.threadId, JSON.stringify(decision.security), decision.routing ? JSON.stringify(decision.routing) : null, JSON.stringify(decision.actions), decision.dryRun ? 1 : 0);
            for (const action of decision.actions) {
                if (action.type === "aggregate_enqueue") {
                    this.enqueueAggregate(action.item);
                }
            }
        },
        markProcessed(sourceId, messageId, processedAt) {
            db.prepare(`INSERT OR IGNORE INTO processed_messages (source_id, message_id, processed_at)
         VALUES (?, ?, ?)`).run(sourceId, messageId, processedAt);
        },
        recordActionStatus(decision, status, attemptedAt = new Date().toISOString()) {
            db.prepare(`INSERT INTO action_attempts (
          source_id, message_id, processed_at, action_index, action_type, required,
          status, error, attempted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(decision.sourceId, decision.messageId, decision.processedAt, status.actionIndex, status.action.type, status.required ? 1 : 0, status.status, status.error ?? null, attemptedAt);
            db.prepare(`INSERT INTO action_statuses (
          source_id, message_id, action_index, action_type, required, status, error, attempted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_id, message_id, action_index) DO UPDATE SET
          action_type = excluded.action_type,
          required = excluded.required,
          status = excluded.status,
          error = excluded.error,
          attempted_at = excluded.attempted_at`).run(decision.sourceId, decision.messageId, status.actionIndex, status.action.type, status.required ? 1 : 0, status.status, status.error ?? null, attemptedAt);
        },
        listActionStatuses(sourceId, messageId) {
            return this.listActionAttempts(sourceId, messageId);
        },
        listActionAttempts(sourceId, messageId) {
            return db.prepare(`SELECT id, processed_at, action_index, action_type, required, status, error, attempted_at
         FROM action_attempts
         WHERE source_id = ? AND message_id = ?
         ORDER BY id ASC`).all?.(sourceId, messageId) ?? [];
        },
        enqueueAggregate(item) {
            db.prepare(`INSERT OR IGNORE INTO aggregate_queue (
          source_id, message_id, thread_id, account_email, tags_json, sanitized_summary,
          queued_at, wake_target, cadence, delivered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(source_id, message_id) DO UPDATE SET
          tags_json = excluded.tags_json,
          sanitized_summary = excluded.sanitized_summary,
          queued_at = excluded.queued_at,
          wake_target = excluded.wake_target,
          cadence = excluded.cadence`).run(item.sourceId, item.messageId, item.threadId, item.accountEmail, JSON.stringify(item.tags), item.sanitizedSummary, item.queuedAt, item.wakeTarget ?? null, item.cadence ?? null);
        },
        listAggregateQueue(limit = 100) {
            const rows = db.prepare(`SELECT source_id, message_id, thread_id, account_email, tags_json, sanitized_summary,
          queued_at, wake_target, cadence
         FROM aggregate_queue
         WHERE delivered_at IS NULL
         ORDER BY queued_at ASC
         LIMIT ?`).all?.(limit) ?? [];
            return rows.map((row) => {
                const raw = row;
                const item = {
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
        markAggregateDelivered(items, deliveredAt = new Date().toISOString()) {
            const statement = db.prepare(`UPDATE aggregate_queue
         SET delivered_at = ?
         WHERE source_id = ? AND message_id = ?`);
            for (const item of items) {
                statement.run(deliveredAt, item.sourceId, item.messageId);
            }
        },
        recordEvent(event) {
            db.prepare(`INSERT INTO intake_events (
          source_id, account_email, message_id, thread_id, event_type, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?)`).run(event.sourceId, event.accountEmail, event.messageId, event.threadId ?? null, event.eventType, event.observedAt);
        },
        recordFeedback(event) {
            db.prepare(`INSERT INTO feedback_events (
          created_at, source_id, message_id, thread_id, feedback_type, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?)`).run(typeof event.createdAt === "string" ? event.createdAt : new Date().toISOString(), typeof event.sourceId === "string" ? event.sourceId : null, typeof event.messageId === "string" ? event.messageId : null, typeof event.threadId === "string" ? event.threadId : null, typeof event.feedbackType === "string" ? event.feedbackType : "unknown", JSON.stringify(event));
        },
        listFeedbackEvents(limit = 100) {
            return db.prepare(`SELECT created_at, source_id, message_id, thread_id, feedback_type, payload_json
         FROM feedback_events
         ORDER BY created_at DESC
         LIMIT ?`).all?.(limit) ?? [];
        },
        getSourceCursor(sourceId) {
            const row = db.prepare("SELECT cursor_json FROM source_cursors WHERE source_id = ?").get?.(sourceId);
            const cursorJson = row?.cursor_json;
            if (typeof cursorJson !== "string") {
                return undefined;
            }
            try {
                const parsed = JSON.parse(cursorJson);
                return parsed && typeof parsed === "object" && !Array.isArray(parsed)
                    ? parsed
                    : undefined;
            }
            catch {
                return undefined;
            }
        },
        setSourceCursor(sourceId, cursor, updatedAt = new Date().toISOString()) {
            db.prepare(`INSERT INTO source_cursors (source_id, cursor_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(source_id) DO UPDATE SET
           cursor_json = excluded.cursor_json,
           updated_at = excluded.updated_at`).run(sourceId, JSON.stringify(cursor), updatedAt);
        },
        close() {
            db.close?.();
        },
    };
}
function initializeSchema(db) {
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
    }
    catch {
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
function openDatabase(path) {
    mkdirSyncForFile(path);
    const require = createRequire(import.meta.url);
    try {
        const sqlite = require("better-sqlite3");
        const Database = sqlite.default ?? sqlite;
        return new Database(path);
    }
    catch (betterSqliteError) {
        try {
            const sqlite = require("node:sqlite");
            return new sqlite.DatabaseSync(path);
        }
        catch {
            throw betterSqliteError;
        }
    }
}
function mkdirSyncForFile(path) {
    const fs = createRequire(import.meta.url)("node:fs");
    fs.mkdirSync(dirname(path), { recursive: true });
}
function expandHome(path) {
    if (path === "~") {
        return process.env.HOME ?? dirname(fileURLToPath(import.meta.url));
    }
    if (path.startsWith("~/")) {
        return `${process.env.HOME ?? dirname(fileURLToPath(import.meta.url))}${path.slice(1)}`;
    }
    return path;
}
function parseStringArray(value) {
    if (typeof value !== "string") {
        return [];
    }
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed.filter((entry) => typeof entry === "string") : [];
    }
    catch {
        return [];
    }
}
