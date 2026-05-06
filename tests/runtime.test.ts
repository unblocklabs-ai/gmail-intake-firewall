import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { resolvePluginConfig } from "../src/config.js";
import { GmailIntakePollingRuntime } from "../src/runtime.js";
import { openSqliteStateStore, type SqliteStateStore } from "../src/state.js";
import type { GmailCandidate, GmailClient } from "../src/gmail.js";
import type { InboundMessage, SecurityClassification } from "../src/types.js";

function message(id: string): InboundMessage {
  return {
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: id,
    threadId: `thread-${id}`,
    headers: {},
    rawHeaders: [],
    from: "client@example.com",
    to: ["user@example.com"],
    cc: [],
    bcc: [],
    subject: "Runtime test",
    labels: ["INBOX"],
    snippet: "Runtime test message",
    bodyText: "Runtime test message",
    attachments: [],
  };
}

async function tempStore(t: { after: (fn: () => void) => void }): Promise<SqliteStateStore> {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-runtime-"));
  const store = openSqliteStateStore(join(dir, "state.sqlite"));
  t.after(() => store.close());
  return store;
}

const safeSecurity: SecurityClassification = {
  verdict: "safe",
  riskScore: 0.01,
  categories: [],
  reasons: ["safe"],
  safeSummary: "Safe runtime message.",
  suspiciousSignals: [],
};

test("polling runtime processes enabled source candidates and persists cursor", async (t) => {
  const stateStore = await tempStore(t);
  const queries: (string | undefined)[] = [];
  const fetched: string[] = [];
  const candidates: GmailCandidate[] = [
    { id: "msg-1", threadId: "thread-msg-1" },
    { id: "msg-2", threadId: "thread-msg-2" },
    { id: "msg-3", threadId: "thread-msg-3" },
  ];
  const client: GmailClient = {
    async listCandidates(query) {
      queries.push(query);
      return candidates;
    },
    async fetchMessage(candidate) {
      fetched.push(candidate.id);
      return message(candidate.id);
    },
    async applyLabel() {},
    async archive() {},
  };
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [
      {
        id: "primary",
        accountEmail: "user@example.com",
        candidateQuery: "in:inbox newer_than:7d",
        include: "category:primary",
        exclude: "from:noise@example.com",
        polling: { maxResults: 2 },
      },
    ],
    tags: [
      {
        id: "client-dev",
        description: "Client dev",
        wakeMode: "none",
      },
    ],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => client,
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: ["client-dev"],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: ["test"],
      }),
    },
    now: () => new Date("2026-05-06T12:00:00.000Z"),
  });

  const summary = await runtime.runOnce();

  assert.deepEqual(queries, ["in:inbox newer_than:7d category:primary -(from:noise@example.com)"]);
  assert.deepEqual(fetched, ["msg-1", "msg-2"]);
  assert.equal(summary.sources, 1);
  assert.equal(summary.events, 2);
  assert.equal(summary.fetched, 2);
  assert.equal(summary.processed, 2);
  assert.equal(summary.errors, 0);
  assert.equal(stateStore.isProcessed("primary", "msg-1"), true);
  assert.equal(stateStore.isProcessed("primary", "msg-3"), false);
  assert.deepEqual(stateStore.getSourceCursor("primary"), {
    mode: "poll",
    lastPolledAt: "2026-05-06T12:00:00.000Z",
    candidateCount: 2,
  });
});

test("polling runtime skips already processed messages before fetch", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  stateStore.recordDecision({
    processedAt: "2026-05-06T00:00:00.000Z",
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-msg-1",
    security: safeSecurity,
    actions: [{ type: "record_only", reason: "preexisting" }],
    dryRun: true,
  });
  let fetchCount = 0;
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage() {
        fetchCount += 1;
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Skipped",
        reasons: [],
      }),
    },
  });

  const summary = await runtime.runOnce();
  assert.equal(fetchCount, 0);
  assert.equal(summary.skipped, 1);
  assert.equal(summary.processed, 0);
});

test("polling runtime ignores disabled sources", async (t) => {
  const stateStore = await tempStore(t);
  let listCount = 0;
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [
      { id: "primary", accountEmail: "user@example.com", enabled: false },
    ],
  }), {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        listCount += 1;
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
  });

  const summary = await runtime.runOnce();
  assert.equal(listCount, 0);
  assert.equal(summary.sources, 0);
});

test("polling runtime leaves message pending when a required action fails", async (t) => {
  const stateStore = await tempStore(t);
  const appliedLabels: string[] = [];
  const config = resolvePluginConfig({
    dryRun: false,
    sqlitePath: stateStore.path,
    security: {
      archiveOnQuarantine: false,
      alertTarget: "slack:#security",
    },
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel(_messageId, label) {
        appliedLabels.push(label);
      },
      async archive() {},
    }),
    securityClassifier: {
      classify: async () => ({
        verdict: "risky",
        riskScore: 1,
        categories: ["phishing"],
        reasons: ["credential theft"],
        safeSummary: "Likely phishing.",
        suspiciousSignals: ["fake login"],
      }),
    },
  });

  const summary = await runtime.runOnce();

  assert.equal(summary.processed, 0);
  assert.equal(summary.errors, 1);
  assert.equal(stateStore.isProcessed("primary", "msg-1"), false);
  assert.deepEqual(appliedLabels, ["OpenClaw/Quarantine"]);
  assert.deepEqual(stateStore.listActionStatuses("primary", "msg-1").map((row) => ({
    action_type: row.action_type,
    required: row.required,
    status: row.status,
  })), [
    { action_type: "gmail_label", required: 1, status: "succeeded" },
    { action_type: "human_alert", required: 1, status: "failed" },
  ]);
});

test("polling runtime stores append-only action attempts across retries", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: false,
    sqlitePath: stateStore.path,
    security: {
      alertTarget: "slack:#security",
    },
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: {
      classify: async () => ({
        verdict: "risky",
        riskScore: 1,
        categories: ["phishing"],
        reasons: ["credential theft"],
        safeSummary: "Likely phishing.",
        suspiciousSignals: ["fake login"],
      }),
    },
    now: (() => {
      let tick = 0;
      return () => new Date(`2026-05-06T12:00:0${tick++}.000Z`);
    })(),
  });

  await runtime.runOnce();
  await runtime.runOnce();

  const attempts = stateStore.listActionAttempts("primary", "msg-1");
  const latest = stateStore.listActionStatuses("primary", "msg-1");
  assert.equal(attempts.length, 4);
  assert.deepEqual(attempts.map((row) => row.status), ["succeeded", "failed", "succeeded", "failed"]);
  assert.deepEqual(attempts.map((row) => row.action_index), [0, 1, 0, 1]);
  assert.deepEqual(latest.map((row) => row.status), ["succeeded", "failed"]);
});

test("polling runtime marks processed only after required actions succeed", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: false,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
    tags: [{ id: "client-dev", description: "Client dev", wakeMode: "wake_now", wakeTarget: "agent:dev" }],
    wakeTargets: [{ id: "agent:dev", agentId: "dev-agent" }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: ["client-dev"],
        wakeMode: "wake_now",
        wakeTarget: "agent:dev",
        sanitizedSummary: "Safe runtime message.",
        reasons: ["test"],
      }),
    },
    actionDeps: {
      wake: {
        async startDetachedAgentTurn() {},
      },
    },
  });

  const summary = await runtime.runOnce();

  assert.equal(summary.processed, 1);
  assert.equal(summary.errors, 0);
  assert.equal(stateStore.isProcessed("primary", "msg-1"), true);
  assert.deepEqual(stateStore.listActionStatuses("primary", "msg-1").map((row) => row.status), ["succeeded"]);
});

test("polling runtime skips overlapping poll for the same source", async (t) => {
  const stateStore = await tempStore(t);
  let releaseList: (() => void) | undefined;
  let listCount = 0;
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  }), {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        listCount += 1;
        await new Promise<void>((resolve) => {
          releaseList = resolve;
        });
        return [];
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
  });

  const firstRun = runtime.runOnce();
  await new Promise((resolve) => setImmediate(resolve));
  const secondRun = await runtime.runOnce();
  releaseList?.();
  await firstRun;

  assert.equal(listCount, 1);
  assert.equal(secondRun.skipped, 1);
});

test("runtime consumes Gmail history events and preserves history cursor", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.setSourceCursor("primary", { mode: "history", historyId: "100" });
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com", intakeMode: "history" }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        throw new Error("poll should not be used");
      },
      async listHistory(startHistoryId) {
        assert.equal(startHistoryId, "100");
        return { historyId: "110", candidates: [{ id: "msg-1", threadId: "thread-msg-1" }] };
      },
      async fetchMessage(candidate) {
        return message(candidate.id);
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: [],
      }),
    },
    now: () => new Date("2026-05-06T12:00:00.000Z"),
  });

  const summary = await runtime.runOnce();

  assert.equal(summary.processed, 1);
  assert.equal(stateStore.getSourceCursor("primary")?.historyId, "110");
});

test("runtime setup watch stores history id without processing initial snapshot", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com", intakeMode: "watch", watchTopicName: "projects/x/topics/gmail" }],
  });
  let watchCount = 0;
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [];
      },
      async setupWatch(topicName) {
        watchCount += 1;
        assert.equal(topicName, "projects/x/topics/gmail");
        return { historyId: "200", expiration: "2026-05-07T12:00:00.000Z" };
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
  });

  const summary = await runtime.runOnce();

  assert.equal(watchCount, 1);
  assert.equal(summary.events, 0);
  assert.equal(stateStore.getSourceCursor("primary")?.historyId, "200");
});

test("runtime drains old history before renewing an expiring watch", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.setSourceCursor("primary", {
    mode: "watch",
    historyId: "100",
    watchExpiresAt: "2026-05-06T12:30:00.000Z",
  });
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com", intakeMode: "watch", watchTopicName: "projects/x/topics/gmail" }],
  });
  const calls: string[] = [];
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        throw new Error("repair poll should not be used");
      },
      async listHistory(startHistoryId) {
        calls.push(`history:${startHistoryId}`);
        return { historyId: "110", candidates: [{ id: "msg-1", threadId: "thread-msg-1" }] };
      },
      async setupWatch() {
        calls.push("watch");
        return { historyId: "200", expiration: "2026-05-07T12:00:00.000Z" };
      },
      async fetchMessage(candidate) {
        return message(candidate.id);
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: [],
      }),
    },
    now: () => new Date("2026-05-06T12:00:00.000Z"),
  });

  const summary = await runtime.runOnce();

  assert.deepEqual(calls, ["history:100", "watch"]);
  assert.equal(summary.processed, 1);
  assert.equal(stateStore.getSourceCursor("primary")?.historyId, "200");
});

test("runtime status reports watch readiness", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.setSourceCursor("primary", {
    mode: "watch",
    historyId: "100",
    watchExpiresAt: "2026-05-06T12:30:00.000Z",
  });
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{
      id: "primary",
      accountEmail: "user@example.com",
      intakeMode: "watch",
      watchTopicName: "projects/example/topics/gmail",
    }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => {
      throw new Error("not used");
    },
    now: () => new Date("2026-05-06T12:00:00.000Z"),
  });

  const status = runtime.status() as { sources?: Array<{ readiness?: Record<string, unknown> }> };

  assert.equal(status.sources?.[0]?.readiness?.mode, "watch");
  assert.equal(status.sources?.[0]?.readiness?.historyCursorPresent, true);
  assert.equal(status.sources?.[0]?.readiness?.watchActive, true);
  assert.equal(status.sources?.[0]?.readiness?.watchNeedsRenewal, true);
});

test("runtime repairs stale Gmail history with bounded lookback poll", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.setSourceCursor("primary", { mode: "history", historyId: "old" });
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{
      id: "primary",
      accountEmail: "user@example.com",
      intakeMode: "history",
      candidateQuery: "in:inbox",
      historyLookback: "2d",
    }],
  });
  const queries: (string | undefined)[] = [];
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates(query) {
        queries.push(query);
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async listHistory() {
        const error = new Error("History ID too old");
        (error as Error & { code?: number }).code = 404;
        throw error;
      },
      async fetchMessage(candidate) {
        return message(candidate.id);
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: [],
      }),
    },
    now: () => new Date("2026-05-06T12:00:00.000Z"),
  });

  const summary = await runtime.runOnce();

  assert.equal(summary.processed, 1);
  assert.deepEqual(queries, ["in:inbox newer_than:2d"]);
});

test("runtime attaches bounded thread context before classification", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  let sawThreadContext = false;
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage(candidate) {
        return message(candidate.id);
      },
      async fetchThreadContext(threadId) {
        assert.equal(threadId, "thread-msg-1");
        return {
          threadId,
          participants: ["client@example.com", "user@example.com"],
          labels: ["INBOX"],
          messages: [{ messageId: "prior", from: "client@example.com", snippet: "Earlier safe context" }],
        };
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: {
      classify: async (normalized) => {
        sawThreadContext = normalized.threadContext?.messages[0]?.messageId === "prior";
        return safeSecurity;
      },
    },
    routerClassifier: {
      classify: async ({ message, normalized }) => {
        assert.equal(message.threadContext?.messages[0]?.messageId, "prior");
        assert.equal(normalized.threadContext?.participants.includes("client@example.com"), true);
        return {
          tags: [],
          wakeMode: "none",
          sanitizedSummary: "Safe runtime message.",
          reasons: [],
        };
      },
    },
  });

  const summary = await runtime.runOnce();

  assert.equal(summary.processed, 1);
  assert.equal(sawThreadContext, true);
});

test("backfill skips processed by default and force reprocesses", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  stateStore.markProcessed("primary", "msg-1", "2026-05-06T00:00:00.000Z");
  let fetchCount = 0;
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage() {
        fetchCount += 1;
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: [],
      }),
    },
  });

  const skipped = await runtime.runBackfill({ sourceId: "primary" });
  const forced = await runtime.runBackfill({ sourceId: "primary", force: true });

  assert.equal(skipped.skipped, 1);
  assert.equal(forced.processed, 1);
  assert.equal(fetchCount, 1);
});

test("backfill reports candidate listing errors without throwing", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        throw new Error("Gmail unavailable");
      },
      async fetchMessage() {
        return message("msg-1");
      },
      async applyLabel() {},
      async archive() {},
    }),
  });

  const summary = await runtime.runBackfill({ sourceId: "primary" });

  assert.equal(summary.sources, 1);
  assert.equal(summary.errors, 1);
  assert.equal(summary.events, 0);
});

test("runtime status and inspect expose safe operator state", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage(candidate) {
        return message(candidate.id);
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: [],
      }),
    },
    now: () => new Date("2026-05-06T12:00:00.000Z"),
  });

  await runtime.runOnce();
  const status = runtime.status() as { sources?: Array<{ stats?: Record<string, unknown>; readiness?: Record<string, unknown> }> };
  const inspection = runtime.inspectMessage("primary", "msg-1") as {
    processed?: boolean;
    events?: unknown[];
    decisions?: unknown[];
    latestActionStatuses?: unknown[];
    actionAttempts?: unknown[];
  };

  assert.equal(status.sources?.[0]?.stats?.processed, 1);
  assert.equal(status.sources?.[0]?.readiness?.authConfigured, false);
  assert.equal(status.sources?.[0]?.readiness?.canModifyGmail, true);
  assert.equal(inspection.processed, true);
  assert.equal(inspection.events?.length, 1);
  assert.equal(inspection.decisions?.length, 1);
  assert.equal(inspection.latestActionStatuses?.length, 1);
  assert.equal(inspection.actionAttempts?.length, 1);
});

test("runtime status reflects credential scope modify limits from cursor", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.setSourceCursor("primary", {
    credentialScopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  });
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => {
      throw new Error("not used");
    },
  });

  const status = runtime.status() as { sources?: Array<{ readiness?: Record<string, unknown> }> };

  assert.equal(status.sources?.[0]?.readiness?.configuredModifyScope, true);
  assert.equal(status.sources?.[0]?.readiness?.credentialModifyScope, false);
  assert.equal(status.sources?.[0]?.readiness?.canModifyGmail, false);
});

test("runtime status counts all pending aggregate rows", async (t) => {
  const stateStore = await tempStore(t);
  for (let index = 0; index < 3; index += 1) {
    stateStore.enqueueAggregate({
      sourceId: "primary",
      accountEmail: "user@example.com",
      messageId: `msg-${index}`,
      threadId: `thread-${index}`,
      tags: ["digest"],
      sanitizedSummary: "Digest item",
      queuedAt: "2026-05-05T00:00:00.000Z",
      cadence: "daily",
    });
  }
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    aggregate: { maxDigestItems: 1 },
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() { return []; },
      async fetchMessage() { return message("msg-1"); },
      async applyLabel() {},
      async archive() {},
    }),
  });

  const status = runtime.status() as { aggregate?: { pending?: number } };

  assert.equal(status.aggregate?.pending, 3);
});

test("runtime replay reprocesses stored intake event when forced", async (t) => {
  const stateStore = await tempStore(t);
  const config = resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  });
  let fetchCount = 0;
  const runtime = new GmailIntakePollingRuntime(config, {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() {
        return [{ id: "msg-1", threadId: "thread-msg-1" }];
      },
      async fetchMessage(candidate) {
        fetchCount += 1;
        return message(candidate.id);
      },
      async applyLabel() {},
      async archive() {},
    }),
    securityClassifier: { classify: async () => safeSecurity },
    routerClassifier: {
      classify: async () => ({
        tags: [],
        wakeMode: "none",
        sanitizedSummary: "Safe runtime message.",
        reasons: [],
      }),
    },
  });

  await runtime.runOnce();
  const skippedReplay = await runtime.replayEvent({ sourceId: "primary", messageId: "msg-1" });
  const forcedReplay = await runtime.replayEvent({ sourceId: "primary", messageId: "msg-1", force: true });

  assert.equal(skippedReplay.skipped, 1);
  assert.equal(forcedReplay.processed, 1);
  assert.equal(fetchCount, 2);
});

test("runtime replay reports client creation errors without throwing", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.recordEvent({
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-msg-1",
    eventType: "poll_candidate",
    observedAt: "2026-05-06T12:00:00.000Z",
  });
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    sources: [{ id: "primary", accountEmail: "user@example.com" }],
  }), {
    stateStore,
    gmailClientFactory: () => {
      throw new Error("Gmail credentials missing");
    },
  });

  const summary = await runtime.replayEvent({ sourceId: "primary", messageId: "msg-1", force: true });

  assert.equal(summary.sources, 1);
  assert.equal(summary.events, 1);
  assert.equal(summary.errors, 1);
});

test("aggregate drain delivers due digest and marks rows delivered", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.enqueueAggregate({
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-msg-1",
    tags: ["digest"],
    sanitizedSummary: "Digest item",
    queuedAt: "2026-05-05T00:00:00.000Z",
    wakeTarget: "agent:digest",
    cadence: "daily",
  });
  const wakes: string[] = [];
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: false,
    sqlitePath: stateStore.path,
    wakeTargets: [{ id: "agent:digest", agentId: "digest-agent" }],
  }), {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() { return []; },
      async fetchMessage() { return message("msg-1"); },
      async applyLabel() {},
      async archive() {},
    }),
    actionDeps: {
      wake: {
        async startDetachedAgentTurn(payload) {
          wakes.push(payload.messageId);
        },
      },
    },
  });

  const summary = await runtime.drainAggregates(new Date("2026-05-06T12:00:00.000Z"));

  assert.equal(summary.processed, 1);
  assert.deepEqual(wakes, ["digest:msg-1"]);
  assert.deepEqual(stateStore.listAggregateQueue(), []);
});

test("aggregate daily cadence uses configured timezone calendar boundary", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.enqueueAggregate({
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-msg-1",
    tags: ["digest"],
    sanitizedSummary: "Digest item",
    queuedAt: "2026-05-06T03:30:00.000Z",
    wakeTarget: "agent:digest",
    cadence: "daily",
  });
  const wakes: string[] = [];
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: false,
    sqlitePath: stateStore.path,
    wakeTargets: [{ id: "agent:digest", agentId: "digest-agent" }],
    aggregate: { timezone: "America/New_York" },
  }), {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() { return []; },
      async fetchMessage() { return message("msg-1"); },
      async applyLabel() {},
      async archive() {},
    }),
    actionDeps: {
      wake: {
        async startDetachedAgentTurn(payload) {
          wakes.push(payload.messageId);
        },
      },
    },
  });

  const beforeMidnight = await runtime.drainAggregates(new Date("2026-05-06T03:45:00.000Z"));
  const afterMidnight = await runtime.drainAggregates(new Date("2026-05-06T04:15:00.000Z"));

  assert.equal(beforeMidnight.processed, 0);
  assert.equal(afterMidnight.processed, 1);
  assert.deepEqual(wakes, ["digest:msg-1"]);
  assert.deepEqual(stateStore.listAggregateQueue(), []);
});

test("aggregate dry-run leaves due rows queued", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.enqueueAggregate({
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-msg-1",
    tags: ["digest"],
    sanitizedSummary: "Digest item",
    queuedAt: "2026-05-05T00:00:00.000Z",
    wakeTarget: "agent:digest",
    cadence: "daily",
  });
  let wakeCount = 0;
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: true,
    sqlitePath: stateStore.path,
    wakeTargets: [{ id: "agent:digest", agentId: "digest-agent" }],
  }), {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() { return []; },
      async fetchMessage() { return message("msg-1"); },
      async applyLabel() {},
      async archive() {},
    }),
    actionDeps: {
      wake: {
        async startDetachedAgentTurn() {
          wakeCount += 1;
        },
      },
    },
  });

  const summary = await runtime.drainAggregates(new Date("2026-05-06T12:00:00.000Z"));

  assert.equal(summary.processed, 1);
  assert.equal(wakeCount, 0);
  assert.deepEqual(stateStore.listAggregateQueue().map((item) => item.messageId), ["msg-1"]);
});

test("aggregate drain keeps rows queued when wake target is missing", async (t) => {
  const stateStore = await tempStore(t);
  stateStore.enqueueAggregate({
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-msg-1",
    tags: ["digest"],
    sanitizedSummary: "Digest item",
    queuedAt: "2026-05-05T00:00:00.000Z",
    wakeTarget: "missing-target",
    cadence: "daily",
  });
  const runtime = new GmailIntakePollingRuntime(resolvePluginConfig({
    dryRun: false,
    sqlitePath: stateStore.path,
  }), {
    stateStore,
    gmailClientFactory: () => ({
      async listCandidates() { return []; },
      async fetchMessage() { return message("msg-1"); },
      async applyLabel() {},
      async archive() {},
    }),
    actionDeps: {
      wake: {
        async startDetachedAgentTurn() {
          throw new Error("wake should not be attempted");
        },
      },
    },
  });

  const summary = await runtime.drainAggregates(new Date("2026-05-06T12:00:00.000Z"));

  assert.equal(summary.errors, 1);
  assert.deepEqual(stateStore.listAggregateQueue().map((item) => item.messageId), ["msg-1"]);
});
