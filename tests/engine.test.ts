import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildDigestWake } from "../src/aggregate.js";
import { executePlannedActions } from "../src/actions.js";
import { resolvePluginConfig } from "../src/config.js";
import { processMessage } from "../src/engine.js";
import { createEmptyState, openSqliteStateStore } from "../src/state.js";
import type { InboundMessage, PluginConfig, RoutingClassification, SecurityClassification } from "../src/types.js";

const baseMessage: InboundMessage = {
  sourceId: "primary",
  accountEmail: "user@example.com",
  messageId: "msg-1",
  threadId: "thread-1",
  headers: {},
  rawHeaders: [],
  from: "client@example.com",
  to: ["user@example.com"],
  cc: [],
  bcc: [],
  subject: "Client dev question",
  labels: ["INBOX"],
  snippet: "Can you review this implementation question?",
  bodyText: "Can you review this implementation question?",
  attachments: [],
};

function config(overrides: Partial<PluginConfig> = {}): PluginConfig {
  return {
    ...resolvePluginConfig({
      dryRun: true,
      security: {
        quarantineLabel: "OpenClaw/Quarantine",
        failClosedOnUncertain: true,
        maliciousThreshold: 0.65,
        uncertainThreshold: 0.35,
        alertTarget: "slack:#security",
        archiveOnQuarantine: true,
      },
      sources: [
        {
          id: "primary",
          accountEmail: "user@example.com",
          gmailActions: {
            hasModifyScope: true,
          },
        },
      ],
      alertSinks: [
        {
          id: "local",
          kind: "local_log",
          enabled: true,
        },
        {
          id: "security",
          kind: "slack",
          target: "slack:#security",
          enabled: true,
        },
      ],
      tags: [
        {
          id: "client-dev",
          description: "Client development work",
          gmailLabel: "OpenClaw/ClientDev",
          wakeMode: "wake_now",
          wakeTarget: "agent:dev",
        },
        {
          id: "digest",
          description: "Digest item",
          gmailLabel: "OpenClaw/Digest",
          wakeMode: "aggregate",
          aggregateCadence: "daily",
          wakeTarget: "agent:digest",
        },
      ],
      wakeTargets: [
        {
          id: "agent:dev",
          agentId: "dev-agent",
          workspaceDir: "/workspace",
        },
        {
          id: "agent:digest",
          agentId: "digest-agent",
          workspaceDir: "/workspace",
        },
      ],
    }),
    ...overrides,
  };
}

function security(result: SecurityClassification) {
  return { classify: async () => result };
}

function router(result: RoutingClassification) {
  return { classify: async () => result };
}

test("safe client-dev email gets tagged and wake_now", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0.01,
      categories: [],
      reasons: ["Known client request"],
      safeSummary: "Client asks about implementation.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      wakeTarget: "agent:dev",
      sanitizedSummary: "Client asks about implementation.",
      reasons: ["Matches client-dev"],
    }),
  });

  assert.equal(result.skipped, false);
  assert.deepEqual(result.decision?.actions.map((action) => action.type), ["gmail_label", "agent_wake"]);
  const wake = result.decision?.actions.find((action) => action.type === "agent_wake");
  assert.equal(wake?.type, "agent_wake");
  assert.equal(wake?.payload.sanitizedSummary, "Client asks about implementation.");
  assert.equal(wake?.payload.wakeTarget?.agentId, "dev-agent");
  assert.equal(wake?.payload.security.riskScore, 0.01);
  assert.equal("bodyText" in wake.payload, false);
});

test("artifact analysis is attached to decisions and sanitized wake payloads", async () => {
  const message: InboundMessage = {
    ...baseMessage,
    bodyText: "Please verify this invoice at http://bit.ly/login-reset",
    linkUrls: ["http://bit.ly/login-reset"],
    attachments: [
      { id: "att-1", filename: "invoice.pdf.exe", mimeType: "application/pdf", size: 42 },
    ],
  };
  const result = await processMessage(message, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0.1,
      categories: [],
      reasons: ["safe enough for fixture"],
      safeSummary: "Client sent an invoice link and attachment.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      wakeTarget: "agent:dev",
      sanitizedSummary: "Client sent an invoice link and attachment.",
      reasons: ["Matches client-dev"],
    }),
  });

  assert.ok(result.decision?.artifactAnalysis?.links[0]?.riskHints.includes("url_shortener"));
  assert.ok(result.decision?.artifactAnalysis?.attachments[0]?.riskHints.includes("executable_attachment"));
  const wake = result.decision?.actions.find((action) => action.type === "agent_wake");
  assert.equal(wake?.type, "agent_wake");
  assert.equal(wake.payload.artifacts?.linkCount, 1);
  assert.deepEqual(wake.payload.artifacts?.linkDomains, ["bit.ly"]);
  assert.ok(wake.payload.artifacts?.attachmentRiskHints.includes("executable_attachment"));
  assert.equal("bodyText" in wake.payload, false);
});

test("prompt injection email is quarantined and not normally woken", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "risky",
      riskScore: 0.98,
      categories: ["prompt_injection"],
      reasons: ["Attempts to override the agent runtime"],
      safeSummary: "Message contains prompt injection targeting the agent.",
      suspiciousSignals: ["ignore previous instructions"],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      sanitizedSummary: "Should not run",
      reasons: [],
    }),
  });

  assert.equal(result.decision?.routing, undefined);
  assert.deepEqual(result.decision?.actions.map((action) => action.type), [
    "gmail_label",
    "gmail_archive",
    "local_log",
    "human_alert",
  ]);
  const alert = result.decision?.actions.find((action) => action.type === "human_alert");
  assert.equal(alert?.type, "human_alert");
  assert.equal(alert.payload && "snippet" in alert.payload, false);
});

test("suspicious alert payload can include Gmail snippet when explicitly enabled", async () => {
  const result = await processMessage(baseMessage, config({
    security: {
      ...config().security,
      includeSnippetInAlerts: true,
    },
  }), createEmptyState(), {
    securityClassifier: security({
      verdict: "risky",
      riskScore: 0.98,
      categories: ["prompt_injection"],
      reasons: ["Attempts to override the agent runtime"],
      safeSummary: "Message contains prompt injection targeting the agent.",
      suspiciousSignals: ["ignore previous instructions"],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      sanitizedSummary: "Should not run",
      reasons: [],
    }),
  });

  const alert = result.decision?.actions.find((action) => action.type === "human_alert");

  assert.equal(alert?.type, "human_alert");
  assert.equal(alert.payload?.snippet, baseMessage.snippet);
});

test("irrelevant safe email records state without wake", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Newsletter.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: [],
      wakeMode: "none",
      sanitizedSummary: "Newsletter.",
      reasons: ["No configured tag"],
    }),
  });

  assert.deepEqual(result.decision?.actions, [{ type: "record_only", reason: "safe_message_no_wake" }]);
});

test("mute sender preference changes future safe routing to none", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    routingPreferences: [{
      type: "mute",
      scope: "sender",
      sourceId: "primary",
      value: "client@example.com",
      createdAt: "2026-05-06T12:00:00.000Z",
    }],
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0.01,
      categories: [],
      reasons: ["safe"],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      wakeTarget: "agent:dev",
      sanitizedSummary: "Would wake.",
      reasons: ["router"],
    }),
  });

  assert.equal(result.decision?.routing?.wakeMode, "none");
  assert.deepEqual(result.decision?.actions, [{ type: "record_only", reason: "safe_message_no_wake" }]);
});

test("sender preference does not bypass risky quarantine", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    routingPreferences: [{
      type: "mute",
      scope: "sender",
      sourceId: "primary",
      value: "client@example.com",
      createdAt: "2026-05-06T12:00:00.000Z",
    }],
    securityClassifier: security({
      verdict: "risky",
      riskScore: 0.98,
      categories: ["phishing"],
      reasons: ["credential theft"],
      safeSummary: "Risky.",
      suspiciousSignals: ["fake login"],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      sanitizedSummary: "Should not route.",
      reasons: [],
    }),
  });

  assert.equal(result.decision?.routing, undefined);
  assert.deepEqual(result.decision?.actions.map((action) => action.type), [
    "gmail_label",
    "gmail_archive",
    "local_log",
    "human_alert",
  ]);
});

test("domain always-aggregate preference changes future safe routing to aggregate", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    routingPreferences: [{
      type: "always_aggregate",
      scope: "domain",
      sourceId: "primary",
      value: "example.com",
      createdAt: "2026-05-06T12:00:00.000Z",
    }],
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0.01,
      categories: [],
      reasons: ["safe"],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      wakeTarget: "agent:dev",
      sanitizedSummary: "Would wake.",
      reasons: ["router"],
    }),
  });

  assert.equal(result.decision?.routing?.wakeMode, "aggregate");
  assert.ok(result.decision?.routing?.tags.includes("digest"));
  assert.deepEqual(result.decision?.actions.map((action) => action.type), ["gmail_label", "aggregate_enqueue"]);
});

test("aggregate email is queued and can be included in a digest wake", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Digest candidate.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: ["digest"],
      wakeMode: "aggregate",
      wakeTarget: "agent:digest",
      sanitizedSummary: "Digest candidate.",
      reasons: ["Matches digest"],
    }),
  });

  assert.equal(result.state.aggregateQueue.length, 1);
  const digest = buildDigestWake(result.state.aggregateQueue, "agent:digest");
  assert.match(digest?.sanitizedSummary ?? "", /Digest candidate/);
});

test("same source/message id is not processed twice", async () => {
  const deps = {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: [],
      wakeMode: "none" as const,
      sanitizedSummary: "Safe.",
      reasons: [],
    }),
  };
  const first = await processMessage(baseMessage, config(), createEmptyState(), deps);
  const second = await processMessage(baseMessage, config(), first.state, deps);
  assert.equal(first.skipped, false);
  assert.equal(second.skipped, true);
  assert.equal(second.decision, undefined);
});

test("dry-run records intended actions without changing action plan", async () => {
  const result = await processMessage(baseMessage, config({ dryRun: true }), createEmptyState(), {
    securityClassifier: security({
      verdict: "risky",
      riskScore: 0.99,
      categories: ["phishing"],
      reasons: ["Credential theft"],
      safeSummary: "Likely credential theft.",
      suspiciousSignals: ["fake login"],
    }),
    routerClassifier: router({
      tags: [],
      wakeMode: "none",
      sanitizedSummary: "",
      reasons: [],
    }),
  });

  assert.equal(result.decision?.dryRun, true);
  assert.deepEqual(result.decision?.actions.map((action) => action.type), [
    "gmail_label",
    "gmail_archive",
    "local_log",
    "human_alert",
  ]);
});

test("dry-run executor performs no Gmail Slack or wake side effects", async () => {
  const calls: string[] = [];
  await executePlannedActions(
    [
      { type: "gmail_label", label: "x", messageId: "msg-1" },
      { type: "gmail_archive", messageId: "msg-1" },
      { type: "human_alert", sink: "slack", target: "slack:#security", summary: "alert" },
      {
        type: "agent_wake",
        payload: {
          sourceId: "primary",
          accountEmail: "user@example.com",
          messageId: "msg-1",
          threadId: "thread-1",
          tags: [],
          sanitizedSummary: "summary",
          security: {
            verdict: "safe",
            riskScore: 0,
            categories: [],
            reasons: [],
            safeSummary: "safe",
            suspiciousSignals: [],
          },
        },
      },
    ],
    {
      dryRun: true,
      actions: config().actions,
      source: config().sources[0],
    },
    {
      gmail: {
        applyLabel: async () => { calls.push("label"); },
        archive: async () => { calls.push("archive"); },
      },
      slack: {
        postAlert: async () => { calls.push("slack"); },
      },
      wake: {
        startDetachedAgentTurn: async () => { calls.push("wake"); },
      },
    },
  );
  assert.deepEqual(calls, []);
});

test("action modes gate live execution independently of global dryRun", async () => {
  const calls: string[] = [];
  const baseConfig = config({ dryRun: false });
  const results = await executePlannedActions(
    [
      { type: "gmail_label", label: "OpenClaw/Test", messageId: "msg-1" },
      { type: "gmail_archive", messageId: "msg-1" },
      { type: "local_log", summary: "local" },
    ],
    {
      dryRun: false,
      actions: {
        ...baseConfig.actions,
        gmail: {
          ...baseConfig.actions.gmail,
          label: { mode: "live" },
          archive: { mode: "disabled" },
        },
        local: {
          log: { mode: "live" },
        },
      },
      source: baseConfig.sources[0],
    },
    {
      gmail: {
        applyLabel: async () => { calls.push("label"); },
        archive: async () => { calls.push("archive"); },
      },
      localLog: {
        write: async () => { calls.push("local"); },
      },
    },
  );

  assert.deepEqual(calls, ["label", "local"]);
  assert.deepEqual(results.map((result) => result.status), ["succeeded", "disabled", "succeeded"]);
});

test("global dryRun overrides live action modes", async () => {
  const calls: string[] = [];
  const baseConfig = config({ dryRun: true });
  const results = await executePlannedActions(
    [
      { type: "gmail_label", label: "OpenClaw/Test", messageId: "msg-1" },
      { type: "human_alert", sink: "slack", target: "slack:#security", summary: "alert" },
      { type: "local_log", summary: "local" },
      {
        type: "agent_wake",
        payload: {
          sourceId: "primary",
          accountEmail: "user@example.com",
          messageId: "msg-1",
          threadId: "thread-1",
          tags: [],
          sanitizedSummary: "summary",
          security: {
            verdict: "safe",
            riskScore: 0,
            categories: [],
            reasons: [],
            safeSummary: "safe",
            suspiciousSignals: [],
          },
        },
      },
    ],
    {
      dryRun: true,
      actions: {
        gmail: {
          label: { mode: "live" },
          archive: { mode: "live" },
          removeLabel: { mode: "live" },
          restoreInbox: { mode: "live" },
        },
        slack: { alert: { mode: "live" } },
        wake: {
          agent: { mode: "live" },
          aggregate: { mode: "live" },
        },
        local: { log: { mode: "live" } },
      },
      source: baseConfig.sources[0],
    },
    {
      gmail: {
        applyLabel: async () => { calls.push("label"); },
        archive: async () => { calls.push("archive"); },
      },
      slack: {
        postAlert: async () => { calls.push("slack"); },
      },
      localLog: {
        write: async () => { calls.push("local"); },
      },
      wake: {
        startDetachedAgentTurn: async () => { calls.push("wake"); },
      },
    },
  );

  assert.deepEqual(calls, []);
  assert.deepEqual(results.map((result) => result.status), [
    "skipped_dry_run",
    "skipped_dry_run",
    "skipped_dry_run",
    "skipped_dry_run",
  ]);
});

test("live local log fails when executor is missing", async () => {
  const baseConfig = config({ dryRun: false });
  const results = await executePlannedActions(
    [{ type: "local_log", summary: "local" }],
    {
      dryRun: false,
      actions: {
        ...baseConfig.actions,
        local: { log: { mode: "live" } },
      },
      source: baseConfig.sources[0],
    },
    {},
  );

  assert.equal(results[0]?.status, "failed");
  assert.match(results[0]?.error ?? "", /Local log executor is not configured/);
});

test("record-only and aggregate enqueue are not gated by local log mode", async () => {
  const baseConfig = config({ dryRun: false });
  const results = await executePlannedActions(
    [
      { type: "record_only", reason: "safe_message_no_wake" },
      {
        type: "aggregate_enqueue",
        item: {
          sourceId: "primary",
          accountEmail: "user@example.com",
          messageId: "msg-1",
          threadId: "thread-1",
          tags: ["newsletter"],
          sanitizedSummary: "summary",
          queuedAt: "2026-05-06T12:00:00.000Z",
        },
      },
    ],
    {
      dryRun: false,
      actions: {
        ...baseConfig.actions,
        local: { log: { mode: "disabled" } },
      },
      source: baseConfig.sources[0],
    },
    {},
  );

  assert.deepEqual(results.map((result) => result.status), ["succeeded", "succeeded"]);
});

test("multiple sources do not leak idempotency state", async () => {
  const deps = {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: [],
      wakeMode: "none" as const,
      sanitizedSummary: "Safe.",
      reasons: [],
    }),
  };
  const first = await processMessage(baseMessage, config(), createEmptyState(), deps);
  const otherSource = { ...baseMessage, sourceId: "secondary", accountEmail: "other@example.com" };
  const multiSourceConfig = config({
    sources: [
      {
        id: "primary",
        accountEmail: "user@example.com",
        enabled: true,
        polling: { intervalMs: 60000, maxResults: 25 },
        gmailActions: { hasModifyScope: true },
      },
      {
        id: "secondary",
        accountEmail: "other@example.com",
        enabled: true,
        polling: { intervalMs: 60000, maxResults: 25 },
        gmailActions: { hasModifyScope: true },
      },
    ],
  });
  const second = await processMessage(otherSource, multiSourceConfig, first.state, deps);
  assert.equal(second.skipped, false);
  assert.equal(second.state.decisions.length, 2);
});

test("disabled plugin source and unknown source are skipped", async () => {
  const deps = {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: [],
      wakeMode: "none" as const,
      sanitizedSummary: "Safe.",
      reasons: [],
    }),
  };

  assert.equal(
    (await processMessage(baseMessage, config({ enabled: false }), createEmptyState(), deps)).skipReason,
    "plugin_disabled",
  );
  assert.equal(
    (await processMessage({ ...baseMessage, sourceId: "missing" }, config(), createEmptyState(), deps)).skipReason,
    "unknown_source",
  );
  assert.equal(
    (await processMessage(
      baseMessage,
      config({
        sources: [
          {
            id: "primary",
            accountEmail: "user@example.com",
            enabled: false,
            polling: { intervalMs: 60000, maxResults: 25 },
            gmailActions: { hasModifyScope: true },
          },
        ],
      }),
      createEmptyState(),
      deps,
    )).skipReason,
    "source_disabled",
  );
});

test("router output cannot wake without configured tag policy and target", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    }),
    routerClassifier: router({
      tags: ["unknown-tag"],
      wakeMode: "wake_now",
      wakeTarget: "unconfigured-target",
      sanitizedSummary: "Attempted invalid wake.",
      reasons: ["Classifier tried to wake without configured policy"],
    }),
  });

  assert.deepEqual(result.decision?.actions, [{ type: "record_only", reason: "safe_message_no_wake" }]);
});

test("uncertain classification quarantines by default", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "uncertain",
      riskScore: 0.1,
      categories: ["ambiguous_sender"],
      reasons: ["Cannot verify sender intent"],
      safeSummary: "Uncertain sender intent.",
      suspiciousSignals: ["ambiguous_sender"],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      sanitizedSummary: "Should not run",
      reasons: [],
    }),
  });

  assert.equal(result.decision?.routing, undefined);
  assert.ok(result.decision?.actions.some((action) => action.type === "gmail_label"));
  assert.ok(result.decision?.actions.some((action) => action.type === "human_alert"));
});

test("malicious classification quarantines before routing", async () => {
  const result = await processMessage(baseMessage, config(), createEmptyState(), {
    securityClassifier: security({
      verdict: "malicious",
      riskScore: 0.99,
      categories: ["credential_theft"],
      reasons: ["Fake login link"],
      safeSummary: "Credential theft attempt.",
      suspiciousSignals: ["fake login"],
    }),
    routerClassifier: router({
      tags: ["client-dev"],
      wakeMode: "wake_now",
      sanitizedSummary: "Should not run",
      reasons: [],
    }),
  });

  assert.equal(result.decision?.routing, undefined);
  assert.ok(result.decision?.actions.some((action) => action.type === "gmail_label"));
  assert.ok(result.decision?.actions.some((action) => action.type === "human_alert"));
});

test("read-only Gmail scope degrades to alert and log without label/archive", async () => {
  const readonlyConfig = config({
    sources: [
      {
        id: "primary",
        accountEmail: "user@example.com",
        enabled: true,
        polling: { intervalMs: 60000, maxResults: 25 },
        gmailActions: {
          hasModifyScope: false,
        },
      },
    ],
  });
  const result = await processMessage(baseMessage, readonlyConfig, createEmptyState(), {
    securityClassifier: security({
      verdict: "risky",
      riskScore: 0.99,
      categories: ["phishing"],
      reasons: ["Credential theft"],
      safeSummary: "Likely credential theft.",
      suspiciousSignals: ["fake login"],
    }),
    routerClassifier: router({
      tags: [],
      wakeMode: "none",
      sanitizedSummary: "",
      reasons: [],
    }),
  });

  assert.deepEqual(result.decision?.actions.map((action) => action.type), ["local_log", "human_alert"]);
});

test("sqlite state stores idempotency, decisions, and aggregate queue", async (t) => {
  let store;
  try {
    const dir = await mkdtemp(join(tmpdir(), "gmail-intake-firewall-"));
    store = openSqliteStateStore(join(dir, "state.sqlite"));
  } catch (error) {
    t.skip(`sqlite unavailable: ${String(error)}`);
    return;
  }
  t.after(() => store?.close());

  store.recordDecision({
    processedAt: "2026-05-06T00:00:00.000Z",
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-sqlite",
    threadId: "thread-sqlite",
    security: {
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: [],
      safeSummary: "Safe.",
      suspiciousSignals: [],
    },
    actions: [
      {
        type: "aggregate_enqueue",
        item: {
          sourceId: "primary",
          accountEmail: "user@example.com",
          messageId: "msg-sqlite",
          threadId: "thread-sqlite",
          tags: ["digest"],
          sanitizedSummary: "Digest item.",
          queuedAt: "2026-05-06T00:00:00.000Z",
          wakeTarget: "agent:digest",
        },
      },
    ],
    dryRun: true,
  });

  assert.equal(store.isProcessed("primary", "msg-sqlite"), true);
  assert.equal(store.listAggregateQueue().length, 1);
});

test("sqlite state stores feedback events", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-state-"));
  const store = openSqliteStateStore(join(dir, "state.sqlite"));
  t.after(() => store.close());

  store.recordFeedback({
    createdAt: "2026-05-06T12:00:00.000Z",
    sourceId: "primary",
    messageId: "msg-1",
    threadId: "thread-1",
    feedbackType: "wrong_tag",
    selectedTag: "newsletter",
  });

  assert.equal(store.listFeedbackEvents()[0]?.feedbackType, "wrong_tag");
  assert.equal((store.listFeedbackEvents()[0]?.payload as Record<string, unknown> | undefined)?.selectedTag, "newsletter");
});
