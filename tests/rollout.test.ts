import assert from "node:assert/strict";
import test from "node:test";
import { resolvePluginConfig } from "../src/config.js";
import { buildRolloutReadiness } from "../src/rollout.js";

const liveActions = {
  gmail: {
    label: { mode: "live" },
    archive: { mode: "live" },
    removeLabel: { mode: "live" },
    restoreInbox: { mode: "live" },
  },
  slack: {
    alert: { mode: "live" },
  },
  wake: {
    agent: { mode: "live" },
    aggregate: { mode: "live" },
  },
  local: {
    log: { mode: "live" },
  },
};

function auth(ok = true): Record<string, unknown> {
  return {
    ok,
    sources: [{
      sourceId: "primary",
      enabled: true,
      ok,
      hasRefreshToken: ok,
      hasClientId: ok,
      hasClientSecret: ok,
      configuredModifyScope: true,
      credentialModifyScope: ok,
      canModifyGmail: ok,
      scopes: ok ? ["https://www.googleapis.com/auth/gmail.modify"] : [],
    }],
  };
}

function status(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    started: true,
    sources: [{
      id: "primary",
      enabled: true,
      intakeMode: "poll",
      readiness: {
        mode: "poll",
        authConfigured: true,
        configuredModifyScope: true,
        credentialModifyScope: true,
        canModifyGmail: true,
      },
      lastPoll: {
        status: "succeeded",
        stage: "cursor_update",
      },
      ...overrides,
    }],
  };
}

test("rollout readiness is blocked by config/auth/action errors", () => {
  const config = resolvePluginConfig({
    dryRun: false,
    actions: liveActions,
    sources: [{
      id: "primary",
      accountEmail: "user@example.com",
      authRef: { source: "env", provider: "env", id: "GMAIL_PRIMARY_OAUTH_JSON" },
      gmailActions: { hasModifyScope: true },
    }],
    alertSinks: [],
    wakeTargets: [],
  });

  const rollout = buildRolloutReadiness({
    config,
    validation: [{ severity: "error", path: "tags.client.wakeTarget", message: "Tag references unknown wake target." }],
    status: status(),
    auth: auth(false),
  });

  assert.equal(rollout.verdict, "blocked");
  assert.ok(rollout.summary.errorCount >= 1);
  assert.equal(rollout.actions.gmail.label.ready, false);
  assert.equal(rollout.actions.slack.alert.ready, false);
  assert.equal(rollout.actions.wake.agent.ready, false);
  assert.ok(rollout.suggestedOperations.includes("validateConfig"));
  assert.ok(rollout.suggestedOperations.includes("checkSourceAuth"));
});

test("rollout readiness is caution when dry-run or watch setup remains", () => {
  const config = resolvePluginConfig({
    dryRun: true,
    actions: liveActions,
    sources: [{
      id: "primary",
      accountEmail: "user@example.com",
      authRef: { source: "env", provider: "env", id: "GMAIL_PRIMARY_OAUTH_JSON" },
      intakeMode: "watch",
      watchTopicName: "projects/example/topics/gmail",
      gmailActions: { hasModifyScope: true },
    }],
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
    wakeTargets: [{ id: "agent:digest", agentId: "digest" }],
  });

  const rollout = buildRolloutReadiness({
    config,
    validation: [],
    status: status({
      intakeMode: "watch",
      readiness: {
        mode: "watch",
        authConfigured: true,
        configuredModifyScope: true,
        credentialModifyScope: true,
        canModifyGmail: true,
        watchTopicConfigured: true,
        historyCursorPresent: false,
        watchActive: false,
        watchNeedsRenewal: true,
      },
    }),
    auth: auth(true),
  });

  assert.equal(rollout.verdict, "caution");
  assert.equal(rollout.actions.gmail.label.effective, "dry_run");
  assert.ok(rollout.suggestedOperations.includes("setupWatch:primary"));
  assert.ok(rollout.suggestedOperations.includes("renewWatch:primary"));
});

test("rollout readiness is ready when auth, actions, and sources are live-ready", () => {
  const config = resolvePluginConfig({
    dryRun: false,
    actions: liveActions,
    sources: [{
      id: "primary",
      accountEmail: "user@example.com",
      authRef: { source: "env", provider: "env", id: "GMAIL_PRIMARY_OAUTH_JSON" },
      gmailActions: { hasModifyScope: true },
    }],
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
    wakeTargets: [{ id: "agent:digest", agentId: "digest" }],
  });

  const rollout = buildRolloutReadiness({
    config,
    validation: [],
    status: status(),
    auth: auth(true),
  });

  assert.equal(rollout.verdict, "ready");
  assert.equal(rollout.summary.errorCount, 0);
  assert.equal(rollout.summary.warningCount, 0);
  assert.equal(rollout.actions.gmail.label.ready, true);
  assert.equal(rollout.actions.slack.alert.ready, true);
  assert.equal(rollout.actions.wake.aggregate.ready, true);
  assert.ok(rollout.productionChecklist.every((item) => item.status === "pass"));
});

test("rollout readiness ignores disabled sources for auth and watch gates", () => {
  const primaryStatusSource = (status().sources as Array<Record<string, unknown>>)[0];
  const primaryAuthSource = (auth(true).sources as Array<Record<string, unknown>>)[0];
  const config = resolvePluginConfig({
    dryRun: false,
    actions: liveActions,
    sources: [
      {
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "env", provider: "env", id: "GMAIL_PRIMARY_OAUTH_JSON" },
        gmailActions: { hasModifyScope: true },
      },
      {
        id: "disabled",
        accountEmail: "disabled@example.com",
        authRef: { source: "env", provider: "env", id: "DISABLED_GMAIL_AUTH" },
        enabled: false,
        intakeMode: "watch",
        watchTopicName: "projects/example/topics/gmail",
      },
    ],
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
    wakeTargets: [{ id: "agent:digest", agentId: "digest" }],
  });

  const rollout = buildRolloutReadiness({
    config,
    validation: [],
    status: {
      started: true,
      sources: [
        primaryStatusSource,
        {
          id: "disabled",
          enabled: false,
          intakeMode: "watch",
          readiness: {
            mode: "watch",
            watchTopicConfigured: false,
            historyCursorPresent: false,
          },
        },
      ],
    },
    auth: {
      ok: false,
      sources: [
        primaryAuthSource,
        {
          sourceId: "disabled",
          enabled: false,
          ok: false,
          canModifyGmail: false,
        },
      ],
    },
  });

  assert.equal(rollout.verdict, "ready");
  assert.equal(rollout.actions.gmail.label.ready, true);
  assert.equal(rollout.productionChecklist.find((item) => item.id === "auth-ready")?.status, "pass");
  assert.equal(rollout.productionChecklist.find((item) => item.id === "watch-ready")?.status, "pass");
});

test("rollout readiness blocks production with no enabled sources", () => {
  const config = resolvePluginConfig({
    dryRun: false,
    actions: liveActions,
    sources: [{
      id: "disabled",
      accountEmail: "disabled@example.com",
      authRef: { source: "env", provider: "env", id: "DISABLED_GMAIL_AUTH" },
      enabled: false,
    }],
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
    wakeTargets: [{ id: "agent:digest", agentId: "digest" }],
  });

  const rollout = buildRolloutReadiness({
    config,
    validation: [],
    status: {
      started: true,
      sources: [{
        id: "disabled",
        enabled: false,
        intakeMode: "poll",
        readiness: {
          mode: "poll",
          canModifyGmail: false,
        },
      }],
    },
    auth: {
      ok: false,
      sources: [{
        sourceId: "disabled",
        enabled: false,
        ok: false,
        canModifyGmail: false,
      }],
    },
  });

  assert.equal(rollout.verdict, "blocked");
  assert.equal(rollout.productionChecklist.find((item) => item.id === "enabled-sources")?.status, "fail");
  assert.equal(rollout.findings.some((finding) => finding.path === "sources"), true);
});
