import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { registerGmailIntakeFirewallPlugin } from "../src/plugin.js";

type CapturedService = {
  start(): Promise<Record<string, unknown>>;
  stop(): Promise<Record<string, unknown>>;
  probe(): Promise<Record<string, unknown>>;
  status(): Promise<Record<string, unknown>>;
  validateConfig(): Promise<Record<string, unknown>>;
  checkSourceAuth(options: Record<string, unknown>): Promise<Record<string, unknown>>;
  backfill(options: Record<string, unknown>): Promise<Record<string, unknown>>;
  inspectMessage(options: Record<string, unknown>): Promise<Record<string, unknown>>;
  replayEvent(options: Record<string, unknown>): Promise<Record<string, unknown>>;
};

test("plugin service exposes validation and status operator methods", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  registerGmailIntakeFirewallPlugin({
    config: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  const validation = await service.validateConfig();
  const start = await service.start();
  const status = await service.status();
  await service.stop();

  assert.equal(validation.ok, true);
  assert.equal(start.ok, true);
  assert.equal(status.started, true);
  assert.equal(Array.isArray(status.sources), true);
  assert.equal(Array.isArray(status.runtimeReadiness), true);
});

test("plugin prefers api.pluginConfig over api.config", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  registerGmailIntakeFirewallPlugin({
    config: {
      dryRun: true,
      sqlitePath: join(dir, "wrong.sqlite"),
      sources: [],
    },
    pluginConfig: {
      dryRun: true,
      sqlitePath: join(dir, "right.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  const status = await service.probe();

  assert.equal(status.configuredSources, 1);
  assert.equal(status.sqlitePath, join(dir, "right.sqlite"));
});

test("plugin registers read-only operator status tool when host supports tools", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let tool: { id: string; run(input: unknown): Promise<Record<string, unknown>> } | undefined;
  registerGmailIntakeFirewallPlugin({
    pluginConfig: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [],
    },
    registerTool(candidate: unknown) {
      tool = candidate as typeof tool;
    },
  });

  assert.ok(tool);
  assert.equal(tool.id, "gmail_intake_firewall_status");
  const result = await tool.run({ operation: "validateConfig" });
  assert.equal(result.ok, true);
  assert.equal(result.service, "gmail-intake-firewall-service");
});

test("plugin service and tool expose redacted source auth checks", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  let tool: { run(input: unknown): Promise<Record<string, unknown>> } | undefined;
  registerGmailIntakeFirewallPlugin({
    pluginConfig: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    secrets: {
      async resolveSecret() {
        return {
          refreshToken: "refresh-token",
          clientId: "client-id",
          clientSecret: "client-secret",
          scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
        };
      },
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
    registerTool(candidate: unknown) {
      tool = candidate as typeof tool;
    },
  });

  assert.ok(service);
  assert.ok(tool);
  const serviceResult = await service.checkSourceAuth({ sourceId: "primary" });
  const toolResult = await tool.run({ operation: "checkSourceAuth", sourceId: "primary" });
  const first = (serviceResult.sources as Array<Record<string, unknown>>)[0];

  assert.equal(serviceResult.ok, true);
  assert.equal(toolResult.ok, true);
  assert.equal(first?.ok, true);
  assert.equal(first?.hasRefreshToken, true);
  assert.equal(first?.configuredModifyScope, true);
  assert.equal(first?.credentialModifyScope, false);
  assert.equal(first?.canModifyGmail, false);
  assert.equal("refreshToken" in first!, false);
  assert.deepEqual(first?.scopes, ["https://www.googleapis.com/auth/gmail.readonly"]);
});

test("plugin source auth check fails for unimplemented DWD", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  registerGmailIntakeFirewallPlugin({
    pluginConfig: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    secrets: {
      async resolveSecret() {
        return {
          tokenType: "workspace_domain_wide_delegation",
          refreshToken: "refresh-token",
          clientId: "client-id",
          clientSecret: "client-secret",
          scopes: ["https://www.googleapis.com/auth/gmail.modify"],
        };
      },
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  const result = await service.checkSourceAuth({ sourceId: "primary" });
  const first = (result.sources as Array<Record<string, unknown>>)[0];

  assert.equal(result.ok, false);
  assert.equal(first?.ok, false);
  assert.equal(first?.tokenType, "workspace_domain_wide_delegation");
  assert.match(String(first?.error), /not implemented/);
});

test("plugin service rejects unbounded backfill unless explicitly allowed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  registerGmailIntakeFirewallPlugin({
    config: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  await service.start();
  await assert.rejects(() => service!.backfill({ sourceId: "primary" }), /query or maxResults/);
  await service.stop();
});

test("plugin service exposes inspect and replay argument validation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  registerGmailIntakeFirewallPlugin({
    config: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      OPENAI_API_KEY: "test-key",
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    secrets: {
      async resolveSecret() {
        return {
          refreshToken: "refresh-token",
          clientId: "client-id",
          clientSecret: "client-secret",
        };
      },
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  await service.start();
  const inspection = await service.inspectMessage({ sourceId: "primary", messageId: "missing" });
  const replay = await service.replayEvent({ sourceId: "primary", messageId: "missing", force: true });
  await assert.rejects(() => service!.inspectMessage({ sourceId: "primary" }), /sourceId and messageId/);
  await assert.rejects(() => service!.replayEvent({ messageId: "missing" }), /sourceId and messageId/);
  await service.stop();

  assert.equal(inspection.ok, true);
  assert.equal(replay.skipped, 1);
});

test("plugin service reports runtime readiness problems", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  registerGmailIntakeFirewallPlugin({
    config: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
      }],
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  const start = await service.start();
  const status = await service.status();
  await service.stop();

  assert.equal(start.ok, true);
  assert.equal(Array.isArray(start.runtimeReadiness), true);
  assert.equal((start.runtimeReadiness as unknown[]).length > 0, true);
  assert.equal(Array.isArray(status.runtimeReadiness), true);
});
