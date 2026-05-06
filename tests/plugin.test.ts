import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
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
  handleGmailNotification(options: Record<string, unknown>): Promise<Record<string, unknown>>;
};
type CapturedHttpRoute = {
  id: string;
  path: string;
  auth: string;
  match: string;
  handler(req: unknown, res: unknown): Promise<boolean>;
};

function jsonRequest(body: unknown, headers: Record<string, string> = {}, url = "/gmail-intake-firewall/pubsub"): unknown {
  const req = Readable.from([JSON.stringify(body)]) as Readable & {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
  };
  req.method = "POST";
  req.url = url;
  req.headers = headers;
  return req;
}

function mockResponse(): { res: unknown; statusCode: number | undefined; headers: Record<string, string>; body: string | undefined } {
  const response: { res: unknown; statusCode: number | undefined; headers: Record<string, string>; body: string | undefined } = {
    headers: {},
    body: undefined,
    statusCode: undefined,
    res: undefined,
  };
  response.res = {
    get statusCode() {
      return response.statusCode;
    },
    set statusCode(value: number | undefined) {
      response.statusCode = value;
    },
    setHeader(key: string, value: string) {
      response.headers[key.toLowerCase()] = value;
    },
    end(body: string) {
      response.body = body;
    },
  };
  return response;
}

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
  assert.deepEqual(status.httpRoute, {
    id: "gmail-intake-firewall-pubsub",
    path: "/gmail-intake-firewall/pubsub",
    auth: "plugin",
    match: "exact",
    webhookSecretConfigured: false,
    routeActivationHint: "gateway-webhook",
  });
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
  let toolOptions: Record<string, unknown> | undefined;
  registerGmailIntakeFirewallPlugin({
    pluginConfig: {
      dryRun: true,
      sqlitePath: join(dir, "state.sqlite"),
      sources: [],
    },
    registerTool(candidate: unknown, options?: Record<string, unknown>) {
      tool = candidate as typeof tool;
      toolOptions = options;
    },
  });

  assert.ok(tool);
  assert.equal(tool.id, "gmail_intake_firewall_status");
  assert.deepEqual(toolOptions, { name: "gmail_intake_firewall_status" });
  const result = await tool.run({ operation: "validateConfig" });
  assert.equal(result.ok, true);
  assert.equal(result.service, "gmail-intake-firewall-service");
});

test("plugin registers authenticated Pub/Sub HTTP route", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let route: CapturedHttpRoute | undefined;
  registerGmailIntakeFirewallPlugin({
    pluginConfig: {
      dryRun: true,
      webhookSecret: "secret",
      sqlitePath: join(dir, "state.sqlite"),
      sources: [],
    },
    registerHttpRoute(candidate: unknown) {
      route = candidate as CapturedHttpRoute;
    },
  });

  assert.ok(route);
  assert.equal(route.id, "gmail-intake-firewall-pubsub");
  assert.equal(route.path, "/gmail-intake-firewall/pubsub");
  assert.equal(route.auth, "plugin");
  assert.equal(route.match, "exact");

  const unauthorized = mockResponse();
  await route.handler(jsonRequest({ historyId: "1" }), unauthorized.res);
  assert.equal(unauthorized.statusCode, 401);
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
  const wrappedToolResult = await tool.run({ input: { operation: "checkSourceAuth", sourceId: "primary" } });
  const first = (serviceResult.sources as Array<Record<string, unknown>>)[0];

  assert.equal(serviceResult.ok, true);
  assert.equal(toolResult.ok, true);
  assert.equal(wrappedToolResult.ok, true);
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

test("plugin service parses Gmail Pub/Sub notification envelopes", async () => {
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
        intakeMode: "watch",
        watchTopicName: "projects/x/topics/gmail",
      }],
    },
    registerService(candidate: unknown) {
      service = candidate as typeof service;
    },
  });

  assert.ok(service);
  await service.start();
  await new Promise((resolve) => setImmediate(resolve));
  const payload = Buffer.from(JSON.stringify({
    emailAddress: "user@example.com",
    historyId: "120",
  }), "utf8").toString("base64url");
  const result = await service.handleGmailNotification({
    message: {
      data: payload,
      attributes: { sourceId: "primary" },
    },
  });
  const status = await service.status();
  await service.stop();

  assert.equal(result.ok, true);
  assert.deepEqual(result.notification, {
    sourceId: "primary",
    accountEmail: "user@example.com",
    historyId: "120",
  });
  assert.equal(result.skipped, 1);
  assert.equal(((status.sources as Array<Record<string, unknown>>)[0]?.cursor as Record<string, unknown> | undefined)?.historyId, "120");
});

test("plugin Pub/Sub HTTP route handles authorized notification envelopes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-plugin-"));
  let service: CapturedService | undefined;
  let route: CapturedHttpRoute | undefined;
  registerGmailIntakeFirewallPlugin({
    config: {
      dryRun: true,
      webhookSecret: "secret",
      sqlitePath: join(dir, "state.sqlite"),
      sources: [{
        id: "primary",
        accountEmail: "user@example.com",
        authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
        intakeMode: "watch",
        watchTopicName: "projects/x/topics/gmail",
      }],
    },
    registerService(candidate: unknown) {
      service = candidate as CapturedService;
    },
    registerHttpRoute(candidate: unknown) {
      route = candidate as CapturedHttpRoute;
    },
  });

  assert.ok(service);
  assert.ok(route);
  const payload = Buffer.from(JSON.stringify({
    emailAddress: "user@example.com",
    historyId: "120",
  }), "utf8").toString("base64url");
  const response = mockResponse();
  await route.handler(jsonRequest({
    message: {
      data: payload,
      attributes: { sourceId: "primary" },
    },
  }, { authorization: "Bearer secret" }), response.res);
  await service.stop();

  assert.equal(response.statusCode, 200);
  const parsed = JSON.parse(response.body ?? "{}") as Record<string, unknown>;
  assert.equal(parsed.ok, true);
  assert.equal(parsed.skipped, 1);
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
