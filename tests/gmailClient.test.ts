import assert from "node:assert/strict";
import test from "node:test";
import { createGmailClientFromApi, gmailApiMessageToInboundMessage, gmailQuerySystemLabelIds, type GmailApi } from "../src/gmailClient.js";
import { resolvePluginConfig } from "../src/config.js";

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

test("Gmail query parser extracts supported system label filters", () => {
  assert.deepEqual(
    gmailQuerySystemLabelIds("in:inbox is:unread category:primary newer_than:7d -in:spam"),
    ["INBOX", "UNREAD", "CATEGORY_PRIMARY"],
  );
  assert.deepEqual(
    gmailQuerySystemLabelIds("(in:inbox OR category:updates) newer_than:7d"),
    [],
  );
});

test("Gmail API message maps to inbound message without attachment download", () => {
  const source = resolvePluginConfig({ sources: [{ id: "primary", accountEmail: "user@example.com" }] }).sources[0]!;
  const message = gmailApiMessageToInboundMessage(source, {
    id: "msg-1",
    threadId: "thread-1",
    labelIds: ["INBOX"],
    snippet: "snippet",
    payload: {
      mimeType: "multipart/mixed",
      headers: [
        { name: "From", value: "client@example.com" },
        { name: "To", value: "user@example.com" },
        { name: "Subject", value: "Client request" },
        { name: "Authentication-Results", value: "mx.example; spf=pass" },
        { name: "Authentication-Results", value: "mx.example; dkim=pass" },
      ],
      parts: [
        { mimeType: "text/plain", body: { data: b64url("Please see https://client.example/task") } },
        { mimeType: "application/pdf", filename: "brief.pdf", body: { attachmentId: "att-1", size: 42 } },
      ],
    },
  });

  assert.equal(message.messageId, "msg-1");
  assert.deepEqual(message.rawHeaders.filter((header) => header.name === "Authentication-Results"), [
    { name: "Authentication-Results", value: "mx.example; spf=pass" },
    { name: "Authentication-Results", value: "mx.example; dkim=pass" },
  ]);
  assert.equal(message.bodyText, "Please see https://client.example/task");
  assert.deepEqual(message.linkUrls, ["https://client.example/task"]);
  assert.deepEqual(message.attachments, [{ id: "att-1", filename: "brief.pdf", mimeType: "application/pdf", size: 42 }]);
});

test("Gmail client lists candidates with labelIds and applies label/archive actions", async () => {
  const calls: Record<string, unknown>[] = [];
  const api: GmailApi = {
    users: {
      messages: {
        async list(params) {
          calls.push({ kind: "list", params });
          return { data: { messages: [{ id: "msg-1", threadId: "thread-1" }] } };
        },
        async get() {
          throw new Error("not used");
        },
        async modify(params) {
          calls.push({ kind: "modify", params });
          return {};
        },
      },
      labels: {
        async list(params) {
          calls.push({ kind: "labels.list", params });
          return { data: { labels: [{ id: "Label_1", name: "OpenClaw/Quarantine" }] } };
        },
        async create(params) {
          calls.push({ kind: "labels.create", params });
          return { data: { id: "Label_2", name: "OpenClaw/New" } };
        },
      },
    },
  };
  const source = resolvePluginConfig({
    sources: [{ id: "primary", accountEmail: "user@example.com", candidateQuery: "in:inbox is:unread", polling: { maxResults: 10 } }],
  }).sources[0]!;
  const client = createGmailClientFromApi(source, api);

  assert.deepEqual(await client.listCandidates(), [{ id: "msg-1", threadId: "thread-1" }]);
  await client.applyLabel("msg-1", "OpenClaw/Quarantine");
  await client.applyLabel("msg-1", "OpenClaw/New");
  await client.archive("msg-1");

  const listCall = calls.find((call) => call.kind === "list")!;
  assert.deepEqual((listCall.params as Record<string, unknown>).labelIds, ["INBOX", "UNREAD"]);
  assert.equal(calls.some((call) => call.kind === "labels.create"), true);
  assert.deepEqual(calls.filter((call) => call.kind === "modify").map((call) => (call.params as Record<string, unknown>).requestBody), [
    { addLabelIds: ["Label_1"] },
    { addLabelIds: ["Label_2"] },
    { removeLabelIds: ["INBOX"] },
  ]);
});

test("Gmail client maps history and thread context", async () => {
  const api: GmailApi = {
    users: {
      messages: {
        async list() { return { data: { messages: [] } }; },
        async get() { throw new Error("not used"); },
        async modify() { return {}; },
      },
      history: {
        async list(params) {
          assert.equal(params.startHistoryId, "100");
          return {
            data: {
              historyId: "101",
              history: [{ messagesAdded: [{ message: { id: "msg-1", threadId: "thread-1" } }] }],
            },
          };
        },
      },
      threads: {
        async get() {
          return {
            data: {
              messages: [
                {
                  id: "msg-1",
                  threadId: "thread-1",
                  labelIds: ["INBOX"],
                  snippet: "hello",
                  payload: {
                    headers: [
                      { name: "From", value: "client@example.com" },
                      { name: "To", value: "user@example.com" },
                      { name: "Subject", value: "Hello" },
                      { name: "Date", value: "Wed, 06 May 2026 12:00:00 +0000" },
                    ],
                  },
                },
              ],
            },
          };
        },
      },
      labels: {
        async list() { return { data: { labels: [] } }; },
        async create() { return { data: { id: "Label_1" } }; },
      },
    },
  };
  const source = resolvePluginConfig({ sources: [{ id: "primary", accountEmail: "user@example.com" }] }).sources[0]!;
  const client = createGmailClientFromApi(source, api);

  assert.deepEqual(await client.listHistory?.("100"), {
    historyId: "101",
    candidates: [{ id: "msg-1", threadId: "thread-1" }],
  });
  assert.deepEqual(await client.fetchThreadContext?.("thread-1"), {
    threadId: "thread-1",
    participants: ["client@example.com", "user@example.com"],
    labels: ["INBOX"],
    messages: [{
      messageId: "msg-1",
      from: "client@example.com",
      subject: "Hello",
      date: "Wed, 06 May 2026 12:00:00 +0000",
      snippet: "hello",
    }],
  });
});

test("Gmail watch ignores malformed expiration while preserving history id", async () => {
  const api: GmailApi = {
    users: {
      messages: {
        async list() { return { data: { messages: [] } }; },
        async get() { throw new Error("not used"); },
        async modify() { return {}; },
      },
      async watch() {
        return { data: { historyId: "200", expiration: "not-a-number" } };
      },
      labels: {
        async list() { return { data: { labels: [] } }; },
        async create() { return { data: { id: "Label_1" } }; },
      },
    },
  };
  const source = resolvePluginConfig({ sources: [{ id: "primary", accountEmail: "user@example.com" }] }).sources[0]!;
  const client = createGmailClientFromApi(source, api);

  assert.deepEqual(await client.setupWatch?.("projects/x/topics/gmail"), { historyId: "200" });
});
