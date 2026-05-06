import assert from "node:assert/strict";
import test from "node:test";
import { createOpenAiRouterClassifier } from "../src/openaiRouterClassifier.js";
import type { RouterClassifierInput } from "../src/routerClassifier.js";

const input: RouterClassifierInput = {
  message: {
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
    subject: "Client dev",
    labels: ["INBOX"],
    bodyText: "Can you review this bug?",
    attachments: [],
  },
  normalized: {
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-1",
    headers: {},
    rawHeaders: [],
    authHeaders: {},
    from: "client@example.com",
    to: ["user@example.com"],
    cc: [],
    labels: ["INBOX"],
    bodyText: "Can you review this bug?",
    links: [],
    attachments: [],
  },
  security: {
    verdict: "safe",
    riskScore: 0,
    categories: [],
    reasons: [],
    safeSummary: "Client asks about a bug.",
    suspiciousSignals: [],
  },
};

test("OpenAI router constrains output to configured tags and derives wake mode", async () => {
  const classifier = createOpenAiRouterClassifier({
    apiKey: "test-key",
    model: "gpt-5.5",
    fetch: async () => new Response(JSON.stringify({
      output_text: JSON.stringify({
        tags: ["client-dev", "invented"],
        sanitizedSummary: "Client asks about a bug.",
        reasons: ["Matches client development work."],
      }),
    }), { status: 200 }),
  });

  const result = await classifier.classify(input, [
    { id: "client-dev", description: "Client development", wakeMode: "wake_now", wakeTarget: "agent:dev" },
  ]);

  assert.deepEqual(result.tags, ["client-dev"]);
  assert.equal(result.wakeMode, "wake_now");
});

test("OpenAI router fails closed to no wake on API error", async () => {
  const classifier = createOpenAiRouterClassifier({
    apiKey: "test-key",
    model: "gpt-5.5",
    fetch: async () => new Response("nope", { status: 500 }),
  });

  const result = await classifier.classify(input, [
    { id: "client-dev", description: "Client development", wakeMode: "wake_now", wakeTarget: "agent:dev" },
  ]);

  assert.deepEqual(result.tags, []);
  assert.equal(result.wakeMode, "none");
});
