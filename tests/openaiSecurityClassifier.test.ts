import assert from "node:assert/strict";
import test from "node:test";
import { resolvePluginConfig } from "../src/config.js";
import { createOpenAiSecurityClassifier, resolveOpenAiApiKey } from "../src/openaiSecurityClassifier.js";
import { normalizeMessageForSecurity } from "../src/securityClassifier.js";
import type { NormalizedMessageForClassification } from "../src/types.js";

const normalized: NormalizedMessageForClassification = {
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
  bodyText: "Hello",
  links: [],
  attachments: [],
  artifactAnalysis: {
    links: [],
    attachments: [],
    notes: [
      "Links were structurally analyzed only; URLs were not fetched.",
      "Attachments were metadata-analyzed only; attachment bytes were not downloaded or opened.",
    ],
  },
};

test("OpenAI API key resolves from SecretRef before config fallback", async () => {
  const config = resolvePluginConfig({
    openaiApiKeyRef: { source: "openclaw", provider: "env", id: "OPENAI_API_KEY" },
    OPENAI_API_KEY: "fallback",
  });

  const apiKey = await resolveOpenAiApiKey(config, {
    async resolveSecret(ref) {
      assert.deepEqual(ref, { source: "openclaw", provider: "env", id: "OPENAI_API_KEY" });
      return { OPENAI_API_KEY: "from-secret" };
    },
  });

  assert.equal(apiKey, "from-secret");
});

test("config defaults OpenAI model to gpt-5.5 and accepts override", () => {
  assert.equal(resolvePluginConfig({}).openai_model, "gpt-5.5");
  assert.equal(resolvePluginConfig({ openai_model: "gpt-5.5-mini" }).openai_model, "gpt-5.5-mini");
});

test("disabled link analysis still clips and redacts displayed URLs", () => {
  const normalizedMessage = normalizeMessageForSecurity({
    sourceId: "primary",
    accountEmail: "user@example.com",
    messageId: "msg-1",
    threadId: "thread-1",
    headers: {},
    rawHeaders: [],
    to: ["user@example.com"],
    cc: [],
    bcc: [],
    labels: ["INBOX"],
    bodyText: "See https://user:pass@example.com/reset?token=secret-token&next=/home",
    attachments: [],
  }, 500, {
    analyzeLinks: false,
    analyzeAttachments: false,
    fetchLinks: false,
    downloadAttachments: false,
    maxDisplayedUrlChars: 48,
  });

  assert.equal(normalizedMessage.links.length, 1);
  assert.equal(normalizedMessage.links[0]?.riskHints.length, 0);
  assert.equal(normalizedMessage.links[0]?.url.includes("user:pass"), false);
  assert.equal(normalizedMessage.links[0]?.url.includes("secret-token"), false);
  assert.ok((normalizedMessage.links[0]?.url.length ?? 0) <= 48);
  assert.match(normalizedMessage.artifactAnalysis.notes.join(" "), /Link analysis was disabled/);
  assert.match(normalizedMessage.artifactAnalysis.notes.join(" "), /Attachment analysis was disabled/);
});

test("OpenAI classifier sends structured output request and normalizes response", async () => {
  const calls: Array<{ input: string | URL; init?: RequestInit }> = [];
  const classifier = createOpenAiSecurityClassifier({
    apiKey: "test-key",
    model: "gpt-5.5",
    fetch: async (input, init) => {
      calls.push(init ? { input, init } : { input });
      return new Response(JSON.stringify({
        output_text: JSON.stringify({
          verdict: "safe",
          riskScore: 0.02,
          categories: [],
          reasons: ["No suspicious indicators."],
          safeSummary: "Routine client email.",
          suspiciousSignals: [],
        }),
      }), { status: 200 });
    },
  });

  const result = await classifier.classify(normalized);

  assert.equal(result.verdict, "safe");
  assert.equal(result.safeSummary, "Routine client email.");
  assert.equal(calls.length, 1);
  const body = JSON.parse(String(calls[0]?.init?.body)) as Record<string, unknown>;
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual((body.text as { format: { type: string; name: string } }).format.type, "json_schema");
  assert.equal((calls[0]?.init?.headers as Record<string, string>).Authorization, "Bearer test-key");
  assert.match(JSON.stringify(body), /URLs were not fetched/);
  assert.match(JSON.stringify(body), /attachment bytes were not downloaded/);
});

test("OpenAI classifier accepts explicit malicious verdict", async () => {
  const classifier = createOpenAiSecurityClassifier({
    apiKey: "test-key",
    model: "gpt-5.5",
    fetch: async () => new Response(JSON.stringify({
      output_text: JSON.stringify({
        verdict: "malicious",
        riskScore: 0.98,
        categories: ["phishing"],
        reasons: ["Credential theft attempt."],
        safeSummary: "Credential theft attempt.",
        suspiciousSignals: ["fake login"],
      }),
    }), { status: 200 }),
  });

  const result = await classifier.classify(normalized);

  assert.equal(result.verdict, "malicious");
  assert.equal(result.riskScore, 0.98);
});

test("OpenAI classifier fails closed on API error", async () => {
  const classifier = createOpenAiSecurityClassifier({
    apiKey: "test-key",
    model: "gpt-5.5",
    fetch: async () => new Response("nope", { status: 500 }),
  });

  const result = await classifier.classify(normalized);

  assert.equal(result.verdict, "uncertain");
  assert.equal(result.riskScore, 1);
  assert.deepEqual(result.categories, ["classifier_error"]);
});
