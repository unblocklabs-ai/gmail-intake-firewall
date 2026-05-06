import assert from "node:assert/strict";
import test from "node:test";
import { createHostActionDeps } from "../src/hostActions.js";

test("host action deps route Slack alerts local logs and detached wakes", async () => {
  const calls: string[] = [];
  const deps = createHostActionDeps({
    slack: {
      async postAlert(payload: unknown) {
        calls.push(`slack:${JSON.stringify(payload)}`);
      },
    },
    runtime: {
      agent: {
        async startDetachedTurn(payload: unknown) {
          calls.push(`wake:${JSON.stringify(payload)}`);
        },
      },
    },
  }, {
    info(message) {
      calls.push(`log:${message}`);
    },
  });

  await deps.slack?.postAlert("slack:#security", "summary", { a: 1 });
  await deps.localLog?.write("summary", { a: 1 });
  await deps.wake?.startDetachedAgentTurn({
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
  });

  assert.equal(calls.length, 3);
  assert.match(calls[0] ?? "", /^slack:/);
  assert.equal(calls[1], "log:gmail-intake-firewall local log");
  assert.match(calls[2] ?? "", /^wake:/);
});
