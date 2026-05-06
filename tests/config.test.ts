import assert from "node:assert/strict";
import test from "node:test";
import { resolvePluginConfig, validatePluginConfig } from "../src/config.js";

test("config validation catches broken cross references", () => {
  const config = resolvePluginConfig({
    aggregate: { timezone: "Not/AZone" },
    sources: [
      { id: "primary", accountEmail: "user@example.com", intakeMode: "watch" },
      { id: "primary", accountEmail: "other@example.com" },
    ],
    tags: [
      { id: "client-dev", description: "Client dev", wakeMode: "wake_now" },
      { id: "digest", description: "Digest", wakeMode: "aggregate", aggregateCadence: "monthly" },
      { id: "unknown-target", description: "Unknown", wakeMode: "wake_now", wakeTarget: "agent:missing" },
    ],
  });

  const findings = validatePluginConfig(config);

  assert.equal(findings.some((finding) => finding.path === "sources" && finding.severity === "error"), true);
  assert.equal(findings.some((finding) => finding.path === "sources.primary.watchTopicName"), true);
  assert.equal(findings.some((finding) => finding.path === "tags.client-dev.wakeTarget"), true);
  assert.equal(findings.some((finding) => finding.path === "tags.digest.aggregateCadence"), true);
  assert.equal(findings.some((finding) => finding.path === "tags.unknown-target.wakeTarget"), true);
  assert.equal(findings.some((finding) => finding.path === "aggregate.timezone"), true);
});

test("config validation accepts a complete operator policy", () => {
  const config = resolvePluginConfig({
    aggregate: { timezone: "America/New_York" },
    sources: [{
      id: "primary",
      accountEmail: "user@example.com",
      authRef: { source: "openclaw", provider: "secrets", id: "gmail-primary" },
    }],
    security: { alertTarget: "security" },
    alertSinks: [{ id: "security", kind: "slack", target: "slack:#security", enabled: true }],
    tags: [
      { id: "client-dev", description: "Client dev", wakeMode: "wake_now", wakeTarget: "agent:dev" },
      { id: "newsletter", description: "Newsletter", wakeMode: "aggregate", aggregateCadence: "daily", wakeTarget: "agent:digest" },
      { id: "receipt", description: "Receipt", wakeMode: "none", gmailLabel: "OpenClaw/Receipt" },
    ],
    wakeTargets: [
      { id: "agent:dev", agentId: "dev-agent" },
      { id: "agent:digest", agentId: "digest-agent" },
    ],
  });

  assert.deepEqual(validatePluginConfig(config), []);
});
