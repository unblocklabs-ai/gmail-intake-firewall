import assert from "node:assert/strict";
import test from "node:test";
import { shouldQuarantine } from "../src/securityClassifier.js";
import type { SecurityClassification, SecurityConfig } from "../src/types.js";

const baseSecurity: SecurityConfig = {
  quarantineLabel: "OpenClaw/Quarantine",
  maxBodyChars: 24000,
  maliciousThreshold: 0.65,
  uncertainThreshold: 0.35,
  failClosedOnUncertain: true,
  includeSnippetInAlerts: false,
  archiveOnQuarantine: false,
};

function classification(
  verdict: SecurityClassification["verdict"],
  riskScore: number,
): SecurityClassification {
  return {
    verdict,
    riskScore,
    categories: [],
    reasons: [],
    safeSummary: "summary",
    suspiciousSignals: [],
  };
}

test("shouldQuarantine fail-closes malicious verdict even with partial threshold config", () => {
  const partialSecurity = {
    ...baseSecurity,
    maliciousThreshold: undefined,
    uncertainThreshold: undefined,
  } as unknown as SecurityConfig;

  assert.equal(shouldQuarantine(classification("malicious", 0.01), partialSecurity), true);
  assert.equal(shouldQuarantine(classification("risky", 0.7), partialSecurity), true);
  assert.equal(shouldQuarantine(classification("uncertain", 0.01), partialSecurity), true);
});

test("shouldQuarantine uses threshold fallback when uncertain fail-closed is explicitly disabled", () => {
  const partialSecurity = {
    ...baseSecurity,
    uncertainThreshold: undefined,
    failClosedOnUncertain: false,
  } as unknown as SecurityConfig;

  assert.equal(shouldQuarantine(classification("uncertain", 0.34), partialSecurity), false);
  assert.equal(shouldQuarantine(classification("uncertain", 0.35), partialSecurity), true);
});
