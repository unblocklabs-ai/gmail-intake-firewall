import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { resolveGoogleAuthMaterial } from "../src/googleAuth.js";
import type { GmailSourceConfig } from "../src/types.js";

function source(authRef: Record<string, unknown>): GmailSourceConfig {
  return {
    id: "primary",
    accountEmail: "user@example.com",
    authRef,
    enabled: true,
    polling: {
      intervalMs: 60000,
      maxResults: 1,
    },
    gmailActions: {
      hasModifyScope: true,
    },
  };
}

test("Gmail auth resolves inline OAuth material without a host resolver", async () => {
  const material = await resolveGoogleAuthMaterial(source({
    refreshToken: "refresh-token",
    clientId: "client-id",
    clientSecret: "client-secret",
    scopes: ["https://www.googleapis.com/auth/gmail.modify"],
  }));

  assert.equal(material.refreshToken, "refresh-token");
  assert.equal(material.clientId, "client-id");
  assert.equal(material.clientSecret, "client-secret");
  assert.deepEqual(material.scopes, ["https://www.googleapis.com/auth/gmail.modify"]);
});

test("Gmail auth resolves JSON env SecretRef without a host resolver", async () => {
  const key = "GMAIL_INTAKE_FIREWALL_TEST_AUTH_JSON";
  const previous = process.env[key];
  process.env[key] = JSON.stringify({
    refreshToken: "refresh-token",
    clientId: "client-id",
    clientSecret: "client-secret",
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  });
  try {
    const material = await resolveGoogleAuthMaterial(source({ source: "env", id: key }));
    assert.equal(material.refreshToken, "refresh-token");
    assert.equal(material.clientId, "client-id");
    assert.equal(material.clientSecret, "client-secret");
    assert.deepEqual(material.scopes, ["https://www.googleapis.com/auth/gmail.readonly"]);
  } finally {
    if (previous === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = previous;
    }
  }
});

test("Gmail auth resolves JSON file SecretRef without a host resolver", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gmail-intake-auth-"));
  const path = join(dir, "oauth.json");
  await writeFile(path, JSON.stringify({
    accessToken: "access-token",
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  }), "utf8");

  const material = await resolveGoogleAuthMaterial(source({ source: "file", id: path }));

  assert.equal(material.accessToken, "access-token");
  assert.deepEqual(material.scopes, ["https://www.googleapis.com/auth/gmail.readonly"]);
});
