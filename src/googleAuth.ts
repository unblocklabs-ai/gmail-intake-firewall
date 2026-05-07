import { readFile } from "node:fs/promises";
import type { GmailSourceConfig } from "./types.js";

export type GoogleAuthMaterial = {
  accessToken?: string;
  refreshToken?: string;
  clientId?: string;
  clientSecret?: string;
  tokenType?: "per_user_oauth_refresh_token" | "workspace_domain_wide_delegation";
  scopes?: string[];
};

const GMAIL_MODIFY_SCOPES = new Set([
  "https://www.googleapis.com/auth/gmail.modify",
  "https://mail.google.com/",
]);

export type SecretResolver = {
  resolveSecret(ref: unknown): Promise<unknown>;
};

export function resolveSecretResolver(host: unknown): SecretResolver | undefined {
  if (!host || typeof host !== "object") {
    return undefined;
  }
  const raw = host as Record<string, unknown>;
  const candidates = [
    raw,
    objectValue(raw.secrets),
    objectValue(raw.secretResolver),
    objectValue(raw.config),
  ];
  for (const candidate of candidates) {
    const resolver = candidate?.resolveSecret ?? candidate?.resolve;
    if (typeof resolver === "function") {
      return {
        resolveSecret(ref: unknown) {
          return Promise.resolve(resolver.call(candidate, ref));
        },
      };
    }
  }
  return undefined;
}

export function gmailScopesAllowModify(scopes: string[] | undefined): boolean | undefined {
  if (!scopes || scopes.length === 0) {
    return undefined;
  }
  return scopes.some((scope) => GMAIL_MODIFY_SCOPES.has(scope));
}

export async function resolveGoogleAuthMaterial(
  source: GmailSourceConfig,
  resolver?: SecretResolver,
): Promise<GoogleAuthMaterial> {
  const ref = source.authRef ?? source.credentialRef;
  if (!ref) {
    return {};
  }
  const value = await resolveCredentialValue(ref, resolver);
  return normalizeGoogleAuthMaterial(value);
}

export async function resolveSecretValue(ref: unknown, resolver?: SecretResolver): Promise<unknown> {
  return resolveCredentialValue(ref, resolver);
}

async function resolveCredentialValue(ref: unknown, resolver?: SecretResolver): Promise<unknown> {
  if (isCredentialObject(ref)) {
    return ref;
  }
  if (resolver) {
    return resolver.resolveSecret(ref);
  }
  return resolveLocalSecretRef(ref);
}

async function resolveLocalSecretRef(ref: unknown): Promise<unknown> {
  const raw = objectValue(ref);
  if (!raw) {
    return undefined;
  }
  const source = stringValue(raw.source);
  const provider = stringValue(raw.provider);
  const id = stringValue(raw.id) ?? stringValue(raw.name) ?? stringValue(raw.key) ?? stringValue(raw.env);
  if ((source === "env" || provider === "env") && id) {
    return parseSecretValue(process.env[id]);
  }
  const path = source === "file"
    ? id
    : provider === "file"
      ? id
      : stringValue(raw.path);
  if ((source === "file" || provider === "file" || raw.path) && path) {
    return parseSecretValue(await readFile(path, "utf8"));
  }
  throw new Error("Host secret resolver is unavailable and authRef is not an inline, env, or file credential reference.");
}

function parseSecretValue(value: string | undefined): unknown {
  const trimmed = value?.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return trimmed;
  }
}

function normalizeGoogleAuthMaterial(value: unknown): GoogleAuthMaterial {
  if (!value || typeof value !== "object") {
    return {};
  }
  const raw = value as Record<string, unknown>;
  const material: GoogleAuthMaterial = {};
  if (typeof raw.accessToken === "string") {
    material.accessToken = raw.accessToken;
  }
  if (typeof raw.refreshToken === "string") {
    material.refreshToken = raw.refreshToken;
  }
  if (typeof raw.clientId === "string") {
    material.clientId = raw.clientId;
  }
  if (typeof raw.clientSecret === "string") {
    material.clientSecret = raw.clientSecret;
  }
  material.tokenType = raw.tokenType === "workspace_domain_wide_delegation"
    ? "workspace_domain_wide_delegation"
    : "per_user_oauth_refresh_token";
  if (Array.isArray(raw.scopes)) {
    material.scopes = raw.scopes.filter((scope): scope is string => typeof scope === "string");
  }
  return material;
}

function isCredentialObject(value: unknown): boolean {
  const raw = objectValue(value);
  return Boolean(raw && (
    typeof raw.accessToken === "string"
    || typeof raw.refreshToken === "string"
    || typeof raw.clientId === "string"
    || typeof raw.clientSecret === "string"
    || typeof raw.OPENAI_API_KEY === "string"
    || typeof raw.apiKey === "string"
  ));
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" ? value as Record<string, unknown> : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
