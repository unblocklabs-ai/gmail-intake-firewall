import type { GmailSourceConfig } from "./types.js";

export type GoogleAuthMaterial = {
  accessToken?: string;
  refreshToken?: string;
  clientId?: string;
  clientSecret?: string;
  tokenType?: "per_user_oauth_refresh_token" | "workspace_domain_wide_delegation";
  scopes?: string[];
};

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

export async function resolveGoogleAuthMaterial(
  source: GmailSourceConfig,
  resolver: SecretResolver,
): Promise<GoogleAuthMaterial> {
  const ref = source.authRef ?? source.credentialRef;
  if (!ref) {
    return {};
  }
  const value = await resolver.resolveSecret(ref);
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

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" ? value as Record<string, unknown> : undefined;
}
