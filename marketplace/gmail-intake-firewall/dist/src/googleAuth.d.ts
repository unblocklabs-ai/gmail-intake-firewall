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
export declare function resolveSecretResolver(host: unknown): SecretResolver | undefined;
export declare function gmailScopesAllowModify(scopes: string[] | undefined): boolean | undefined;
export declare function resolveGoogleAuthMaterial(source: GmailSourceConfig, resolver?: SecretResolver): Promise<GoogleAuthMaterial>;
export declare function resolveSecretValue(ref: unknown, resolver?: SecretResolver): Promise<unknown>;
//# sourceMappingURL=googleAuth.d.ts.map