const GMAIL_MODIFY_SCOPES = new Set([
    "https://www.googleapis.com/auth/gmail.modify",
    "https://mail.google.com/",
]);
export function resolveSecretResolver(host) {
    if (!host || typeof host !== "object") {
        return undefined;
    }
    const raw = host;
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
                resolveSecret(ref) {
                    return Promise.resolve(resolver.call(candidate, ref));
                },
            };
        }
    }
    return undefined;
}
export function gmailScopesAllowModify(scopes) {
    if (!scopes || scopes.length === 0) {
        return undefined;
    }
    return scopes.some((scope) => GMAIL_MODIFY_SCOPES.has(scope));
}
export async function resolveGoogleAuthMaterial(source, resolver) {
    const ref = source.authRef ?? source.credentialRef;
    if (!ref) {
        return {};
    }
    const value = await resolver.resolveSecret(ref);
    if (!value || typeof value !== "object") {
        return {};
    }
    const raw = value;
    const material = {};
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
        material.scopes = raw.scopes.filter((scope) => typeof scope === "string");
    }
    return material;
}
function objectValue(value) {
    return value && typeof value === "object" ? value : undefined;
}
