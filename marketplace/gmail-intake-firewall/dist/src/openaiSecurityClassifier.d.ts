import { type SecretResolver } from "./googleAuth.js";
import type { PluginConfig } from "./types.js";
import type { SecurityClassifier } from "./securityClassifier.js";
type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
export declare function resolveOpenAiApiKey(config: PluginConfig, resolver: SecretResolver | undefined): Promise<string | undefined>;
export declare function createOpenAiSecurityClassifier(options: {
    apiKey: string;
    model: string;
    fetch?: FetchLike;
}): SecurityClassifier;
export {};
//# sourceMappingURL=openaiSecurityClassifier.d.ts.map