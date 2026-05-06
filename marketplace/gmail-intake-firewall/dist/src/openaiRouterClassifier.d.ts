import type { RouterClassifier } from "./routerClassifier.js";
type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
export declare function createOpenAiRouterClassifier(options: {
    apiKey: string;
    model: string;
    fetch?: FetchLike;
}): RouterClassifier;
export {};
//# sourceMappingURL=openaiRouterClassifier.d.ts.map