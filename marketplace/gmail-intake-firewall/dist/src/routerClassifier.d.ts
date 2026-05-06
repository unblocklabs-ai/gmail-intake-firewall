import type { InboundMessage, NormalizedMessageForClassification, RoutingClassification, SecurityClassification, TagConfig } from "./types.js";
export type RouterClassifier = {
    classify(input: RouterClassifierInput, tags: TagConfig[]): Promise<RoutingClassification>;
};
export type RouterClassifierInput = {
    message: InboundMessage;
    normalized: NormalizedMessageForClassification;
    security: SecurityClassification;
};
export declare function createNoopRouterClassifier(): RouterClassifier;
//# sourceMappingURL=routerClassifier.d.ts.map