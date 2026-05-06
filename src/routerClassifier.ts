import type { InboundMessage, NormalizedMessageForClassification, RoutingClassification, SecurityClassification, TagConfig } from "./types.js";

export type RouterClassifier = {
  classify(input: RouterClassifierInput, tags: TagConfig[]): Promise<RoutingClassification>;
};

export type RouterClassifierInput = {
  message: InboundMessage;
  normalized: NormalizedMessageForClassification;
  security: SecurityClassification;
};

export function createNoopRouterClassifier(): RouterClassifier {
  return {
    async classify(input: RouterClassifierInput): Promise<RoutingClassification> {
      return {
        tags: [],
        wakeMode: "none",
        sanitizedSummary: input.security.safeSummary || input.message.snippet || input.message.subject || "Safe message with no routing tag.",
        reasons: ["No routing classifier has been configured."],
      };
    },
  };
}
