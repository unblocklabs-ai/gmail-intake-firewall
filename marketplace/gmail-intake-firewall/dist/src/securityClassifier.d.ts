import type { InboundMessage, NormalizedMessageForClassification, SecurityClassification, SecurityConfig, ArtifactConfig } from "./types.js";
export type SecurityClassifier = {
    classify(message: NormalizedMessageForClassification): Promise<SecurityClassification>;
};
export declare function shouldQuarantine(classification: SecurityClassification, security: SecurityConfig): boolean;
export declare function normalizeMessageForSecurity(message: InboundMessage, maxBodyChars: number, artifacts?: ArtifactConfig): NormalizedMessageForClassification;
export declare function createUnavailableSecurityClassifier(): SecurityClassifier;
//# sourceMappingURL=securityClassifier.d.ts.map