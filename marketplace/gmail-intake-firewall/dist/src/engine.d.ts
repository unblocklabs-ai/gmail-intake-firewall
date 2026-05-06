import type { RouterClassifier } from "./routerClassifier.js";
import type { SecurityClassifier } from "./securityClassifier.js";
import { type FirewallState } from "./state.js";
import type { DecisionLogEntry, InboundMessage, PluginConfig, ProcessSkipReason, RoutingPreference } from "./types.js";
export type ProcessMessageDeps = {
    securityClassifier: SecurityClassifier;
    routerClassifier: RouterClassifier;
    routingPreferences?: RoutingPreference[];
    now?: () => Date;
};
export declare function processMessage(message: InboundMessage, config: PluginConfig, state: FirewallState, deps: ProcessMessageDeps): Promise<{
    state: FirewallState;
    decision?: DecisionLogEntry;
    skipped: boolean;
    skipReason?: ProcessSkipReason;
}>;
//# sourceMappingURL=engine.d.ts.map