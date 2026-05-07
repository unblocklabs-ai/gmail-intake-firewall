import type { AgentWakePayload, InboundMessage, PlannedAction, PluginConfig, RoutingClassification, SecurityClassification, GmailSourceConfig, TagConfig, WakeTargetConfig } from "./types.js";
export declare function buildQuarantineActions(message: InboundMessage, classification: SecurityClassification, config: PluginConfig, source: GmailSourceConfig): PlannedAction[];
export type ActionExecutorDeps = {
    gmail?: {
        applyLabel(messageId: string, label: string): Promise<void>;
        removeLabel?(messageId: string, label: string): Promise<void>;
        archive(messageId: string): Promise<void>;
        restoreInbox?(messageId: string): Promise<void>;
    };
    slack?: {
        postAlert(target: string | undefined, summary: string, payload: Record<string, unknown> | undefined): Promise<void>;
    };
    wake?: {
        startDetachedAgentTurn(payload: AgentWakePayload): Promise<void>;
    };
    localLog?: {
        write(summary: string, payload: Record<string, unknown> | undefined): Promise<void>;
    };
};
export type ActionExecutionStatus = {
    actionIndex: number;
    action: PlannedAction;
    required: boolean;
    status: "succeeded" | "failed" | "skipped_dry_run";
    error?: string;
};
export declare function executePlannedActions(actions: PlannedAction[], dryRun: boolean, deps: ActionExecutorDeps): Promise<ActionExecutionStatus[]>;
export declare function requiredActionsSucceeded(results: ActionExecutionStatus[]): boolean;
export declare function buildSafeRoutingActions(message: InboundMessage, routing: RoutingClassification, security: SecurityClassification, tags: TagConfig[], wakeTargets: WakeTargetConfig[], source: GmailSourceConfig): PlannedAction[];
//# sourceMappingURL=actions.d.ts.map