import type { ActionModeConfig, ActionExecutionMode, ActionsConfig, AgentWakePayload, ArtifactAnalysis, InboundMessage, PlannedAction, PluginConfig, RoutingClassification, SecurityClassification, GmailSourceConfig, TagConfig, WakeTargetConfig } from "./types.js";
export declare function buildQuarantineActions(message: InboundMessage, classification: SecurityClassification, config: PluginConfig, source: GmailSourceConfig, artifactAnalysis?: ArtifactAnalysis): PlannedAction[];
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
    status: "succeeded" | "failed" | "skipped_dry_run" | "disabled";
    error?: string;
    reason?: string;
};
export type ActionExecutionOptions = {
    dryRun: boolean;
    actions: ActionsConfig;
    source?: GmailSourceConfig | undefined;
};
export declare function executePlannedActions(actions: PlannedAction[], options: ActionExecutionOptions, deps: ActionExecutorDeps): Promise<ActionExecutionStatus[]>;
export declare function requiredActionsSucceeded(results: ActionExecutionStatus[]): boolean;
export declare function buildSafeRoutingActions(message: InboundMessage, routing: RoutingClassification, security: SecurityClassification, tags: TagConfig[], wakeTargets: WakeTargetConfig[], source: GmailSourceConfig, artifactAnalysis?: ArtifactAnalysis): PlannedAction[];
export declare function resolveActionMode(action: PlannedAction, actions: ActionsConfig): {
    path: string;
    mode: ActionExecutionMode;
};
export declare function resolveConfiguredMode(modeConfig: ActionModeConfig, path: string, dryRun: boolean): {
    mode: ActionExecutionMode;
    reason?: string;
};
//# sourceMappingURL=actions.d.ts.map