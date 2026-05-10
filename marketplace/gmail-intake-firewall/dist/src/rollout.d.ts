import type { ActionExecutionMode, PluginConfig } from "./types.js";
export type RolloutVerdict = "blocked" | "caution" | "ready";
export type RolloutFinding = {
    severity: "error" | "warning" | "info";
    path: string;
    message: string;
};
type RolloutAction = {
    configured: ActionExecutionMode;
    effective: ActionExecutionMode;
    ready: boolean;
    reason?: string;
    sourceIds?: string[];
};
export type RolloutReadiness = {
    verdict: RolloutVerdict;
    summary: {
        enabled: boolean;
        dryRun: boolean;
        sourceCount: number;
        enabledSourceCount: number;
        errorCount: number;
        warningCount: number;
        infoCount: number;
    };
    actions: {
        dryRunOverride: boolean;
        gmail: {
            label: RolloutAction;
            archive: RolloutAction;
            removeLabel: RolloutAction;
            restoreInbox: RolloutAction;
        };
        slack: {
            alert: RolloutAction;
        };
        wake: {
            agent: RolloutAction;
            aggregate: RolloutAction;
        };
        local: {
            log: RolloutAction;
        };
    };
    sources: Array<Record<string, unknown>>;
    productionChecklist: Array<{
        id: string;
        status: "pass" | "warn" | "fail";
        message: string;
    }>;
    suggestedOperations: string[];
    findings: RolloutFinding[];
};
export declare function buildRolloutReadiness(input: {
    config: PluginConfig;
    validation: Array<{
        severity: "error" | "warning";
        path: string;
        message: string;
    }>;
    status: Record<string, unknown>;
    auth: Record<string, unknown>;
}): RolloutReadiness;
export declare function buildEffectiveActions(config: PluginConfig): RolloutReadiness["actions"];
export {};
//# sourceMappingURL=rollout.d.ts.map