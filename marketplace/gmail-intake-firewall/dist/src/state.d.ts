import type { ActionExecutionStatus } from "./actions.js";
import type { AggregateItem, DecisionLogEntry, IntakeEvent } from "./types.js";
export type FirewallState = {
    processed: Record<string, string>;
    decisions: DecisionLogEntry[];
    aggregateQueue: AggregateItem[];
};
export declare function processedKey(sourceId: string, messageId: string): string;
export declare function createEmptyState(): FirewallState;
export declare function isProcessed(state: FirewallState, sourceId: string, messageId: string): boolean;
export declare function recordDecision(state: FirewallState, decision: DecisionLogEntry): FirewallState;
export declare function loadState(path: string): Promise<FirewallState>;
export declare function saveState(path: string, state: FirewallState): Promise<void>;
export type SqliteStateStore = {
    readonly path: string;
    isProcessed(sourceId: string, messageId: string): boolean;
    recordDecision(decision: DecisionLogEntry): void;
    recordDecisionPlan(decision: DecisionLogEntry): void;
    markProcessed(sourceId: string, messageId: string, processedAt: string): void;
    recordActionStatus(decision: DecisionLogEntry, status: ActionExecutionStatus, attemptedAt?: string): void;
    listActionStatuses(sourceId: string, messageId: string): Array<Record<string, unknown>>;
    listActionAttempts(sourceId: string, messageId: string): Array<Record<string, unknown>>;
    enqueueAggregate(item: AggregateItem): void;
    listAggregateQueue(limit?: number): AggregateItem[];
    markAggregateDelivered(items: AggregateItem[], deliveredAt?: string): void;
    recordEvent(event: IntakeEvent): void;
    recordFeedback(event: Record<string, unknown>): void;
    listFeedbackEvents(limit?: number): Array<Record<string, unknown>>;
    getSourceCursor(sourceId: string): Record<string, unknown> | undefined;
    setSourceCursor(sourceId: string, cursor: Record<string, unknown>, updatedAt?: string): void;
    close(): void;
};
export declare function openSqliteStateStore(path: string): SqliteStateStore;
//# sourceMappingURL=state.d.ts.map