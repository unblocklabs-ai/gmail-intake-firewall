import { type ActionExecutorDeps } from "./actions.js";
import { type GmailClient } from "./gmail.js";
import { type ProcessMessageDeps } from "./engine.js";
import { type SqliteStateStore } from "./state.js";
import type { GmailSourceConfig, PluginConfig } from "./types.js";
export type GmailClientFactory = (source: GmailSourceConfig) => Promise<GmailClient> | GmailClient;
export type RuntimeLogger = {
    info?: (message: string, metadata?: Record<string, unknown>) => void;
    warn?: (message: string, metadata?: Record<string, unknown>) => void;
    error?: (message: string, metadata?: Record<string, unknown>) => void;
};
export type PollingRuntimeDeps = Partial<ProcessMessageDeps> & {
    stateStore: SqliteStateStore;
    gmailClientFactory: GmailClientFactory;
    actionDeps?: ActionExecutorDeps;
    logger?: RuntimeLogger;
    now?: () => Date;
    setInterval?: typeof setInterval;
    clearInterval?: typeof clearInterval;
};
export type PollingRunSummary = {
    sources: number;
    events: number;
    fetched: number;
    processed: number;
    skipped: number;
    errors: number;
};
export type BackfillOptions = {
    sourceId: string;
    query?: string;
    maxResults?: number;
    force?: boolean;
    dryRun?: boolean;
};
export declare class GmailIntakePollingRuntime {
    private readonly config;
    private readonly deps;
    private readonly timers;
    private readonly inFlightSources;
    private running;
    constructor(config: PluginConfig, deps: PollingRuntimeDeps);
    start(): PollingRunSummary;
    stop(): void;
    runOnce(): Promise<PollingRunSummary>;
    runBackfill(options: BackfillOptions): Promise<PollingRunSummary>;
    drainAggregates(now?: Date): Promise<PollingRunSummary>;
    probe(): Record<string, unknown>;
    private runSource;
    private processEvent;
    private enabledSources;
    private listSourceCandidates;
    private listHistoryOrRepair;
    private emptySummary;
    private now;
}
export declare function createUnavailableGmailClientFactory(): GmailClientFactory;
//# sourceMappingURL=runtime.d.ts.map