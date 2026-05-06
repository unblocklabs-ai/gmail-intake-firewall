import type { ActionExecutorDeps } from "./actions.js";
type Logger = {
    info?: (message: string, metadata?: Record<string, unknown>) => void;
};
export declare function createHostActionDeps(host: unknown, logger?: Logger): ActionExecutorDeps;
export {};
//# sourceMappingURL=hostActions.d.ts.map