import type { AgentWakePayload } from "./types.js";
export type DetachedAgentWakeRuntime = {
    startDetachedAgentTurn(payload: AgentWakePayload): Promise<void>;
};
export declare function createDetachedAgentWakeRuntime(api: unknown): DetachedAgentWakeRuntime;
//# sourceMappingURL=wake.d.ts.map