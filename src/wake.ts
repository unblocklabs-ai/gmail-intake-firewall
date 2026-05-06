import type { AgentWakePayload } from "./types.js";

export type DetachedAgentWakeRuntime = {
  startDetachedAgentTurn(payload: AgentWakePayload): Promise<void>;
};

export function createDetachedAgentWakeRuntime(api: unknown): DetachedAgentWakeRuntime {
  const host = api && typeof api === "object" ? api as Record<string, unknown> : {};
  return {
    async startDetachedAgentTurn(payload: AgentWakePayload): Promise<void> {
      const runtime = host.runtime && typeof host.runtime === "object"
        ? host.runtime as Record<string, unknown>
        : {};
      const agent = runtime.agent && typeof runtime.agent === "object"
        ? runtime.agent as Record<string, unknown>
        : {};
      const startDetached = agent.startDetachedTurn ?? agent.startDetachedAgentTurn ?? host.startDetachedAgentTurn;
      if (typeof startDetached !== "function") {
        throw new Error("OpenClaw detached agent wake API is unavailable");
      }
      await startDetached.call(agent, {
        agentId: payload.wakeTarget?.agentId,
        workspaceDir: payload.wakeTarget?.workspaceDir,
        sessionId: payload.wakeTarget?.sessionId,
        deliveryContext: payload.wakeTarget?.deliveryContext,
        input: {
          source: "gmail-intake-firewall",
          messageId: payload.messageId,
          threadId: payload.threadId,
          accountEmail: payload.accountEmail,
          subject: payload.subject,
          from: payload.from,
          tags: payload.tags,
          summary: payload.sanitizedSummary,
          security: payload.security,
        },
      });
    },
  };
}
