export function createDetachedAgentWakeRuntime(api) {
    const host = api && typeof api === "object" ? api : {};
    return {
        async startDetachedAgentTurn(payload) {
            const runtime = host.runtime && typeof host.runtime === "object"
                ? host.runtime
                : {};
            const agent = runtime.agent && typeof runtime.agent === "object"
                ? runtime.agent
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
