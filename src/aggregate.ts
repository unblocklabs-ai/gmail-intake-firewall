import type { AggregateItem, AgentWakePayload } from "./types.js";

export function buildDigestWake(items: AggregateItem[], target?: string): AgentWakePayload | undefined {
  if (items.length === 0) {
    return undefined;
  }
  const first = items[0];
  if (!first) {
    return undefined;
  }
  return {
    sourceId: first.sourceId,
    accountEmail: first.accountEmail,
    messageId: `digest:${items.map((item) => item.messageId).join(",")}`,
    threadId: `digest:${new Date().toISOString()}`,
    tags: [...new Set(items.flatMap((item) => item.tags))],
    sanitizedSummary: items.map((item) => `- ${item.sanitizedSummary}`).join("\n"),
    security: {
      verdict: "safe",
      riskScore: 0,
      categories: [],
      reasons: ["Aggregate digest contains only items that passed security classification."],
      safeSummary: "Aggregate digest of safe Gmail intake items.",
      suspiciousSignals: [],
    },
    ...(target ? { subject: "Gmail intake digest", from: target } : { subject: "Gmail intake digest" }),
  };
}
