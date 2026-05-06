import type { ActionExecutorDeps } from "./actions.js";
import { createDetachedAgentWakeRuntime } from "./wake.js";

type Logger = {
  info?: (message: string, metadata?: Record<string, unknown>) => void;
};

export function createHostActionDeps(host: unknown, logger?: Logger): ActionExecutorDeps {
  const deps: ActionExecutorDeps = {
    wake: createDetachedAgentWakeRuntime(host),
    localLog: {
      async write(summary, payload) {
        logger?.info?.("gmail-intake-firewall local log", { summary, payload });
      },
    },
  };
  const slack = createHostSlackAlert(host);
  if (slack) {
    deps.slack = slack;
  }
  return deps;
}

function createHostSlackAlert(host: unknown): ActionExecutorDeps["slack"] {
  const raw = host && typeof host === "object" ? host as Record<string, unknown> : {};
  const slack = objectValue(raw.slack) ?? objectValue(raw.alerts) ?? objectValue(raw.notifications);
  return {
    async postAlert(target, summary, payload) {
      const postAlert = slack?.postAlert ?? raw.postSlackAlert;
      if (typeof postAlert === "function") {
        await postAlert.call(slack ?? raw, { target, summary, payload });
        return;
      }
      const postMessage = slack?.postMessage ?? raw.postSlackMessage;
      if (typeof postMessage === "function") {
        await postMessage.call(slack ?? raw, {
          channel: target,
          text: summary,
          payload,
        });
        return;
      }
      throw new Error("Slack alert API is unavailable");
    },
  };
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" ? value as Record<string, unknown> : undefined;
}
