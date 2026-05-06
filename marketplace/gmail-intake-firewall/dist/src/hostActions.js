import { createDetachedAgentWakeRuntime } from "./wake.js";
export function createHostActionDeps(host, logger) {
    const deps = {
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
function createHostSlackAlert(host) {
    const raw = host && typeof host === "object" ? host : {};
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
function objectValue(value) {
    return value && typeof value === "object" ? value : undefined;
}
