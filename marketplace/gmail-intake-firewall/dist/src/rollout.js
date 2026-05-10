export function buildRolloutReadiness(input) {
    const findings = input.validation.map((finding) => ({ ...finding }));
    const authSources = arrayOfRecords(input.auth.sources);
    const statusSources = arrayOfRecords(input.status.sources);
    const enabledSources = input.config.sources.filter((source) => source.enabled);
    const actionReadiness = buildActionReadiness(input.config, authSources, findings);
    const sourceReadiness = buildSourceReadiness(input.config, statusSources, authSources, findings);
    if (enabledSources.length === 0) {
        findings.push({
            severity: "error",
            path: "sources",
            message: "At least one Gmail source must be enabled before production rollout.",
        });
    }
    if (!input.config.enabled) {
        findings.push({
            severity: "warning",
            path: "enabled",
            message: "Plugin is disabled; enable it before production rollout.",
        });
    }
    if (input.config.dryRun) {
        findings.push({
            severity: "warning",
            path: "dryRun",
            message: "Global dryRun is enabled; all side effects resolve to dry_run regardless of action mode.",
        });
    }
    for (const source of enabledSources) {
        const sourceAuth = authSources.find((candidate) => candidate.sourceId === source.id);
        if (!sourceAuth || sourceAuth.ok !== true) {
            findings.push({
                severity: "error",
                path: `sources.${source.id}.authRef`,
                message: "Enabled Gmail source auth is not ready.",
            });
        }
    }
    const dedupedFindings = dedupeFindings(findings);
    const checklist = buildProductionChecklist(input.config, actionReadiness, sourceReadiness, dedupedFindings);
    const suggestedOperations = buildSuggestedOperations(input.config, sourceReadiness, dedupedFindings);
    const errorCount = dedupedFindings.filter((finding) => finding.severity === "error").length;
    const warningCount = dedupedFindings.filter((finding) => finding.severity === "warning").length;
    const infoCount = dedupedFindings.filter((finding) => finding.severity === "info").length;
    const verdict = errorCount > 0
        ? "blocked"
        : warningCount > 0 || input.config.dryRun
            ? "caution"
            : "ready";
    return {
        verdict,
        summary: {
            enabled: input.config.enabled,
            dryRun: input.config.dryRun,
            sourceCount: input.config.sources.length,
            enabledSourceCount: enabledSources.length,
            errorCount,
            warningCount,
            infoCount,
        },
        actions: actionReadiness,
        sources: sourceReadiness,
        productionChecklist: checklist,
        suggestedOperations,
        findings: dedupedFindings,
    };
}
export function buildEffectiveActions(config) {
    return {
        dryRunOverride: config.dryRun,
        gmail: {
            label: buildAction(config.actions.gmail.label.mode, config.dryRun, true),
            archive: buildAction(config.actions.gmail.archive.mode, config.dryRun, true),
            removeLabel: buildAction(config.actions.gmail.removeLabel.mode, config.dryRun, true),
            restoreInbox: buildAction(config.actions.gmail.restoreInbox.mode, config.dryRun, true),
        },
        slack: {
            alert: buildAction(config.actions.slack.alert.mode, config.dryRun, true),
        },
        wake: {
            agent: buildAction(config.actions.wake.agent.mode, config.dryRun, true),
            aggregate: buildAction(config.actions.wake.aggregate.mode, config.dryRun, true),
        },
        local: {
            log: buildAction(config.actions.local.log.mode, config.dryRun, true),
        },
    };
}
function buildActionReadiness(config, authSources, findings) {
    const liveGmailBlockedSources = config.sources
        .filter((source) => source.enabled)
        .filter((source) => {
        const authSource = authSources.find((candidate) => String(candidate.sourceId ?? candidate.id ?? "unknown") === source.id);
        return !authSource || authSource.ok !== true || authSource.canModifyGmail === false;
    })
        .map((source) => source.id);
    const gmailReady = liveGmailBlockedSources.length === 0;
    const slackReady = config.alertSinks.some((sink) => sink.enabled && sink.kind === "slack");
    const wakeReady = config.wakeTargets.length > 0;
    const actions = {
        dryRunOverride: config.dryRun,
        gmail: {
            label: buildAction(config.actions.gmail.label.mode, config.dryRun, gmailReady, liveGmailBlockedSources),
            archive: buildAction(config.actions.gmail.archive.mode, config.dryRun, gmailReady, liveGmailBlockedSources),
            removeLabel: buildAction(config.actions.gmail.removeLabel.mode, config.dryRun, gmailReady, liveGmailBlockedSources),
            restoreInbox: buildAction(config.actions.gmail.restoreInbox.mode, config.dryRun, gmailReady, liveGmailBlockedSources),
        },
        slack: {
            alert: buildAction(config.actions.slack.alert.mode, config.dryRun, slackReady),
        },
        wake: {
            agent: buildAction(config.actions.wake.agent.mode, config.dryRun, wakeReady),
            aggregate: buildAction(config.actions.wake.aggregate.mode, config.dryRun, wakeReady),
        },
        local: {
            log: buildAction(config.actions.local.log.mode, config.dryRun, true),
        },
    };
    addActionFinding(findings, "actions.gmail.label.mode", actions.gmail.label, "Gmail label action");
    addActionFinding(findings, "actions.gmail.archive.mode", actions.gmail.archive, "Gmail archive action");
    addActionFinding(findings, "actions.gmail.removeLabel.mode", actions.gmail.removeLabel, "Gmail label removal action");
    addActionFinding(findings, "actions.gmail.restoreInbox.mode", actions.gmail.restoreInbox, "Gmail inbox restore action");
    addActionFinding(findings, "actions.slack.alert.mode", actions.slack.alert, "Slack alert action");
    addActionFinding(findings, "actions.wake.agent.mode", actions.wake.agent, "Agent wake action");
    addActionFinding(findings, "actions.wake.aggregate.mode", actions.wake.aggregate, "Aggregate wake action");
    addActionFinding(findings, "actions.local.log.mode", actions.local.log, "Local log action");
    return actions;
}
function buildAction(configured, dryRun, capabilityReady, sourceIds = []) {
    const effective = dryRun ? "dry_run" : configured;
    if (effective === "live" && !capabilityReady) {
        const action = {
            configured,
            effective,
            ready: false,
            reason: "Required capability is not ready.",
        };
        if (sourceIds.length > 0) {
            action.sourceIds = sourceIds;
        }
        return action;
    }
    if (dryRun && configured === "live") {
        return {
            configured,
            effective,
            ready: true,
            reason: "Global dryRun overrides live mode.",
        };
    }
    if (effective === "disabled") {
        return {
            configured,
            effective,
            ready: true,
            reason: "Action is intentionally disabled.",
        };
    }
    if (effective === "dry_run") {
        return {
            configured,
            effective,
            ready: true,
            reason: "Action is dry-run only.",
        };
    }
    return { configured, effective, ready: true };
}
function addActionFinding(findings, path, action, label) {
    if (!action.ready) {
        findings.push({
            severity: "error",
            path,
            message: `${label} is live but required capability is not ready.`,
        });
        return;
    }
    if (action.effective === "dry_run") {
        findings.push({
            severity: "warning",
            path,
            message: `${label} is not live; effective mode is dry_run.`,
        });
    }
    else if (action.effective === "disabled") {
        findings.push({
            severity: "warning",
            path,
            message: `${label} is disabled.`,
        });
    }
}
function buildSourceReadiness(config, statusSources, authSources, findings) {
    const sourceIds = new Set([
        ...config.sources.map((source) => source.id),
        ...statusSources.map((source) => String(source.id ?? source.sourceId ?? "unknown")),
        ...authSources.map((source) => String(source.sourceId ?? source.id ?? "unknown")),
    ]);
    const sources = [];
    for (const sourceId of sourceIds) {
        const configuredSource = config.sources.find((source) => source.id === sourceId);
        const statusSource = statusSources.find((source) => String(source.id ?? source.sourceId ?? "unknown") === sourceId);
        const authSource = authSources.find((source) => String(source.sourceId ?? source.id ?? "unknown") === sourceId);
        const readiness = recordValue(statusSource?.readiness);
        const lastPoll = recordValue(statusSource?.lastPoll);
        const enabled = configuredSource?.enabled ?? authSource?.enabled ?? statusSource?.enabled;
        const item = {
            sourceId,
            enabled,
            authReady: authSource?.ok === true,
            intakeMode: readiness?.mode ?? statusSource?.intakeMode,
            canModifyGmail: authSource?.canModifyGmail ?? readiness?.canModifyGmail,
            credentialModifyScope: authSource?.credentialModifyScope ?? readiness?.credentialModifyScope,
            lastPollStatus: lastPoll?.status,
            lastPollStage: lastPoll?.stage,
        };
        for (const key of ["watchTopicConfigured", "historyCursorPresent", "watchActive", "watchNeedsRenewal", "missedNotificationRepairDue", "lastNotificationAt", "lastHistoryAt", "lastWatchRenewalAt", "lastRepairAt", "suggestedOperations"]) {
            if (readiness && key in readiness) {
                item[key] = readiness[key];
            }
        }
        if (enabled !== false && authSource?.ok !== true) {
            findings.push({
                severity: "error",
                path: `sources.${sourceId}.authRef`,
                message: "Source auth is not ready.",
            });
        }
        if (enabled !== false && readiness?.mode === "watch" && readiness.watchTopicConfigured !== true) {
            findings.push({
                severity: "error",
                path: `sources.${sourceId}.watchTopicName`,
                message: "Watch source has no Pub/Sub topic configured.",
            });
        }
        if (enabled !== false && readiness?.mode === "watch" && readiness.historyCursorPresent !== true) {
            findings.push({
                severity: "warning",
                path: `sources.${sourceId}.watch`,
                message: "Watch source has no stored Gmail history cursor; run setupWatch.",
            });
        }
        if (enabled !== false && readiness?.watchNeedsRenewal === true) {
            findings.push({
                severity: "warning",
                path: `sources.${sourceId}.watch`,
                message: "Watch needs renewal; run renewWatch.",
            });
        }
        if (enabled !== false && readiness?.missedNotificationRepairDue === true) {
            findings.push({
                severity: "warning",
                path: `sources.${sourceId}.watch`,
                message: "Watch repair is due; run repairWatch.",
            });
        }
        sources.push(item);
    }
    return sources;
}
function buildProductionChecklist(config, actions, sources, findings) {
    return [
        checklistItem("plugin-enabled", config.enabled, "Plugin is enabled.", "Plugin is disabled."),
        checklistItem("enabled-sources", config.sources.some((source) => source.enabled), "At least one Gmail source is enabled.", "No Gmail sources are enabled."),
        checklistItem("auth-ready", sources.every((source) => source.enabled === false || source.authReady === true), "All configured source auth checks pass.", "One or more source auth checks are not ready."),
        checklistItem("dry-run-reviewed", !config.dryRun, "Global dryRun is disabled for live rollout.", "Global dryRun is still enabled; safe for testing, not live rollout.", "warn"),
        checklistItem("quarantine-label", Boolean(config.security.quarantineLabel), "Quarantine label is configured.", "Quarantine label is missing."),
        checklistItem("alert-lane", actions.slack.alert.effective === "live" || actions.local.log.effective === "live", "At least one alert/log lane is live.", "No alert/log lane is live.", "warn"),
        checklistItem("action-capabilities", findings.every((finding) => !finding.path.startsWith("actions.") || finding.severity !== "error"), "Live action capabilities are ready.", "One or more live actions are blocked."),
        checklistItem("watch-ready", sources.every((source) => source.enabled === false || source.intakeMode !== "watch" || (source.watchTopicConfigured === true && source.historyCursorPresent === true)), "Watch sources have topic and cursor readiness.", "One or more watch sources need setup.", "warn"),
    ];
}
function checklistItem(id, passed, passMessage, failMessage, failStatus = "fail") {
    return {
        id,
        status: passed ? "pass" : failStatus,
        message: passed ? passMessage : failMessage,
    };
}
function buildSuggestedOperations(config, sources, findings) {
    const operations = new Set();
    operations.add("validateConfig");
    operations.add("checkSourceAuth");
    if (config.dryRun) {
        operations.add("run bounded backfill with dryRun:true");
        operations.add("review action_attempts/action_statuses");
    }
    for (const source of sources) {
        if (source.enabled === false) {
            continue;
        }
        if (source.intakeMode === "watch") {
            if (source.historyCursorPresent !== true) {
                operations.add(`setupWatch:${String(source.sourceId)}`);
            }
            if (source.watchNeedsRenewal === true) {
                operations.add(`renewWatch:${String(source.sourceId)}`);
            }
            if (source.missedNotificationRepairDue === true) {
                operations.add(`repairWatch:${String(source.sourceId)}`);
            }
        }
    }
    for (const finding of findings) {
        if (finding.path.startsWith("actions.") && finding.severity === "warning" && finding.message.includes("dry_run")) {
            operations.add(`review ${finding.path} before setting live`);
        }
    }
    return [...operations];
}
function arrayOfRecords(value) {
    return Array.isArray(value)
        ? value.filter((entry) => Boolean(recordValue(entry)))
        : [];
}
function recordValue(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}
function dedupeFindings(findings) {
    const seen = new Set();
    return findings.filter((finding) => {
        const key = `${finding.severity}:${finding.path}:${finding.message}`;
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}
