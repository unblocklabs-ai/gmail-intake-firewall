export function buildQuarantineActions(message, classification, config, source, artifactAnalysis) {
    const actions = [];
    if (canApplyGmailModifications(source) && source.gmailActions.applyLabels) {
        actions.push({ type: "gmail_label", label: config.security.quarantineLabel, messageId: message.messageId });
    }
    if (canApplyGmailModifications(source) && source.gmailActions.archive && config.security.archiveOnQuarantine) {
        actions.push({ type: "gmail_archive", messageId: message.messageId });
    }
    for (const sink of config.alertSinks.filter((candidate) => candidate.enabled)) {
        if (sink.kind === "local_log") {
            actions.push({ type: "local_log", summary: classification.safeSummary, payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts, artifactAnalysis) });
            continue;
        }
        if (sink.kind === "slack") {
            const alert = {
                type: "human_alert",
                sink: "slack",
                summary: classification.safeSummary,
                payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts, artifactAnalysis),
            };
            const target = sink.target ?? config.security.alertTarget;
            if (target) {
                alert.target = target;
            }
            actions.push(alert);
        }
    }
    if (!actions.some((action) => action.type === "human_alert" || action.type === "local_log")) {
        actions.push({ type: "local_log", summary: classification.safeSummary, payload: buildSuspiciousAlertPayload(message, classification, config.security.includeSnippetInAlerts, artifactAnalysis) });
    }
    return actions;
}
export async function executePlannedActions(actions, dryRun, deps) {
    if (dryRun) {
        return actions.map((action, actionIndex) => ({
            actionIndex,
            action,
            required: isRequiredExecutableAction(action),
            status: "skipped_dry_run",
        }));
    }
    const results = [];
    for (const action of actions) {
        const actionIndex = results.length;
        const required = isRequiredExecutableAction(action);
        try {
            if (action.type === "gmail_label") {
                if (!deps.gmail) {
                    throw new Error("Gmail action executor is not configured");
                }
                await deps.gmail.applyLabel(action.messageId, action.label);
            }
            else if (action.type === "gmail_remove_label") {
                if (!deps.gmail?.removeLabel) {
                    throw new Error("Gmail label removal executor is not configured");
                }
                await deps.gmail.removeLabel(action.messageId, action.label);
            }
            else if (action.type === "gmail_archive") {
                if (!deps.gmail) {
                    throw new Error("Gmail action executor is not configured");
                }
                await deps.gmail.archive(action.messageId);
            }
            else if (action.type === "gmail_restore_inbox") {
                if (!deps.gmail?.restoreInbox) {
                    throw new Error("Gmail inbox restore executor is not configured");
                }
                await deps.gmail.restoreInbox(action.messageId);
            }
            else if (action.type === "human_alert" && action.sink === "slack") {
                if (!deps.slack) {
                    throw new Error("Slack alert executor is not configured");
                }
                await deps.slack.postAlert(action.target, action.summary, action.payload);
            }
            else if (action.type === "local_log") {
                await deps.localLog?.write(action.summary, action.payload);
            }
            else if (action.type === "agent_wake") {
                if (!deps.wake) {
                    throw new Error("Detached wake executor is not configured");
                }
                await deps.wake.startDetachedAgentTurn(action.payload);
            }
            results.push({ actionIndex, action, required, status: "succeeded" });
        }
        catch (error) {
            const failed = {
                actionIndex,
                action,
                required,
                status: "failed",
            };
            if (error instanceof Error) {
                failed.error = error.message;
            }
            else {
                failed.error = String(error);
            }
            results.push(failed);
        }
    }
    return results;
}
export function requiredActionsSucceeded(results) {
    return results.every((result) => !result.required || result.status !== "failed");
}
function isRequiredExecutableAction(action) {
    return action.type === "gmail_label"
        || action.type === "gmail_remove_label"
        || action.type === "gmail_archive"
        || action.type === "gmail_restore_inbox"
        || action.type === "human_alert"
        || action.type === "agent_wake";
}
export function buildSafeRoutingActions(message, routing, security, tags, wakeTargets, source, artifactAnalysis) {
    const actions = [];
    const policy = resolveRoutingPolicy(routing, tags, wakeTargets);
    for (const tag of policy.tags) {
        if (tag?.gmailLabel && canApplyGmailModifications(source) && source.gmailActions.applyLabels) {
            actions.push({ type: "gmail_label", label: tag.gmailLabel, messageId: message.messageId });
        }
    }
    if (policy.wakeMode === "wake_now" && policy.wakeTarget) {
        const wakeAction = {
            type: "agent_wake",
            target: policy.wakeTarget.id,
            payload: buildWakePayload(message, routing, security, artifactAnalysis),
        };
        wakeAction.payload.wakeTarget = policy.wakeTarget;
        actions.push(wakeAction);
    }
    else if (policy.wakeMode === "aggregate") {
        const item = buildAggregateItem(message, routing);
        if (policy.aggregateCadence) {
            item.cadence = policy.aggregateCadence;
        }
        const aggregateAction = {
            type: "aggregate_enqueue",
            item,
        };
        if (policy.aggregateCadence) {
            aggregateAction.cadence = policy.aggregateCadence;
        }
        actions.push(aggregateAction);
    }
    else if (actions.length === 0) {
        actions.push({ type: "record_only", reason: "safe_message_no_wake" });
    }
    return actions;
}
function canApplyGmailModifications(source) {
    return source.gmailActions.enabled && source.gmailActions.hasModifyScope;
}
function buildWakePayload(message, routing, security, artifactAnalysis) {
    const payload = {
        sourceId: message.sourceId,
        accountEmail: message.accountEmail,
        messageId: message.messageId,
        threadId: message.threadId,
        tags: routing.tags,
        sanitizedSummary: routing.sanitizedSummary,
        security,
    };
    const artifactSummary = buildArtifactWakeSummary(artifactAnalysis);
    if (artifactSummary) {
        payload.artifacts = artifactSummary;
    }
    if (message.subject) {
        payload.subject = message.subject;
    }
    if (message.from) {
        payload.from = message.from;
    }
    return payload;
}
function resolveRoutingPolicy(routing, tags, wakeTargets) {
    const validTags = routing.tags
        .map((tagId) => tags.find((tag) => tag.id === tagId))
        .filter((tag) => Boolean(tag));
    const wakeTag = validTags.find((tag) => tag.wakeMode === "wake_now" && tag.wakeTarget);
    if (wakeTag?.wakeTarget) {
        const wakeTarget = wakeTargets.find((target) => target.id === wakeTag.wakeTarget);
        if (wakeTarget) {
            return { tags: validTags, wakeMode: "wake_now", wakeTarget };
        }
    }
    const aggregateTag = validTags.find((tag) => tag.wakeMode === "aggregate");
    if (aggregateTag) {
        const policy = {
            tags: validTags,
            wakeMode: "aggregate",
        };
        if (aggregateTag.aggregateCadence) {
            policy.aggregateCadence = aggregateTag.aggregateCadence;
        }
        return policy;
    }
    return { tags: validTags, wakeMode: "none" };
}
function buildAggregateItem(message, routing) {
    const item = {
        sourceId: message.sourceId,
        accountEmail: message.accountEmail,
        messageId: message.messageId,
        threadId: message.threadId,
        tags: routing.tags,
        sanitizedSummary: routing.sanitizedSummary,
        queuedAt: new Date().toISOString(),
    };
    if (routing.wakeTarget) {
        item.wakeTarget = routing.wakeTarget;
    }
    return item;
}
function buildSuspiciousAlertPayload(message, classification, includeSnippet, artifactAnalysis) {
    const artifactSummary = buildArtifactWakeSummary(artifactAnalysis);
    const payload = {
        sourceId: message.sourceId,
        accountEmail: message.accountEmail,
        sender: message.from,
        replyTo: findHeader(message.headers, "reply-to"),
        recipients: message.to,
        cc: message.cc,
        subject: message.subject,
        date: findHeader(message.headers, "date"),
        messageId: message.messageId,
        threadId: message.threadId,
        gmailLink: `https://mail.google.com/mail/u/${encodeURIComponent(message.accountEmail)}/#all/${encodeURIComponent(message.messageId)}`,
        labels: message.labels,
        authHeaders: {
            authenticationResults: findHeader(message.headers, "authentication-results"),
            receivedSpf: findHeader(message.headers, "received-spf"),
            dkimSignature: findHeader(message.headers, "dkim-signature"),
            arcAuthenticationResults: findHeader(message.headers, "arc-authentication-results"),
        },
        linkDomains: artifactSummary?.linkDomains ?? Array.from(new Set((message.linkUrls ?? []).flatMap((url) => {
            try {
                return [new URL(url).hostname.toLowerCase()];
            }
            catch {
                return [];
            }
        }))),
        links: artifactAnalysis?.links,
        linkRiskHints: artifactSummary?.linkRiskHints,
        attachments: artifactAnalysis?.attachments ?? message.attachments,
        attachmentRiskHints: artifactSummary?.attachmentRiskHints,
        artifactNotes: artifactAnalysis?.notes,
        riskReasons: classification.reasons,
        suspiciousSignals: classification.suspiciousSignals,
        sanitizedSummary: classification.safeSummary,
    };
    if (includeSnippet && message.snippet) {
        payload.snippet = message.snippet;
    }
    return payload;
}
function buildArtifactWakeSummary(artifactAnalysis) {
    if (!artifactAnalysis) {
        return undefined;
    }
    return {
        linkCount: artifactAnalysis.links.length,
        linkDomains: Array.from(new Set(artifactAnalysis.links.map((link) => link.domain).filter(Boolean))),
        linkRiskHints: Array.from(new Set(artifactAnalysis.links.flatMap((link) => link.riskHints))),
        attachmentCount: artifactAnalysis.attachments.length,
        attachments: artifactAnalysis.attachments,
        attachmentRiskHints: Array.from(new Set(artifactAnalysis.attachments.flatMap((attachment) => attachment.riskHints))),
    };
}
function findHeader(headers, name) {
    const lowerName = name.toLowerCase();
    return Object.entries(headers).find(([key]) => key.toLowerCase() === lowerName)?.[1];
}
