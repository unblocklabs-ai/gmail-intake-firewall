export type WakeMode = "none" | "wake_now" | "aggregate";
export type SecurityVerdict = "safe" | "uncertain" | "risky" | "malicious";
export type AlertSinkKind = "slack" | "local_log";
export type IntakeMode = "watch" | "history" | "poll";
export type ActionExecutionMode = "live" | "dry_run" | "disabled";
export type SecretRef = {
    source: string;
    provider: string;
    id: string;
};
export type GmailSourceConfig = {
    id: string;
    accountEmail: string;
    authRef?: SecretRef | Record<string, unknown>;
    credentialRef?: SecretRef | Record<string, unknown>;
    enabled: boolean;
    candidateQuery?: string;
    include?: string;
    exclude?: string;
    defaultRoutingPolicy?: string;
    intakeMode?: IntakeMode;
    watchTopicName?: string;
    historyLookback?: string;
    polling: {
        intervalMs: number;
        maxResults: number;
    };
    gmailActions: {
        hasModifyScope: boolean;
    };
};
export type SecurityConfig = {
    quarantineLabel: string;
    provider?: string;
    model?: string;
    maxBodyChars: number;
    maliciousThreshold: number;
    uncertainThreshold: number;
    failClosedOnUncertain: boolean;
    includeSnippetInAlerts: boolean;
    alertTarget?: string;
    archiveOnQuarantine: boolean;
};
export type TagConfig = {
    id: string;
    description: string;
    gmailLabel?: string;
    wakeMode: WakeMode;
    aggregateCadence?: string;
    wakeTarget?: string;
};
export type WakeTargetConfig = {
    id: string;
    agentId: string;
    workspaceDir?: string;
    sessionId?: string;
    deliveryContext?: Record<string, unknown>;
};
export type AlertSinkConfig = {
    id: string;
    kind: AlertSinkKind;
    target?: string;
    enabled: boolean;
};
export type ArtifactConfig = {
    analyzeLinks: boolean;
    analyzeAttachments: boolean;
    fetchLinks: boolean;
    downloadAttachments: boolean;
    maxDisplayedUrlChars: number;
};
export type WatchConfig = {
    autoSetup: boolean;
    renewBeforeMs: number;
    repairOnNoNotificationMs: number;
    labelIds: string[];
    labelFilterBehavior: "INCLUDE" | "EXCLUDE";
};
export type ActionModeConfig = {
    mode: ActionExecutionMode;
};
export type ActionsConfig = {
    gmail: {
        label: ActionModeConfig;
        archive: ActionModeConfig;
        removeLabel: ActionModeConfig;
        restoreInbox: ActionModeConfig;
    };
    slack: {
        alert: ActionModeConfig;
    };
    wake: {
        agent: ActionModeConfig;
        aggregate: ActionModeConfig;
    };
    local: {
        log: ActionModeConfig;
    };
};
export type PluginConfig = {
    enabled: boolean;
    dryRun: boolean;
    webhookSecret?: string;
    openaiApiKeyRef?: SecretRef | Record<string, unknown>;
    OPENAI_API_KEY?: string;
    openai_model: string;
    statePath: string;
    sqlitePath: string;
    sources: GmailSourceConfig[];
    security: SecurityConfig;
    tags: TagConfig[];
    wakeTargets: WakeTargetConfig[];
    alertSinks: AlertSinkConfig[];
    aggregate: {
        maxDigestItems: number;
        timezone: string;
    };
    artifacts: ArtifactConfig;
    watch: WatchConfig;
    actions: ActionsConfig;
};
export type RoutingPreference = {
    type: "mute" | "always_aggregate";
    scope: "sender" | "domain";
    sourceId: string;
    value: string;
    createdAt: string;
    actor?: string;
    reason?: string;
};
export type AttachmentMetadata = {
    id?: string;
    filename?: string;
    mimeType?: string;
    size?: number;
};
export type EmailHeader = {
    name: string;
    value: string;
};
export type InboundMessage = {
    sourceId: string;
    accountEmail: string;
    messageId: string;
    threadId: string;
    headers: Record<string, string>;
    rawHeaders: EmailHeader[];
    from?: string;
    to: string[];
    cc: string[];
    bcc: string[];
    subject?: string;
    labels: string[];
    snippet?: string;
    bodyText?: string;
    bodyHtml?: string;
    linkUrls?: string[];
    attachments: AttachmentMetadata[];
    receivedAt?: string;
    threadContext?: GmailThreadContext;
};
export type NormalizedLink = {
    url: string;
    domain?: string;
    registrableDomain?: string;
    scheme?: string;
    riskHints?: string[];
    isShortener?: boolean;
    isIpLiteral?: boolean;
    isPunycode?: boolean;
    isHttps?: boolean;
    unusualPort?: string;
    pathExtension?: string;
};
export type LinkRiskMetadata = Required<Pick<NormalizedLink, "url" | "domain" | "riskHints">> & {
    registrableDomain?: string;
    scheme?: string;
    isShortener?: boolean;
    isIpLiteral?: boolean;
    isPunycode?: boolean;
    isHttps?: boolean;
    unusualPort?: string;
    pathExtension?: string;
};
export type AttachmentRiskMetadata = AttachmentMetadata & {
    extension?: string;
    riskHints: string[];
    hasAttachmentId: boolean;
    isArchive?: boolean;
    isMacroCapable?: boolean;
    isExecutable?: boolean;
    isScript?: boolean;
    hasDoubleExtension?: boolean;
    mimeExtensionMismatch?: boolean;
};
export type ArtifactAnalysis = {
    links: LinkRiskMetadata[];
    attachments: AttachmentRiskMetadata[];
    notes: string[];
};
export type NormalizedMessageForClassification = {
    sourceId: string;
    accountEmail: string;
    messageId: string;
    threadId: string;
    headers: Record<string, string>;
    rawHeaders: EmailHeader[];
    authHeaders: Record<string, string>;
    from?: string;
    replyTo?: string;
    to: string[];
    cc: string[];
    subject?: string;
    labels: string[];
    snippet?: string;
    bodyText: string;
    links: LinkRiskMetadata[];
    attachments: AttachmentRiskMetadata[];
    artifactAnalysis: ArtifactAnalysis;
    threadContext?: GmailThreadContext;
};
export type SecurityClassification = {
    verdict: SecurityVerdict;
    riskScore: number;
    categories: string[];
    reasons: string[];
    safeSummary: string;
    suspiciousSignals: string[];
};
export type RoutingClassification = {
    tags: string[];
    wakeMode: WakeMode;
    wakeTarget?: string;
    sanitizedSummary: string;
    reasons: string[];
};
export type DecisionLogEntry = {
    processedAt: string;
    sourceId: string;
    accountEmail: string;
    messageId: string;
    threadId: string;
    security: SecurityClassification;
    routing?: RoutingClassification;
    artifactAnalysis?: ArtifactAnalysis;
    actions: PlannedAction[];
    dryRun: boolean;
};
export type PlannedAction = {
    type: "gmail_label";
    label: string;
    messageId: string;
} | {
    type: "gmail_remove_label";
    label: string;
    messageId: string;
} | {
    type: "gmail_archive";
    messageId: string;
} | {
    type: "gmail_restore_inbox";
    messageId: string;
} | {
    type: "human_alert";
    sink: AlertSinkKind;
    target?: string;
    summary: string;
    payload?: Record<string, unknown>;
} | {
    type: "local_log";
    summary: string;
    payload?: Record<string, unknown>;
} | {
    type: "agent_wake";
    target?: string;
    payload: AgentWakePayload;
} | {
    type: "aggregate_enqueue";
    cadence?: string;
    item: AggregateItem;
} | {
    type: "record_only";
    reason: string;
};
export type AgentWakePayload = {
    sourceId: string;
    accountEmail: string;
    messageId: string;
    threadId: string;
    subject?: string;
    from?: string;
    tags: string[];
    sanitizedSummary: string;
    security: SecurityClassification;
    artifacts?: ArtifactWakeSummary;
    wakeTarget?: WakeTargetConfig;
};
export type ArtifactWakeSummary = {
    linkCount: number;
    linkDomains: string[];
    linkRiskHints: string[];
    attachmentCount: number;
    attachments: AttachmentRiskMetadata[];
    attachmentRiskHints: string[];
};
export type AggregateItem = {
    sourceId: string;
    accountEmail: string;
    messageId: string;
    threadId: string;
    tags: string[];
    sanitizedSummary: string;
    queuedAt: string;
    wakeTarget?: string;
    cadence?: string;
};
export type ProcessSkipReason = "plugin_disabled" | "unknown_source" | "source_disabled" | "already_processed";
export type IntakeEvent = {
    sourceId: string;
    accountEmail: string;
    messageId: string;
    threadId?: string;
    eventType: "poll_candidate" | "gmail_history" | "gmail_watch";
    observedAt: string;
};
export type GmailThreadContext = {
    threadId: string;
    participants: string[];
    labels: string[];
    messages: Array<{
        messageId: string;
        from?: string;
        subject?: string;
        date?: string;
        snippet?: string;
    }>;
};
//# sourceMappingURL=types.d.ts.map