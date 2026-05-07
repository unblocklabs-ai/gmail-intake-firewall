import { extractLinksFromGmailContent, normalizeLinks, sanitizeGmailBody } from "./gmailSanitize.js";
import { analyzeLinks, summarizeLinkMetadata } from "./linkAnalysis.js";
import { analyzeAttachments } from "./attachmentAnalysis.js";
const DEFAULT_MALICIOUS_THRESHOLD = 0.65;
const DEFAULT_UNCERTAIN_THRESHOLD = 0.35;
export function shouldQuarantine(classification, security) {
    if (classification.verdict === "malicious") {
        return true;
    }
    if (classification.verdict === "risky") {
        return classification.riskScore >= numericThreshold(security.maliciousThreshold, DEFAULT_MALICIOUS_THRESHOLD);
    }
    if (classification.verdict === "uncertain") {
        return security.failClosedOnUncertain !== false ||
            classification.riskScore >= numericThreshold(security.uncertainThreshold, DEFAULT_UNCERTAIN_THRESHOLD);
    }
    return false;
}
function numericThreshold(value, fallback) {
    return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
export function normalizeMessageForSecurity(message, maxBodyChars, artifacts = {
    analyzeLinks: true,
    analyzeAttachments: true,
    fetchLinks: false,
    downloadAttachments: false,
    maxDisplayedUrlChars: 160,
}) {
    const textBody = sanitizeGmailBody(message.bodyText, false);
    const htmlText = sanitizeGmailBody(message.bodyHtml, true);
    const bodyText = clipText([textBody, htmlText].filter(Boolean).join("\n\n"), maxBodyChars);
    const normalizedLinks = normalizeLinks([
        ...(message.linkUrls ?? []),
        ...extractLinksFromGmailContent(message.bodyText, message.bodyHtml),
    ]);
    const links = artifacts.analyzeLinks
        ? analyzeLinks(normalizedLinks, artifacts.maxDisplayedUrlChars)
        : normalizedLinks.map((link) => summarizeLinkMetadata(link, artifacts.maxDisplayedUrlChars));
    const attachments = artifacts.analyzeAttachments
        ? analyzeAttachments(message.attachments)
        : message.attachments.map((attachment) => ({
            ...attachment,
            riskHints: [],
            hasAttachmentId: Boolean(attachment.id),
        }));
    const artifactAnalysis = {
        links,
        attachments,
        notes: buildArtifactNotes(artifacts),
    };
    const authHeaders = pickAuthHeaders(message.headers);
    const replyTo = headerValue(message.headers, "reply-to");
    const normalized = {
        sourceId: message.sourceId,
        accountEmail: message.accountEmail,
        messageId: message.messageId,
        threadId: message.threadId,
        headers: message.headers,
        rawHeaders: message.rawHeaders,
        authHeaders,
        to: message.to,
        cc: message.cc,
        labels: message.labels,
        bodyText,
        links,
        attachments,
        artifactAnalysis,
    };
    if (message.from) {
        normalized.from = message.from;
    }
    if (replyTo) {
        normalized.replyTo = replyTo;
    }
    if (message.subject) {
        normalized.subject = message.subject;
    }
    if (message.snippet) {
        normalized.snippet = message.snippet;
    }
    if (message.threadContext) {
        normalized.threadContext = message.threadContext;
    }
    return normalized;
}
function buildArtifactNotes(artifacts) {
    return [
        artifacts.analyzeLinks
            ? "Links were structurally analyzed only; URLs were not fetched."
            : "Link analysis was disabled by config; URLs were normalized only and were not fetched.",
        artifacts.analyzeAttachments
            ? "Attachments were metadata-analyzed only; attachment bytes were not downloaded or opened."
            : "Attachment analysis was disabled by config; attachment bytes were not downloaded or opened.",
    ];
}
function clipText(value, maxChars) {
    return value.length <= maxChars ? value : value.slice(0, maxChars);
}
function headerValue(headers, name) {
    const lower = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === lower) {
            return value;
        }
    }
    return undefined;
}
function pickAuthHeaders(headers) {
    const wanted = new Set(["authentication-results", "received-spf", "dkim-signature", "arc-authentication-results"]);
    return Object.fromEntries(Object.entries(headers).filter(([key]) => wanted.has(key.toLowerCase())));
}
export function createUnavailableSecurityClassifier() {
    return {
        async classify() {
            return {
                verdict: "uncertain",
                riskScore: 1,
                categories: ["classifier_unavailable"],
                reasons: ["No standalone LLM security classifier has been configured."],
                safeSummary: "Message held because the security classifier is unavailable.",
                suspiciousSignals: ["classifier_unavailable"],
            };
        },
    };
}
