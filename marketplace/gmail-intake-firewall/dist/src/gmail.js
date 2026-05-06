import { collectAttachmentMetadata } from "./gmailMime.js";
export function candidateToIntakeEvent(source, candidate, observedAt = new Date()) {
    return {
        sourceId: source.id,
        accountEmail: source.accountEmail,
        messageId: candidate.id,
        threadId: candidate.threadId,
        eventType: "poll_candidate",
        observedAt: observedAt.toISOString(),
    };
}
export function buildCandidateQuery(source) {
    const parts = [source.candidateQuery, source.include, source.exclude ? `-(${source.exclude})` : undefined]
        .filter((part) => Boolean(part));
    return parts.length > 0 ? parts.join(" ") : undefined;
}
export function extractAttachmentMetadata(parts) {
    return parts.flatMap((part) => collectAttachmentMetadata(part));
}
export function parseGmailPushNotification(input) {
    if (!input || typeof input !== "object") {
        throw new Error("Gmail notification must be an object");
    }
    const raw = input;
    const attributes = objectValue(raw.attributes) ?? objectValue(objectValue(raw.message)?.attributes);
    const decoded = decodeGmailNotificationData(raw);
    const sourceId = stringValue(raw.sourceId) ?? stringValue(attributes?.sourceId) ?? stringValue(decoded?.sourceId);
    const accountEmail = stringValue(raw.accountEmail)
        ?? stringValue(raw.emailAddress)
        ?? stringValue(attributes?.accountEmail)
        ?? stringValue(attributes?.emailAddress)
        ?? stringValue(decoded?.accountEmail)
        ?? stringValue(decoded?.emailAddress);
    const historyId = stringValue(raw.historyId)
        ?? stringValue(attributes?.historyId)
        ?? stringValue(decoded?.historyId);
    if (!historyId) {
        throw new Error("Gmail notification missing historyId");
    }
    return {
        ...(sourceId ? { sourceId } : {}),
        ...(accountEmail ? { accountEmail } : {}),
        historyId,
    };
}
function decodeGmailNotificationData(raw) {
    const message = objectValue(raw.message);
    const data = stringValue(message?.data) ?? stringValue(raw.data);
    if (!data) {
        return undefined;
    }
    try {
        const normalized = data.replace(/-/g, "+").replace(/_/g, "/");
        const decoded = Buffer.from(normalized, "base64").toString("utf8");
        const parsed = JSON.parse(decoded);
        return objectValue(parsed);
    }
    catch {
        return undefined;
    }
}
function objectValue(value) {
    return value && typeof value === "object" ? value : undefined;
}
function stringValue(value) {
    if (typeof value === "string" && value.trim()) {
        return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
        return String(value);
    }
    return undefined;
}
