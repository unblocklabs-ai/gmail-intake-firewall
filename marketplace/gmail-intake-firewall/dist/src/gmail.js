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
