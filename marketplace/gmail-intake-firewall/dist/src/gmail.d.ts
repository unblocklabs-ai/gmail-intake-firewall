import type { AttachmentMetadata, GmailSourceConfig, InboundMessage, IntakeEvent } from "./types.js";
export type GmailCandidate = {
    id: string;
    threadId: string;
};
export type GmailWatchRegistration = {
    historyId?: string;
    expiration?: string;
};
export type GmailHistoryPage = {
    candidates: GmailCandidate[];
    historyId?: string;
};
export type GmailPushNotification = {
    sourceId?: string;
    accountEmail?: string;
    historyId: string;
};
export type GmailSourceAdapter = {
    poll(source: GmailSourceConfig, observedAt?: Date): Promise<IntakeEvent[]>;
};
export type GmailClient = {
    listCandidates(query?: string): Promise<GmailCandidate[]>;
    listHistory?(startHistoryId: string): Promise<GmailHistoryPage>;
    setupWatch?(topicName: string, labelIds?: string[]): Promise<GmailWatchRegistration>;
    fetchMessage(candidate: GmailCandidate): Promise<InboundMessage>;
    fetchThreadContext?(threadId: string, maxMessages?: number): Promise<import("./types.js").GmailThreadContext | undefined>;
    applyLabel(messageId: string, label: string): Promise<void>;
    removeLabel?(messageId: string, label: string): Promise<void>;
    archive(messageId: string): Promise<void>;
    restoreInbox?(messageId: string): Promise<void>;
};
export declare function candidateToIntakeEvent(source: GmailSourceConfig, candidate: GmailCandidate, observedAt?: Date): IntakeEvent;
export declare function buildCandidateQuery(source: GmailSourceConfig): string | undefined;
export declare function extractAttachmentMetadata(parts: unknown[]): AttachmentMetadata[];
export declare function parseGmailPushNotification(input: unknown): GmailPushNotification;
//# sourceMappingURL=gmail.d.ts.map