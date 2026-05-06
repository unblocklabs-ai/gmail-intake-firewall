import type { AttachmentMetadata, GmailSourceConfig, InboundMessage, IntakeEvent } from "./types.js";
import { collectAttachmentMetadata, type GmailMessagePart } from "./gmailMime.js";

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
  archive(messageId: string): Promise<void>;
};

export function candidateToIntakeEvent(
  source: GmailSourceConfig,
  candidate: GmailCandidate,
  observedAt = new Date(),
): IntakeEvent {
  return {
    sourceId: source.id,
    accountEmail: source.accountEmail,
    messageId: candidate.id,
    threadId: candidate.threadId,
    eventType: "poll_candidate",
    observedAt: observedAt.toISOString(),
  };
}

export function buildCandidateQuery(source: GmailSourceConfig): string | undefined {
  const parts = [source.candidateQuery, source.include, source.exclude ? `-(${source.exclude})` : undefined]
    .filter((part): part is string => Boolean(part));
  return parts.length > 0 ? parts.join(" ") : undefined;
}

export function extractAttachmentMetadata(parts: unknown[]): AttachmentMetadata[] {
  return parts.flatMap((part) => collectAttachmentMetadata(part as GmailMessagePart));
}
