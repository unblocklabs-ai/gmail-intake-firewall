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

export function parseGmailPushNotification(input: unknown): GmailPushNotification {
  if (!input || typeof input !== "object") {
    throw new Error("Gmail notification must be an object");
  }
  const raw = input as Record<string, unknown>;
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

function decodeGmailNotificationData(raw: Record<string, unknown>): Record<string, unknown> | undefined {
  const message = objectValue(raw.message);
  const data = stringValue(message?.data) ?? stringValue(raw.data);
  if (!data) {
    return undefined;
  }
  try {
    const normalized = data.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = Buffer.from(normalized, "base64").toString("utf8");
    const parsed = JSON.parse(decoded) as unknown;
    return objectValue(parsed);
  } catch {
    return undefined;
  }
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" ? value as Record<string, unknown> : undefined;
}

function stringValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  return undefined;
}
