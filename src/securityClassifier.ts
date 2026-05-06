import type {
  InboundMessage,
  NormalizedMessageForClassification,
  SecurityClassification,
  SecurityConfig,
} from "./types.js";
import { extractLinksFromGmailContent, normalizeLinks, sanitizeGmailBody } from "./gmailSanitize.js";

export type SecurityClassifier = {
  classify(message: NormalizedMessageForClassification): Promise<SecurityClassification>;
};

export function shouldQuarantine(
  classification: SecurityClassification,
  security: SecurityConfig,
): boolean {
  if (classification.verdict === "risky" || classification.verdict === "malicious") {
    return classification.riskScore >= security.maliciousThreshold;
  }
  if (classification.verdict === "uncertain") {
    return security.failClosedOnUncertain || classification.riskScore >= security.uncertainThreshold;
  }
  return false;
}

export function normalizeMessageForSecurity(
  message: InboundMessage,
  maxBodyChars: number,
): NormalizedMessageForClassification {
  const textBody = sanitizeGmailBody(message.bodyText, false);
  const htmlText = sanitizeGmailBody(message.bodyHtml, true);
  const bodyText = clipText([textBody, htmlText].filter(Boolean).join("\n\n"), maxBodyChars);
  const links = normalizeLinks([
    ...(message.linkUrls ?? []),
    ...extractLinksFromGmailContent(message.bodyText, message.bodyHtml),
  ]);
  const authHeaders = pickAuthHeaders(message.headers);
  const replyTo = headerValue(message.headers, "reply-to");
  const normalized: NormalizedMessageForClassification = {
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
    attachments: message.attachments,
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

function clipText(value: string, maxChars: number): string {
  return value.length <= maxChars ? value : value.slice(0, maxChars);
}

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      return value;
    }
  }
  return undefined;
}

function pickAuthHeaders(headers: Record<string, string>): Record<string, string> {
  const wanted = new Set(["authentication-results", "received-spf", "dkim-signature", "arc-authentication-results"]);
  return Object.fromEntries(
    Object.entries(headers).filter(([key]) => wanted.has(key.toLowerCase())),
  );
}

export function createUnavailableSecurityClassifier(): SecurityClassifier {
  return {
    async classify(): Promise<SecurityClassification> {
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
