import { Buffer } from "node:buffer";
import type { AttachmentMetadata, EmailHeader } from "./types.js";

export type GmailMessagePart = {
  partId?: string | null;
  mimeType?: string | null;
  filename?: string | null;
  headers?: GmailHeader[] | null;
  body?: GmailPartBody | null;
  parts?: GmailMessagePart[] | null;
};

export type GmailHeader = {
  name?: string | null;
  value?: string | null;
};

export type GmailPartBody = {
  data?: string | null;
  size?: number | null;
  attachmentId?: string | null;
};

export function headersToRecord(headers: readonly GmailHeader[] | null | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  for (const header of headers ?? []) {
    if (header.name && typeof header.value === "string") {
      result[header.name] = header.value;
    }
  }
  return result;
}

export function headersToList(headers: readonly GmailHeader[] | null | undefined): EmailHeader[] {
  return (headers ?? []).flatMap((header) => {
    if (!header.name || typeof header.value !== "string") {
      return [];
    }
    return [{ name: header.name, value: header.value }];
  });
}

export function headerValue(partOrHeaders: GmailMessagePart | Record<string, string>, name: string): string | undefined {
  const lowerName = name.toLowerCase();
  const maybePart = partOrHeaders as GmailMessagePart;
  if (Array.isArray(maybePart.headers)) {
    return maybePart.headers.find((header: GmailHeader) => header.name?.toLowerCase() === lowerName)?.value ?? undefined;
  }
  const headers = partOrHeaders as Record<string, string>;
  return Object.entries(headers).find(([key]) => key.toLowerCase() === lowerName)?.[1];
}

export function bestBodyText(part: GmailMessagePart | undefined): string | undefined {
  return findPartBody(part, "text/plain");
}

export function bestBodyHtml(part: GmailMessagePart | undefined): string | undefined {
  return findPartBody(part, "text/html");
}

export function bestBodyForDisplay(part: GmailMessagePart | undefined): { body?: string; isHtml: boolean } {
  const text = bestBodyText(part);
  if (text) {
    return { body: text, isHtml: false };
  }
  const html = bestBodyHtml(part);
  if (html) {
    return { body: html, isHtml: true };
  }
  const decoded = decodePartBody(part);
  return decoded ? { body: decoded, isHtml: looksLikeHtml(decoded) } : { isHtml: false };
}

export function findPartBody(part: GmailMessagePart | undefined, mimeType: string): string | undefined {
  if (!part) {
    return undefined;
  }
  if (normalizeMimeType(part.mimeType) === mimeType) {
    const body = decodePartBody(part);
    if (body) {
      return body;
    }
  }
  for (const child of part.parts ?? []) {
    const body = findPartBody(child, mimeType);
    if (body) {
      return body;
    }
  }
  return undefined;
}

export function decodePartBody(part: GmailMessagePart | undefined): string | undefined {
  const data = part?.body?.data;
  if (!data) {
    return undefined;
  }
  const initial = decodeBase64Like(data);
  const transferEncoding = headerValue(part, "content-transfer-encoding")?.toLowerCase();
  const decoded = transferEncoding === "quoted-printable" || looksQuotedPrintable(initial.toString("latin1"))
    ? decodeQuotedPrintable(initial.toString("latin1"))
    : transferEncoding === "base64" && looksBase64(initial.toString("latin1"))
      ? decodeBase64Like(initial.toString("latin1"))
      : initial;
  return decodeCharset(decoded, contentCharset(part));
}

export function collectAttachmentMetadata(part: GmailMessagePart | undefined): AttachmentMetadata[] {
  if (!part) {
    return [];
  }
  const body = part.body ?? {};
  const filename = part.filename?.trim();
  const attachmentId = body.attachmentId ?? undefined;
  const hasAttachment = Boolean(filename || attachmentId);
  const current: AttachmentMetadata[] = [];
  if (hasAttachment) {
    const metadata: AttachmentMetadata = {};
    if (attachmentId) {
      metadata.id = attachmentId;
    }
    if (filename) {
      metadata.filename = filename;
    } else if (attachmentId) {
      metadata.filename = "attachment";
    }
    if (part.mimeType) {
      metadata.mimeType = part.mimeType;
    }
    if (typeof body.size === "number") {
      metadata.size = body.size;
    }
    current.push(metadata);
  }
  for (const child of part.parts ?? []) {
    current.push(...collectAttachmentMetadata(child));
  }
  return current;
}

export function normalizeMimeType(mimeType: string | null | undefined): string {
  return (mimeType ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
}

export function looksLikeHtml(value: string): boolean {
  return /<html\b|<body\b|<div\b|<p\b|<br\b/i.test(value);
}

function decodeBase64Like(value: string): Buffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=");
  return Buffer.from(padded, "base64");
}

function decodeQuotedPrintable(value: string): Buffer {
  const withoutSoftBreaks = value.replace(/=\r?\n/g, "");
  const bytes: number[] = [];
  for (let i = 0; i < withoutSoftBreaks.length; i += 1) {
    const char = withoutSoftBreaks[i];
    if (char === "=" && /^[0-9a-f]{2}$/i.test(withoutSoftBreaks.slice(i + 1, i + 3))) {
      bytes.push(Number.parseInt(withoutSoftBreaks.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(withoutSoftBreaks.charCodeAt(i));
    }
  }
  return Buffer.from(bytes);
}

function decodeCharset(buffer: Buffer, charset: string | undefined): string {
  const normalized = charset?.trim().toLowerCase().replaceAll("_", "-");
  if (normalized === "iso-8859-1" || normalized === "latin1" || normalized === "windows-1252") {
    return buffer.toString("latin1");
  }
  if (normalized === "utf-16" || normalized === "utf-16le") {
    return buffer.toString("utf16le");
  }
  if (normalized === "us-ascii" || normalized === "ascii") {
    return buffer.toString("ascii");
  }
  return buffer.toString("utf8");
}

function contentCharset(part: GmailMessagePart | undefined): string | undefined {
  const contentType = headerValue(part ?? {}, "content-type") ?? part?.mimeType ?? "";
  return /charset="?([^";]+)"?/i.exec(contentType)?.[1];
}

function looksQuotedPrintable(value: string): boolean {
  return /=\r?\n|=[0-9a-f]{2}/i.test(value);
}

function looksBase64(value: string): boolean {
  const compact = value.replace(/\s+/g, "");
  return compact.length > 0 && compact.length % 4 === 0 && /^[a-z0-9+/]+={0,2}$/i.test(compact);
}
