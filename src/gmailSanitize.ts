import type { NormalizedLink } from "./types.js";

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"')\]]+/gi;

export function sanitizeGmailBody(body: string | undefined, isHtml: boolean): string {
  if (!body) {
    return "";
  }
  const text = isHtml ? extractHtmlText(body) : body;
  return normalizeWhitespace(removeUrls(decodeHtmlEntities(text)));
}

export function extractLinksFromGmailContent(...values: (string | undefined)[]): string[] {
  const links: string[] = [];
  for (const value of values) {
    if (!value) {
      continue;
    }
    links.push(...Array.from(value.matchAll(URL_PATTERN), (match) => trimUrlPunctuation(match[0])));
  }
  return links;
}

export function normalizeLinks(urls: string[]): NormalizedLink[] {
  const seen = new Set<string>();
  return urls.flatMap((rawUrl) => {
    try {
      const parsed = new URL(rawUrl);
      parsed.hash = "";
      const url = parsed.toString();
      if (seen.has(url)) {
        return [];
      }
      seen.add(url);
      return [{ url, domain: parsed.hostname.toLowerCase() }];
    } catch {
      return [];
    }
  });
}

export function extractHtmlText(html: string): string {
  return normalizeWhitespace(decodeHtmlEntities(html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<(?:br|hr)\b[^>]*>/gi, "\n")
    .replace(/<\/(?:p|div|section|article|header|footer|li|tr|td|th|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")));
}

export function removeUrls(value: string): string {
  return value.replace(URL_PATTERN, "[url removed]");
}

export function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function trimUrlPunctuation(url: string): string {
  return url.replace(/[.,;:!?]+$/g, "");
}

function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, "\"")
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal: string) => String.fromCodePoint(Number.parseInt(decimal, 10)));
}
