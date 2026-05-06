import type { NormalizedLink } from "./types.js";
export declare function sanitizeGmailBody(body: string | undefined, isHtml: boolean): string;
export declare function extractLinksFromGmailContent(...values: (string | undefined)[]): string[];
export declare function normalizeLinks(urls: string[]): NormalizedLink[];
export declare function extractHtmlText(html: string): string;
export declare function removeUrls(value: string): string;
export declare function normalizeWhitespace(value: string): string;
//# sourceMappingURL=gmailSanitize.d.ts.map