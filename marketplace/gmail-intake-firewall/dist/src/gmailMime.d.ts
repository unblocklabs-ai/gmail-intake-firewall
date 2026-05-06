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
export declare function headersToRecord(headers: readonly GmailHeader[] | null | undefined): Record<string, string>;
export declare function headersToList(headers: readonly GmailHeader[] | null | undefined): EmailHeader[];
export declare function headerValue(partOrHeaders: GmailMessagePart | Record<string, string>, name: string): string | undefined;
export declare function bestBodyText(part: GmailMessagePart | undefined): string | undefined;
export declare function bestBodyHtml(part: GmailMessagePart | undefined): string | undefined;
export declare function bestBodyForDisplay(part: GmailMessagePart | undefined): {
    body?: string;
    isHtml: boolean;
};
export declare function findPartBody(part: GmailMessagePart | undefined, mimeType: string): string | undefined;
export declare function decodePartBody(part: GmailMessagePart | undefined): string | undefined;
export declare function collectAttachmentMetadata(part: GmailMessagePart | undefined): AttachmentMetadata[];
export declare function normalizeMimeType(mimeType: string | null | undefined): string;
export declare function looksLikeHtml(value: string): boolean;
//# sourceMappingURL=gmailMime.d.ts.map