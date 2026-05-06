import { google } from "googleapis";
import { type GmailCandidate, type GmailClient } from "./gmail.js";
import { type GmailMessagePart } from "./gmailMime.js";
import type { GoogleAuthMaterial } from "./googleAuth.js";
import type { GmailSourceConfig, InboundMessage } from "./types.js";
export type GmailApi = {
    users: {
        messages: {
            list(params: Record<string, unknown>): Promise<{
                data: {
                    messages?: GmailApiMessageRef[];
                    nextPageToken?: string | null;
                };
            }>;
            get(params: Record<string, unknown>): Promise<{
                data: GmailApiMessage;
            }>;
            modify(params: Record<string, unknown>): Promise<unknown>;
        };
        history?: {
            list(params: Record<string, unknown>): Promise<{
                data: {
                    history?: GmailApiHistory[];
                    historyId?: string | null;
                    nextPageToken?: string | null;
                };
            }>;
        };
        watch?: (params: Record<string, unknown>) => Promise<{
            data: {
                historyId?: string | null;
                expiration?: string | null;
            };
        }>;
        threads?: {
            get(params: Record<string, unknown>): Promise<{
                data: {
                    id?: string | null;
                    messages?: GmailApiMessage[] | null;
                };
            }>;
        };
        labels: {
            list(params: Record<string, unknown>): Promise<{
                data: {
                    labels?: GmailApiLabel[];
                };
            }>;
            create(params: Record<string, unknown>): Promise<{
                data: GmailApiLabel;
            }>;
        };
    };
};
type GmailApiMessageRef = {
    id?: string | null;
    threadId?: string | null;
};
type GmailApiLabel = {
    id?: string | null;
    name?: string | null;
    type?: string | null;
};
type GmailApiMessage = {
    id?: string | null;
    threadId?: string | null;
    labelIds?: string[] | null;
    snippet?: string | null;
    internalDate?: string | null;
    payload?: GmailMessagePart | null;
};
type GmailApiHistory = {
    messagesAdded?: Array<{
        message?: GmailApiMessageRef | null;
    }> | null;
    messages?: GmailApiMessageRef[] | null;
};
export declare function createGoogleapisGmailClient(source: GmailSourceConfig, authMaterial: GoogleAuthMaterial): GmailClient;
export declare function createGoogleOAuth2Auth(authMaterial: GoogleAuthMaterial): InstanceType<typeof google.auth.OAuth2>;
export declare function createGmailClientFromApi(source: GmailSourceConfig, api: GmailApi): GmailClient;
export declare function gmailApiMessageToInboundMessage(source: GmailSourceConfig, message: GmailApiMessage, candidate?: GmailCandidate): InboundMessage;
export declare function gmailQuerySystemLabelIds(query: string | undefined): string[];
export {};
//# sourceMappingURL=gmailClient.d.ts.map