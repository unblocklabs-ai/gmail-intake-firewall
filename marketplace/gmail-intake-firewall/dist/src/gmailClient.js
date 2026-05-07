import { google } from "googleapis";
import { buildCandidateQuery } from "./gmail.js";
import { collectAttachmentMetadata, headersToList, headersToRecord, headerValue } from "./gmailMime.js";
import { bestBodyHtml, bestBodyText } from "./gmailMime.js";
import { extractLinksFromGmailContent } from "./gmailSanitize.js";
export function createGoogleapisGmailClient(source, authMaterial) {
    const auth = createGoogleOAuth2Auth(authMaterial);
    const api = google.gmail({ version: "v1", auth });
    return createGmailClientFromApi(source, api);
}
export function createGoogleOAuth2Auth(authMaterial) {
    if (authMaterial.tokenType === "workspace_domain_wide_delegation") {
        throw new Error("Workspace domain-wide delegation is not implemented in v1");
    }
    if (authMaterial.refreshToken) {
        if (!authMaterial.clientId || !authMaterial.clientSecret) {
            throw new Error("Gmail OAuth refresh token auth requires clientId and clientSecret");
        }
        const client = new google.auth.OAuth2(authMaterial.clientId, authMaterial.clientSecret);
        client.setCredentials({ refresh_token: authMaterial.refreshToken });
        return client;
    }
    if (authMaterial.accessToken) {
        const client = new google.auth.OAuth2();
        client.setCredentials({ access_token: authMaterial.accessToken });
        return client;
    }
    throw new Error("No Gmail OAuth credentials were resolved");
}
export function createGmailClientFromApi(source, api) {
    const labels = new GmailLabelResolver(api);
    return {
        async listCandidates(query = buildCandidateQuery(source)) {
            const labelIds = gmailQuerySystemLabelIds(query);
            const results = [];
            let pageToken;
            do {
                const response = await withGmailRetry(() => api.users.messages.list({
                    userId: "me",
                    q: query,
                    maxResults: Math.max(1, Math.min(500, source.polling.maxResults - results.length)),
                    pageToken,
                    fields: "messages(id,threadId),nextPageToken",
                    ...(labelIds.length > 0 ? { labelIds } : {}),
                }));
                for (const message of response.data.messages ?? []) {
                    if (message.id) {
                        results.push({ id: message.id, threadId: message.threadId ?? "" });
                    }
                    if (results.length >= source.polling.maxResults) {
                        break;
                    }
                }
                pageToken = response.data.nextPageToken ?? undefined;
            } while (pageToken && results.length < source.polling.maxResults);
            return results;
        },
        async listHistory(startHistoryId) {
            return listHistory(api, startHistoryId);
        },
        async setupWatch(topicName, labelIds = ["INBOX"]) {
            if (!api.users.watch) {
                throw new Error("Gmail watch API is unavailable");
            }
            const response = await withGmailRetry(() => api.users.watch({
                userId: "me",
                requestBody: {
                    topicName,
                    labelIds,
                    labelFilterBehavior: "INCLUDE",
                },
            }));
            const registration = {};
            if (response.data.historyId) {
                registration.historyId = response.data.historyId;
            }
            if (response.data.expiration) {
                const expirationMs = Number(response.data.expiration);
                if (Number.isFinite(expirationMs)) {
                    registration.expiration = new Date(expirationMs).toISOString();
                }
            }
            return registration;
        },
        async fetchMessage(candidate) {
            const response = await withGmailRetry(() => api.users.messages.get({
                userId: "me",
                id: candidate.id,
                format: "full",
            }));
            return gmailApiMessageToInboundMessage(source, response.data, candidate);
        },
        async fetchThreadContext(threadId, maxMessages = 6) {
            if (!api.users.threads) {
                return undefined;
            }
            const threads = api.users.threads;
            const response = await withGmailRetry(() => threads.get({
                userId: "me",
                id: threadId,
                format: "metadata",
                metadataHeaders: ["From", "To", "Cc", "Subject", "Date"],
            }));
            const messages = (response.data.messages ?? []).slice(-maxMessages);
            const participants = new Set();
            const labels = new Set();
            const contextMessages = messages.map((message) => {
                const headers = headersToRecord(message.payload?.headers);
                const from = headerValue(headers, "from");
                for (const value of [from, headerValue(headers, "to"), headerValue(headers, "cc")]) {
                    for (const part of splitAddressList(value)) {
                        participants.add(part);
                    }
                }
                for (const label of message.labelIds ?? []) {
                    labels.add(label);
                }
                const contextMessage = {
                    messageId: message.id ?? "",
                };
                if (from) {
                    contextMessage.from = from;
                }
                const subject = headerValue(headers, "subject");
                if (subject) {
                    contextMessage.subject = subject;
                }
                const date = headerValue(headers, "date");
                if (date) {
                    contextMessage.date = date;
                }
                if (message.snippet) {
                    contextMessage.snippet = message.snippet;
                }
                return contextMessage;
            });
            return {
                threadId,
                participants: Array.from(participants),
                labels: Array.from(labels),
                messages: contextMessages,
            };
        },
        async applyLabel(messageId, label) {
            const labelId = await labels.resolveOrCreate(label);
            await withGmailRetry(() => api.users.messages.modify({
                userId: "me",
                id: messageId,
                requestBody: { addLabelIds: [labelId] },
            }));
        },
        async removeLabel(messageId, label) {
            const labelId = await labels.resolveExisting(label);
            if (!labelId) {
                return;
            }
            await withGmailRetry(() => api.users.messages.modify({
                userId: "me",
                id: messageId,
                requestBody: { removeLabelIds: [labelId] },
            }));
        },
        async archive(messageId) {
            await withGmailRetry(() => api.users.messages.modify({
                userId: "me",
                id: messageId,
                requestBody: { removeLabelIds: ["INBOX"] },
            }));
        },
        async restoreInbox(messageId) {
            await withGmailRetry(() => api.users.messages.modify({
                userId: "me",
                id: messageId,
                requestBody: { addLabelIds: ["INBOX"] },
            }));
        },
    };
}
async function listHistory(api, startHistoryId) {
    if (!api.users.history) {
        return { candidates: [] };
    }
    const candidates = new Map();
    let historyId;
    let pageToken;
    do {
        const response = await withGmailRetry(() => api.users.history.list({
            userId: "me",
            startHistoryId,
            historyTypes: ["messageAdded"],
            pageToken,
            fields: "history(messages(id,threadId),messagesAdded(message(id,threadId))),historyId,nextPageToken",
        }));
        if (response.data.historyId) {
            historyId = response.data.historyId;
        }
        for (const history of response.data.history ?? []) {
            const refs = [
                ...(history.messages ?? []),
                ...(history.messagesAdded ?? []).flatMap((entry) => entry.message ? [entry.message] : []),
            ];
            for (const ref of refs) {
                if (ref.id) {
                    candidates.set(ref.id, { id: ref.id, threadId: ref.threadId ?? "" });
                }
            }
        }
        pageToken = response.data.nextPageToken ?? undefined;
    } while (pageToken);
    return { candidates: Array.from(candidates.values()), ...(historyId ? { historyId } : {}) };
}
export function gmailApiMessageToInboundMessage(source, message, candidate) {
    const payload = message.payload ?? undefined;
    const headers = headersToRecord(payload?.headers);
    const rawHeaders = headersToList(payload?.headers);
    const bodyText = bestBodyText(payload);
    const bodyHtml = bestBodyHtml(payload);
    const inbound = {
        sourceId: source.id,
        accountEmail: source.accountEmail,
        messageId: message.id ?? candidate?.id ?? "",
        threadId: message.threadId ?? candidate?.threadId ?? "",
        headers,
        rawHeaders,
        to: splitAddressList(headerValue(headers, "to")),
        cc: splitAddressList(headerValue(headers, "cc")),
        bcc: splitAddressList(headerValue(headers, "bcc")),
        labels: message.labelIds ?? [],
        attachments: collectAttachmentMetadata(payload),
    };
    const from = headerValue(headers, "from");
    const subject = headerValue(headers, "subject");
    const date = headerValue(headers, "date");
    if (from) {
        inbound.from = from;
    }
    if (subject) {
        inbound.subject = subject;
    }
    if (message.snippet) {
        inbound.snippet = message.snippet;
    }
    if (bodyText) {
        inbound.bodyText = bodyText;
    }
    if (bodyHtml) {
        inbound.bodyHtml = bodyHtml;
    }
    const linkUrls = extractLinksFromGmailContent(bodyText, bodyHtml);
    if (linkUrls.length > 0) {
        inbound.linkUrls = linkUrls;
    }
    if (date) {
        inbound.receivedAt = date;
    }
    else if (message.internalDate && /^\d+$/.test(message.internalDate)) {
        inbound.receivedAt = new Date(Number(message.internalDate)).toISOString();
    }
    return inbound;
}
export function gmailQuerySystemLabelIds(query) {
    if (!query || isComplexGmailQuery(query)) {
        return [];
    }
    const labels = new Set();
    const lower = query.toLowerCase();
    const mappings = [
        [/\b(?:in|label):inbox\b/g, "INBOX"],
        [/\b(?:is|label):unread\b/g, "UNREAD"],
        [/\b(?:is|label):starred\b/g, "STARRED"],
        [/\b(?:in|label):sent\b/g, "SENT"],
        [/\b(?:in|label):drafts?\b/g, "DRAFT"],
        [/\b(?:in|label):spam\b/g, "SPAM"],
        [/\b(?:in|label):trash\b/g, "TRASH"],
        [/\bcategory:primary\b/g, "CATEGORY_PRIMARY"],
        [/\bcategory:social\b/g, "CATEGORY_SOCIAL"],
        [/\bcategory:promotions\b/g, "CATEGORY_PROMOTIONS"],
        [/\bcategory:updates\b/g, "CATEGORY_UPDATES"],
        [/\bcategory:forums\b/g, "CATEGORY_FORUMS"],
    ];
    for (const [pattern, label] of mappings) {
        if (hasPositiveQueryTerm(lower, pattern)) {
            labels.add(label);
        }
    }
    return Array.from(labels);
}
function isComplexGmailQuery(query) {
    return /\bOR\b|[{}()]/i.test(query);
}
class GmailLabelResolver {
    api;
    cache;
    constructor(api) {
        this.api = api;
    }
    async resolveOrCreate(label) {
        const labels = await this.getLabels();
        const direct = labels.get(label) ?? labels.get(label.toLowerCase());
        if (direct) {
            return direct;
        }
        const created = await withGmailRetry(() => this.api.users.labels.create({
            userId: "me",
            requestBody: { name: label },
        }));
        const id = created.data.id;
        if (!id) {
            throw new Error(`Gmail label creation returned no id for ${label}`);
        }
        labels.set(label, id);
        labels.set(label.toLowerCase(), id);
        return id;
    }
    async resolveExisting(label) {
        const labels = await this.getLabels();
        return labels.get(label) ?? labels.get(label.toLowerCase());
    }
    async getLabels() {
        if (this.cache) {
            return this.cache;
        }
        const response = await withGmailRetry(() => this.api.users.labels.list({
            userId: "me",
            fields: "labels(id,name,type)",
        }));
        this.cache = new Map();
        for (const label of response.data.labels ?? []) {
            if (label.id) {
                this.cache.set(label.id, label.id);
            }
            if (label.name && label.id) {
                this.cache.set(label.name, label.id);
                this.cache.set(label.name.toLowerCase(), label.id);
            }
        }
        return this.cache;
    }
}
function splitAddressList(value) {
    return value?.split(",").map((part) => part.trim()).filter(Boolean) ?? [];
}
async function withGmailRetry(operation, attempts = 3) {
    let lastError;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        try {
            return await operation();
        }
        catch (error) {
            lastError = error;
            if (attempt === attempts - 1 || !isRetryableGoogleError(error)) {
                throw error;
            }
            await new Promise((resolve) => setTimeout(resolve, 100 * 2 ** attempt));
        }
    }
    throw lastError;
}
function isRetryableGoogleError(error) {
    const status = typeof error === "object" && error !== null
        ? error
        : {};
    const code = Number(status.code ?? status.status ?? status.response?.status);
    return code === 429 || (code >= 500 && code < 600);
}
function hasPositiveQueryTerm(query, pattern) {
    for (const match of query.matchAll(pattern)) {
        const index = match.index ?? 0;
        const previous = query[index - 1];
        if (previous !== "-") {
            return true;
        }
    }
    return false;
}
