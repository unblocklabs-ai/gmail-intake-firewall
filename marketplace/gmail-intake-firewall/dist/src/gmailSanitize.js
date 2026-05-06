const URL_PATTERN = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
export function sanitizeGmailBody(body, isHtml) {
    if (!body) {
        return "";
    }
    const text = isHtml ? extractHtmlText(body) : body;
    return normalizeWhitespace(removeUrls(decodeHtmlEntities(text)));
}
export function extractLinksFromGmailContent(...values) {
    const links = [];
    for (const value of values) {
        if (!value) {
            continue;
        }
        links.push(...Array.from(value.matchAll(URL_PATTERN), (match) => trimUrlPunctuation(match[0])));
    }
    return links;
}
export function normalizeLinks(urls) {
    const seen = new Set();
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
        }
        catch {
            return [];
        }
    });
}
export function extractHtmlText(html) {
    return normalizeWhitespace(decodeHtmlEntities(html
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
        .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
        .replace(/<(?:br|hr)\b[^>]*>/gi, "\n")
        .replace(/<\/(?:p|div|section|article|header|footer|li|tr|td|th|h[1-6])>/gi, "\n")
        .replace(/<[^>]+>/g, " ")));
}
export function removeUrls(value) {
    return value.replace(URL_PATTERN, "[url removed]");
}
export function normalizeWhitespace(value) {
    return value.replace(/\s+/g, " ").trim();
}
function trimUrlPunctuation(url) {
    return url.replace(/[.,;:!?]+$/g, "");
}
function decodeHtmlEntities(value) {
    return value
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, "\"")
        .replace(/&#39;/gi, "'")
        .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
        .replace(/&#(\d+);/g, (_, decimal) => String.fromCodePoint(Number.parseInt(decimal, 10)));
}
