import type { LinkRiskMetadata, NormalizedLink } from "./types.js";

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "buff.ly",
  "cutt.ly",
  "goo.gl",
  "is.gd",
  "lnkd.in",
  "ow.ly",
  "rebrand.ly",
  "s.id",
  "t.co",
  "tiny.cc",
  "tinyurl.com",
]);

const SUSPICIOUS_KEYWORDS = [
  "account",
  "billing",
  "confirm",
  "credential",
  "invoice",
  "login",
  "password",
  "reset",
  "secure",
  "signin",
  "verify",
  "wallet",
];

const SUSPICIOUS_EXTENSIONS = new Set([
  "apk",
  "bat",
  "cmd",
  "com",
  "exe",
  "hta",
  "js",
  "lnk",
  "msi",
  "ps1",
  "scr",
  "vbs",
  "wsf",
  "zip",
]);

const COMMON_MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
  "ac.uk",
  "co.jp",
  "co.kr",
  "co.nz",
  "co.uk",
  "com.ar",
  "com.au",
  "com.br",
  "com.cn",
  "com.mx",
  "com.sg",
  "com.tr",
  "gov.uk",
  "net.au",
  "org.au",
  "org.uk",
]);

const SENSITIVE_QUERY_PARAM_PATTERN = /(?:^|[-_])(access.?token|api.?key|auth|authorization|code|credential|key|otp|pass(?:word)?|refresh.?token|secret|session|signature|token)(?:$|[-_])/i;

export function analyzeLinks(links: NormalizedLink[], maxDisplayedUrlChars = 160): LinkRiskMetadata[] {
  return links.map((link) => analyzeLink(link, maxDisplayedUrlChars));
}

export function summarizeLinkMetadata(link: NormalizedLink, maxDisplayedUrlChars = 160): LinkRiskMetadata {
  let parsed: URL | undefined;
  try {
    parsed = new URL(link.url);
  } catch {
    return {
      url: clipUrl(link.url, maxDisplayedUrlChars),
      domain: link.domain ?? "",
      riskHints: [],
    };
  }

  const domain = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  const summarized: LinkRiskMetadata = {
    url: safeDisplayedUrl(parsed, maxDisplayedUrlChars),
    domain,
    riskHints: [],
  };
  const registrableDomain = registrableDomainFromHost(domain);
  if (registrableDomain) {
    summarized.registrableDomain = registrableDomain;
  }
  if (scheme) {
    summarized.scheme = scheme;
  }
  summarized.isHttps = scheme === "https";
  return summarized;
}

export function analyzeLink(link: NormalizedLink, maxDisplayedUrlChars = 160): LinkRiskMetadata {
  const riskHints: string[] = [];
  let parsed: URL | undefined;
  try {
    parsed = new URL(link.url);
  } catch {
    return {
      url: clipUrl(link.url, maxDisplayedUrlChars),
      domain: link.domain ?? "",
      riskHints: ["invalid_url"],
    };
  }

  const domain = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  const isHttps = scheme === "https";
  const isShortener = SHORTENER_DOMAINS.has(domain);
  const isIpLiteral = isIpHost(domain);
  const isPunycode = domain.includes("xn--");
  const unusualPort = parsed.port && !["80", "443"].includes(parsed.port) ? parsed.port : undefined;
  const pathExtension = extensionFromPath(parsed.pathname);

  if (!isHttps) {
    riskHints.push("non_https");
  }
  if (isShortener) {
    riskHints.push("url_shortener");
  }
  if (isIpLiteral) {
    riskHints.push("ip_literal_host");
  }
  if (isPunycode) {
    riskHints.push("punycode_domain");
  }
  if (unusualPort) {
    riskHints.push("unusual_port");
  }
  if (pathExtension && SUSPICIOUS_EXTENSIONS.has(pathExtension)) {
    riskHints.push(`suspicious_path_extension:${pathExtension}`);
  }
  const haystack = `${domain} ${parsed.pathname} ${parsed.search}`.toLowerCase();
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (haystack.includes(keyword)) {
      riskHints.push(`suspicious_keyword:${keyword}`);
    }
  }

  const analyzed: LinkRiskMetadata = {
    url: safeDisplayedUrl(parsed, maxDisplayedUrlChars),
    domain,
    riskHints: Array.from(new Set(riskHints)),
  };
  const registrableDomain = registrableDomainFromHost(domain);
  if (registrableDomain) {
    analyzed.registrableDomain = registrableDomain;
  }
  if (scheme) {
    analyzed.scheme = scheme;
  }
  if (isShortener) {
    analyzed.isShortener = true;
  }
  if (isIpLiteral) {
    analyzed.isIpLiteral = true;
  }
  if (isPunycode) {
    analyzed.isPunycode = true;
  }
  analyzed.isHttps = isHttps;
  if (unusualPort) {
    analyzed.unusualPort = unusualPort;
  }
  if (pathExtension) {
    analyzed.pathExtension = pathExtension;
  }
  return analyzed;
}

function safeDisplayedUrl(parsed: URL, maxChars: number): string {
  const display = new URL(parsed.toString());
  display.username = "";
  display.password = "";
  for (const [name] of display.searchParams) {
    if (SENSITIVE_QUERY_PARAM_PATTERN.test(name)) {
      display.searchParams.set(name, "[redacted]");
    }
  }
  return clipUrl(display.toString(), maxChars);
}

function clipUrl(url: string, maxChars: number): string {
  if (url.length <= maxChars) {
    return url;
  }
  return `${url.slice(0, Math.max(1, maxChars - 12))}...[clipped]`;
}

function isIpHost(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host) || /^[0-9a-f:]*:[0-9a-f:]+$/i.test(host);
}

function extensionFromPath(pathname: string): string | undefined {
  const segment = pathname.split("/").pop() ?? "";
  const match = /\.([a-z0-9]{1,8})$/i.exec(segment);
  return match?.[1]?.toLowerCase();
}

function registrableDomainFromHost(host: string): string | undefined {
  if (!host || isIpHost(host)) {
    return undefined;
  }
  const parts = host.split(".").filter(Boolean);
  if (parts.length < 2) {
    return host;
  }
  const lastTwo = parts.slice(-2).join(".");
  if (parts.length >= 3 && COMMON_MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo)) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}
