import assert from "node:assert/strict";
import test from "node:test";
import { analyzeAttachment } from "../src/attachmentAnalysis.js";
import { analyzeLink } from "../src/linkAnalysis.js";

test("link analyzer flags structural risks without fetching", () => {
  const shortener = analyzeLink({ url: "http://bit.ly/login-reset.exe?verify=1", domain: "bit.ly" });
  assert.equal(shortener.domain, "bit.ly");
  assert.equal(shortener.isShortener, true);
  assert.equal(shortener.isHttps, false);
  assert.ok(shortener.riskHints.includes("url_shortener"));
  assert.ok(shortener.riskHints.includes("non_https"));
  assert.ok(shortener.riskHints.includes("suspicious_path_extension:exe"));
  assert.ok(shortener.riskHints.includes("suspicious_keyword:login"));

  const ipHost = analyzeLink({ url: "https://192.168.0.1:8443/secure", domain: "192.168.0.1" });
  assert.equal(ipHost.isIpLiteral, true);
  assert.equal(ipHost.unusualPort, "8443");
  assert.ok(ipHost.riskHints.includes("ip_literal_host"));
  assert.ok(ipHost.riskHints.includes("unusual_port"));

  const punycode = analyzeLink({ url: "https://xn--paypa1-l2c.example/signin", domain: "xn--paypa1-l2c.example" });
  assert.equal(punycode.isPunycode, true);
  assert.ok(punycode.riskHints.includes("punycode_domain"));

  const tokenized = analyzeLink({ url: "https://user:pass@login.bank.co.uk/reset?token=secret&next=/home", domain: "login.bank.co.uk" });
  assert.equal(tokenized.registrableDomain, "bank.co.uk");
  assert.equal(tokenized.url.includes("user:pass"), false);
  assert.equal(tokenized.url.includes("secret"), false);
  assert.match(tokenized.url, /token=%5Bredacted%5D/);
});

test("attachment analyzer flags metadata-only attachment risks", () => {
  const executable = analyzeAttachment({
    id: "att-1",
    filename: "invoice.pdf.exe",
    mimeType: "application/pdf",
    size: 42,
  });
  assert.equal(executable.extension, "exe");
  assert.equal(executable.hasAttachmentId, true);
  assert.equal(executable.isExecutable, true);
  assert.equal(executable.hasDoubleExtension, true);
  assert.equal(executable.mimeExtensionMismatch, true);
  assert.ok(executable.riskHints.includes("executable_attachment"));
  assert.ok(executable.riskHints.includes("double_extension"));

  const macro = analyzeAttachment({
    id: "att-2",
    filename: "statement.xlsm",
    mimeType: "application/vnd.ms-excel.sheet.macroEnabled.12",
  });
  assert.equal(macro.isMacroCapable, true);
  assert.ok(macro.riskHints.includes("macro_capable_document"));

  const archive = analyzeAttachment({
    filename: "docs.zip",
    mimeType: "application/zip",
  });
  assert.equal(archive.isArchive, true);
  assert.equal(archive.hasAttachmentId, false);
  assert.ok(archive.riskHints.includes("archive_attachment"));
  assert.ok(archive.riskHints.includes("missing_attachment_id"));
});
