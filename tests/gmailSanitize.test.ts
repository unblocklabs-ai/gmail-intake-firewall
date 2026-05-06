import assert from "node:assert/strict";
import test from "node:test";
import { extractLinksFromGmailContent, normalizeLinks, sanitizeGmailBody } from "../src/gmailSanitize.js";

test("sanitizer strips active html and removes URLs from classifier body text", () => {
  const sanitized = sanitizeGmailBody(
    '<div>Hello&nbsp;<script>alert("x")</script><style>.x{}</style><a href="https://evil.example/a">https://evil.example/a</a></div>',
    true,
  );

  assert.equal(sanitized, "Hello [url removed]");
});

test("link extraction keeps normalized URL/domain metadata separately", () => {
  const links = normalizeLinks(extractLinksFromGmailContent(
    "Visit https://Example.com/a#fragment and https://example.com/a#other.",
  ));

  assert.deepEqual(links, [{ url: "https://example.com/a", domain: "example.com" }]);
});
