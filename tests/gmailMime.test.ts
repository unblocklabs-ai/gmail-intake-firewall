import assert from "node:assert/strict";
import test from "node:test";
import { bestBodyForDisplay, bestBodyHtml, bestBodyText, collectAttachmentMetadata, decodePartBody } from "../src/gmailMime.js";

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

test("gmail MIME helpers choose recursive text and html bodies", () => {
  const payload = {
    mimeType: "multipart/alternative",
    parts: [
      { mimeType: "text/html", body: { data: b64url("<p>Hello <b>HTML</b></p>") } },
      { mimeType: "text/plain", body: { data: b64url("Hello text") } },
    ],
  };

  assert.equal(bestBodyText(payload), "Hello text");
  assert.equal(bestBodyHtml(payload), "<p>Hello <b>HTML</b></p>");
  assert.deepEqual(bestBodyForDisplay(payload), { body: "Hello text", isHtml: false });
});

test("gmail MIME decoder handles quoted-printable content", () => {
  const encoded = Buffer.from("Hello=20world=21=\r\n\r\nNext", "latin1").toString("base64url");
  const decoded = decodePartBody({
    mimeType: "text/plain",
    headers: [{ name: "Content-Transfer-Encoding", value: "quoted-printable" }],
    body: { data: encoded },
  });

  assert.equal(decoded, "Hello world!\r\nNext");
});

test("gmail MIME attachment collector is recursive and metadata-only", () => {
  const attachments = collectAttachmentMetadata({
    mimeType: "multipart/mixed",
    parts: [
      { mimeType: "text/plain", body: { data: b64url("body") } },
      {
        mimeType: "application/pdf",
        filename: "invoice.pdf",
        body: { attachmentId: "att-1", size: 12345 },
      },
      {
        mimeType: "multipart/related",
        parts: [
          { mimeType: "image/png", body: { attachmentId: "att-2", size: 99 } },
        ],
      },
    ],
  });

  assert.deepEqual(attachments, [
    { id: "att-1", filename: "invoice.pdf", mimeType: "application/pdf", size: 12345 },
    { id: "att-2", filename: "attachment", mimeType: "image/png", size: 99 },
  ]);
});
