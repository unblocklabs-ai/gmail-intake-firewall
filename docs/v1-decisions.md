# V1 Decisions

## Intake

V1 started with Gmail polling only. Phase 2 adds Gmail history/watch-shaped intake while retaining polling as fallback and repair/backfill. Pub/Sub push delivery can be handed to the plugin through `POST /gmail-intake-firewall/pubsub`, which requires the configured `webhookSecret` as a bearer token, `x-openclaw-token`, or `token` query parameter. The service also exposes `handleGmailNotification(options)` for direct host calls. The runtime drains from its stored cursor and only uses the notification `historyId` as the next cursor marker; without a stored cursor it records the notification and skips message processing.

## Auth

V1 supports per-user OAuth refresh-token material through OpenClaw secret/config references. Domain-wide delegation is intentionally not required and should be added later behind the same auth interface.

## Gmail Scope And Actions

`gmail.modify` is acceptable for v1. Gmail label/archive actions are gated by source config and by `dryRun`. Sources with read-only scope set `gmailActions.hasModifyScope = false`; those sources still classify, alert, and log but do not attempt label/archive.

## Classifiers

The security classifier uses OpenAI in v1. It resolves `OPENAI_API_KEY` from `openaiApiKeyRef` through OpenClaw secrets, with a config-level `OPENAI_API_KEY` fallback for local installs. `openai_model` defaults to `gpt-5.5`.

Security classification input includes raw headers, body text, stripped HTML-derived text, normalized links, Gmail metadata, and attachment metadata. It does not include executable-looking raw HTML, does not fetch links, and does not open attachments.

Uncertain classifications fail closed by default through `security.failClosedOnUncertain = true`.

The router classifier only runs for safe mail. It sees normalized/clipped safe body, metadata, and the security classifier's sanitized summary.

## Routing And Wakes

Tags refer to a named `wakeTarget`; a wake target resolves to `agentId`, `workspaceDir`, `sessionId`, and optional delivery context. `wake_now` uses detached OpenClaw agent turn semantics as the orchestration path. Slack is alert UX only.

## Alerts

V1 alert sinks are Slack and local durable log. Suspicious-mail alerts may include sender, reply-to, recipients, subject, date, message/thread ids, Gmail link, labels, auth headers, snippet, link domains, attachment metadata, risk reasons, suspicious signals, and sanitized summary. Full raw body is intentionally omitted by default.

## State

V1 uses SQLite for idempotency, decisions, aggregate queues, intake events/replay input, and per-source cursor state. JSON state remains only as a legacy fallback helper in tests and migration code.

Phase 2 also stores action statuses, aggregate delivery state, and feedback events.
