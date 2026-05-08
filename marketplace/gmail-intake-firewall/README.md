# Gmail Intake Firewall

OpenClaw plugin for Gmail intake security classification and routing.

## Goal

`gmail-intake-firewall` monitors configured Gmail inbox sources, runs a standalone LLM security classification before any normal agent exposure, quarantines risky or uncertain messages, and wakes agents only through explicit routing policy.

The plugin must use Google APIs directly. It must not shell out to `gog`.

## Product Vision

This is not a client email watcher. It is an email intake firewall and router for agents.

The durable product shape is:

```text
Gmail watch/poll -> intake event -> security classifier -> quarantine or router -> label/action store -> wake now or aggregate queue -> agent wake
```

The long-term value is making email usable as an OpenClaw intake source without turning an inbox into an untrusted prompt channel. Gmail is the first source; the core primitive is broader: untrusted inbox item in, audited security decision and policy-controlled wake out.

What should make it great:

- Event-driven intake through Gmail watch/history, with polling as repair/backfill.
- Security classification before usefulness, including phishing, spoofing, credential theft, malicious links/attachments, impersonation, fake invoices/doc shares, and prompt injection.
- Quarantine lane for risky or uncertain mail, with Gmail labels/actions and human alerts that omit full raw body and attachment contents by default.
- Policy-owned routing where tags map to explicit behavior: `none`, `aggregate`, or `wake_now`.
- Structured output and durable decision logs for auditability, replay, and debugging.
- Attachment and link handling that starts with metadata only, then later adds scanners/sandboxes before anything reaches normal agent context.
- Thread-aware routing so known active conversations are treated differently from cold mail with similar wording.
- Human feedback loops through alert UX, eventually allowing corrections like safe, harmful, wrong tag, wake now, mute sender, or always aggregate.
- Least-privilege Gmail scopes: read, labels, and modify only when configured; no send scope in this plugin.

## Current Scaffold

This repo currently contains the plugin package scaffold, config/schema normalization, policy engine, SQLite state model, Gmail/auth seams, polling runtime, aggregate digest helper, detached-agent wake seam, dry-run-safe action executor, and credential-free unit tests.

V1 is intentionally boring and reliable:

- Polling-only Gmail intake.
- Gmail watch/history-capable intake interface, with polling retained as fallback and repair/backfill path.
- Per-user OAuth refresh tokens first, with auth hidden behind an interface for later Workspace domain-wide delegation.
- `gmail.modify` capable, but Gmail write actions are config-gated and dry-run safe.
- Read-only Gmail sources degrade to classify, alert, and log without label/archive.
- Security classifier uses OpenAI via a SecretRef for `OPENAI_API_KEY`, with a config-level `OPENAI_API_KEY` fallback for local installs. `openai_model` defaults to `gpt-5.5`.
- Security classification receives body text, stripped/sanitized HTML-derived text, normalized links, headers, and attachment metadata. It does not receive active/raw HTML as executable-looking context, and links are not fetched.
- `uncertain` fails closed by default and quarantines.
- Router classification sees safe normalized/clipped body, metadata, and the security sanitized summary.
- Suspicious alerts are Slack plus local durable log in v1; webhook and OpenClaw-channel sinks remain action-layer extension points.
- `wake_now` targets a named wake policy resolving to agent/workspace/session data and uses detached agent wake semantics, not Slack as orchestration.
- SQLite stores idempotency, decisions, aggregate queues, replay/event inputs, and per-source cursor state.
- Service methods support config validation, status/probe, bounded backfill, Gmail Pub/Sub HTTP notification handoff, message inspection, replay from stored intake events, aggregate draining, and text-based quarantine review/feedback.

## Privacy And Safety Invariants

- Gmail candidate queries are retrieval filters only.
- Security and business routing decisions come from structured LLM classifier output.
- Suspicious full bodies and attachment contents are never placed in normal agent wake payloads.
- Attachments are represented as metadata only in v1.
- Every processed message gets a durable SQLite decision log entry.
- Idempotency key is `sourceId + Gmail messageId`.
- `dryRun` records intended actions without executing Gmail, Slack, local log, or wake side effects. When `dryRun` is `true`, it overrides every `actions.*.mode`.
- `actions` is the single production rollout gate for side effects. Each action family supports `live`, `dry_run`, or `disabled`.

## Development

```sh
npm install
npm run preflight
```

## Operator Workflow

Phase 3 adds the service surfaces needed to run the plugin in a real install without reading SQLite by hand first.

Recommended dry-run rollout:

1. Configure one source with `authRef` or `credentialRef`, `dryRun: true`, a local SQLite path, and conservative `actions` modes.
2. Configure `openaiApiKeyRef` for `OPENAI_API_KEY`, or use the fallback `OPENAI_API_KEY` config field for local testing.
3. Add one Slack alert sink, one quarantine label, one wake target, a `webhookSecret`, and a small tag policy.
4. Start the service and call `validateConfig()` and `status()`.
5. Run bounded `backfill({ sourceId, query, maxResults, dryRun: true })`.
6. Use `inspectMessage({ sourceId, messageId })` to review events, decisions, and action attempts.
7. Use `gmail_intake_firewall_review` for text-based quarantine review when an agent needs to list quarantined items, present safe metadata to a human, record feedback, wake a target, or add sender preferences.
8. Enable selected Gmail/Slack/wake actions by moving individual `actions.*.mode` values to `live` only after dry-run decisions look correct.

Current gateway-compatible secret refs are inline credential objects, env refs, and file refs. For Gmail OAuth, the recommended v1 shape is an env or file ref whose value is JSON:

```json
{
  "refreshToken": "google-oauth-refresh-token",
  "clientId": "google-oauth-client-id",
  "clientSecret": "google-oauth-client-secret",
  "scopes": ["https://www.googleapis.com/auth/gmail.modify"]
}
```

For example, set `GMAIL_PRIMARY_OAUTH_JSON` to that JSON and configure `"authRef": { "source": "env", "provider": "env", "id": "GMAIL_PRIMARY_OAUTH_JSON" }`. A file ref may use `"authRef": { "source": "file", "provider": "file", "id": "/secure/path/gmail-primary.json" }`. The plugin still supports host-injected secret resolvers when OpenClaw provides one, but it no longer requires that undocumented runtime surface for gateway Pub/Sub processing.

Service methods:

- `validateConfig()` returns actionable config errors/warnings for duplicate ids, missing wake targets, invalid aggregate cadences, invalid timezones, watch mode without a topic, and likely Gmail scope mismatches.
- `status()` reports configured sources, per-source cursor/state, last poll status/error stage, pending aggregate count, processed counts, quarantine counts, failed action attempts, and aggregate timezone.
- `doctor()` combines config validation, redacted auth readiness, last poll/watch diagnostics, dry-run state, Gmail scope readiness, and suggested watch operations into one operator health report.
- `supportBundle()` returns a redacted troubleshooting payload with validation, runtime readiness, auth readiness, status, review counters, and safe notes. It excludes raw bodies, raw HTML, attachment contents, OAuth tokens, client secrets, and API keys.
- `setupWatch({ sourceId, force })` explicitly registers a Gmail watch for one watch-mode source, stores Gmail's returned `historyId`/expiration, and does not process the initial mailbox snapshot.
- `renewWatch({ sourceId, force })` renews one source when the configured renewal window is due, or all watch sources when no `sourceId` is supplied. Renewal drains old history before calling Gmail `watch`.
- `repairWatch({ sourceId, force })` runs a bounded history repair for watch-mode sources that have gone too long without notification/history/repair activity.
- `backfill(options)` runs bounded replay from Gmail candidates. Through the plugin service, `query` or `maxResults` is required unless `allowUnbounded: true` is explicit.
- `handleGmailNotification(options)` accepts a direct Gmail notification or Pub/Sub push envelope. It resolves the source by `sourceId` or Gmail `emailAddress`, drains Gmail history from the stored cursor, records `gmail_watch` intake events, and updates the cursor. If no stored cursor exists, it records the notification history id and skips processing rather than guessing a starting point.
- `POST /gmail-intake-firewall/pubsub` is the HTTP route for Gmail Pub/Sub push delivery. It requires `webhookSecret` as `Authorization: Bearer <secret>`, `x-openclaw-token`, or a `token` query parameter. The route is intentionally plugin-authenticated rather than operator-authenticated so Google Pub/Sub can call it.
- `inspectMessage({ sourceId, messageId })` returns stored intake events, decisions, and append-only action attempts for one message.
- `replayEvent({ sourceId, messageId, force, dryRun })` reprocesses the latest stored intake event for a message, useful after classifier or policy changes.
- `drainAggregates()` sends due digest wakes. Daily and weekly cadence checks use `aggregate.timezone`; hourly cadence remains elapsed-time based.

Review tool:

- `gmail_intake_firewall_status` is read-only status/probe/config/auth inspection plus `doctor` and `supportBundle` diagnostics.
- `gmail_intake_firewall_review` is the write-capable text review tool. Supported operations: `listQuarantine`, `getQuarantineItem`, `reviewSummary`, `recordFeedback`, `markHarmful`, `releaseFromQuarantine`, `replayWithFeedback`, `wakeNow`, `muteSender`, `unmuteSender`, `alwaysAggregate`, `removeAlwaysAggregate`, `muteDomain`, `unmuteDomain`, `alwaysAggregateDomain`, `removeAlwaysAggregateDomain`, and `listPreferences`.
- Review payloads are safe by default: metadata, auth headers, link domains, attachment metadata, risk reasons, sanitized summary, action history, and feedback history. They do not include full raw body, raw HTML, or attachment contents.
- `muteSender`, `alwaysAggregate`, and their domain variants create preferences that affect future safe routing only. They do not override the security classifier or release risky mail from quarantine. Use `unmuteSender`, `removeAlwaysAggregate`, and the matching domain removals to clear active preferences.
- `releaseFromQuarantine` can remove the configured quarantine label and optionally restore `INBOX` after a human marks an item safe. Gmail mutation still requires `hasModifyScope: true`; `dryRun` and `actions.gmail.removeLabel` / `actions.gmail.restoreInbox` decide whether the planned Gmail actions execute live.
- `replayWithFeedback` records the human decision and replays the latest stored intake event with `force: true` by default, so a reviewed-safe message can run through security/router policy again and produce the normal label/aggregate/wake behavior.
- `wakeNow` creates a sanitized detached wake from the reviewed decision. It requires an explicit `wakeTarget` for reviewed quarantines and does not include raw suspicious body or attachments.
- Artifact analysis is local and non-fetching by default. Link metadata includes structural risk hints without requesting URLs, and attachment metadata includes filename/MIME/extension risk hints without downloading or opening attachment bytes. Keep `artifacts.fetchLinks` and `artifacts.downloadAttachments` false in this version.
- Deprecated `gmailActions.enabled`, `gmailActions.applyLabels`, and `gmailActions.archive` keys may remain in existing config files during update, but they are ignored. Use `actions.*.mode` for rollout policy and `gmailActions.hasModifyScope` only for source Gmail modify capability.

## Gmail Watch / PubSub Production Setup

Use watch mode when the OpenClaw gateway can receive Google Pub/Sub push requests. Polling and history repair remain enabled because Gmail notifications can be delayed or dropped.

Google Cloud setup:

1. Enable Gmail API and Pub/Sub API in the same Google Cloud project used by the OAuth client.
2. Create a Pub/Sub topic, for example `projects/my-project/topics/gmail-intake`.
3. Grant Gmail publish permission on that topic per the Gmail push notification docs. The topic project id must match the developer project used by the watch request.
4. Create a push subscription targeting the OpenClaw gateway route: `https://<gateway-host>/gmail-intake-firewall/pubsub`.
5. Configure the subscription to pass the plugin `webhookSecret` as either `Authorization: Bearer <secret>`, `x-openclaw-token`, or a `token` query parameter. Shared-secret auth is the v1 production path; Pub/Sub OIDC verification is planned later.

Plugin config shape:

```json
{
  "webhookSecret": "use-an-openclaw-secret-or-private-config-value",
  "watch": {
    "autoSetup": true,
    "renewBeforeMs": 86400000,
    "repairOnNoNotificationMs": 21600000,
    "labelIds": ["INBOX"],
    "labelFilterBehavior": "INCLUDE"
  },
  "sources": [
    {
      "id": "primary",
      "accountEmail": "user@example.com",
      "intakeMode": "watch",
      "watchTopicName": "projects/my-project/topics/gmail-intake",
      "historyLookback": "2d",
      "authRef": { "source": "env", "provider": "env", "id": "GMAIL_PRIMARY_OAUTH_JSON" }
    }
  ]
}
```

Operator runbook:

1. Start with `dryRun: true`.
2. Call `gmail_intake_firewall_status` with `operation: "validateConfig"` and fix all errors.
3. Call `gmail_intake_firewall_status` with `operation: "checkSourceAuth"` for the watch source.
4. Call `gmail_intake_firewall_status` with `operation: "setupWatch", sourceId: "primary"`.
5. Confirm `status().sources[].readiness.historyCursorPresent` and `watchActive` are true.
6. Send a test email. The first Gmail watch notification may only establish the cursor; subsequent notifications should drain Gmail history and process messages.
7. Watch `lastNotificationAt`, `lastHistoryAt`, `lastWatchRenewalAt`, `watchNeedsRenewal`, and `missedNotificationRepairDue` in status.
8. If notifications appear missed, call `gmail_intake_firewall_status` with `operation: "repairWatch", sourceId: "primary", force: true`.
9. If watch expiration is near or status reports `watchNeedsRenewal`, call `operation: "renewWatch", sourceId: "primary", force: true`.

Agent-facing quarantine review prompt:

```text
You are reviewing a quarantined Gmail item through gmail-intake-firewall.

1. Call gmail_intake_firewall_review with operation=listQuarantine or reviewSummary to find pending items.
2. For a selected item, call operation=getQuarantineItem with sourceId and messageId.
3. Show the human only safe fields: sender, reply-to, recipients, subject, date, Gmail link, labels, SPF/DKIM/DMARC/auth headers, link domains, link risk hints, attachment metadata/risk hints, risk reasons, suspicious signals, sanitized summary, and prior feedback/action status. Do not ask for or display raw body, raw HTML, snippet, fetched link content, or attachment contents.
4. Ask a concise text question such as:
   "This email was quarantined as possible phishing. Do you want me to mark it harmful, release it as safe, wake an agent with a sanitized summary, mute this sender, always aggregate this sender, or leave it quarantined?"
5. Map the human's answer to review operations:
   - harmful/scam/phishing -> markHarmful
   - safe/release -> releaseFromQuarantine, optionally restoreInbox=true
   - safe and route normally -> replayWithFeedback with feedbackType=safe
   - wake agent -> wakeNow with an explicit wakeTarget
   - mute sender -> muteSender
   - unmute sender -> unmuteSender
   - always aggregate sender -> alwaysAggregate
   - remove always aggregate -> removeAlwaysAggregate
   - domain-level preferences -> use the matching Domain operation only when the human clearly asks for all mail from that domain
   - request deeper artifact review -> explain that v1 only provides metadata/risk hints and requires an external approved workflow for opening links or files
6. After any operation, summarize what changed and include sourceId/messageId for auditability.
```

Example policy skeleton:

```json
{
  "dryRun": true,
  "webhookSecret": "replace-with-long-random-secret",
  "openaiApiKeyRef": { "source": "env", "provider": "env", "id": "OPENAI_API_KEY" },
  "openai_model": "gpt-5.5",
  "sqlitePath": "~/.openclaw/gmail-intake-firewall/state.sqlite",
  "actions": {
    "gmail": {
      "label": { "mode": "dry_run" },
      "archive": { "mode": "disabled" },
      "removeLabel": { "mode": "dry_run" },
      "restoreInbox": { "mode": "disabled" }
    },
    "slack": {
      "alert": { "mode": "dry_run" }
    },
    "wake": {
      "agent": { "mode": "dry_run" },
      "aggregate": { "mode": "dry_run" }
    },
    "local": {
      "log": { "mode": "live" }
    }
  },
  "sources": [
    {
      "id": "primary",
      "accountEmail": "user@example.com",
      "authRef": { "source": "env", "provider": "env", "id": "GMAIL_PRIMARY_OAUTH_JSON" },
      "enabled": true,
      "candidateQuery": "in:inbox newer_than:7d",
      "intakeMode": "poll",
      "polling": { "intervalMs": 60000, "maxResults": 25 },
      "gmailActions": {
        "hasModifyScope": true
      }
    }
  ],
  "security": {
    "quarantineLabel": "OpenClaw/Potentially Harmful",
    "alertTarget": "security",
    "archiveOnQuarantine": true
  },
  "alertSinks": [
    { "id": "security", "kind": "slack", "target": "slack:#security", "enabled": true }
  ],
  "wakeTargets": [
    { "id": "agent:client-dev", "agentId": "client-dev-agent", "workspaceDir": "/workspace" },
    { "id": "agent:digest", "agentId": "digest-agent", "workspaceDir": "/workspace" }
  ],
  "tags": [
    { "id": "client-development", "description": "Client development requests", "gmailLabel": "OpenClaw/ClientDev", "wakeMode": "wake_now", "wakeTarget": "agent:client-dev" },
    { "id": "newsletter", "description": "Newsletters and product updates", "gmailLabel": "OpenClaw/Newsletter", "wakeMode": "aggregate", "aggregateCadence": "daily", "wakeTarget": "agent:digest" },
    { "id": "receipt", "description": "Receipts and billing notices", "gmailLabel": "OpenClaw/Receipt", "wakeMode": "none" },
    { "id": "personal", "description": "Personal mail that should not wake agents", "wakeMode": "none" }
  ],
  "aggregate": {
    "maxDigestItems": 50,
    "timezone": "America/New_York"
  },
  "artifacts": {
    "analyzeLinks": true,
    "analyzeAttachments": true,
    "fetchLinks": false,
    "downloadAttachments": false,
    "maxDisplayedUrlChars": 160
  }
}
```

## Next Phase

The core value of `gmail-intake-firewall` is that it makes Gmail usable as an OpenClaw intake source without turning email into an untrusted prompt channel. It puts a security classification gate in front of agent exposure, quarantines risky or uncertain messages, and only wakes agents through explicit routing policy.

The next phase should build the real end-to-end v1 around the scaffold. Phase 1 has started with a testable polling runtime that can run enabled sources, emit intake events, fetch messages through an injected Gmail client, process decisions, persist SQLite cursors, and manage service start/stop timers.

1. Implement the real polling runtime.
   - Done: service runtime can start/stop polling loops per enabled source.
   - Done: poll with `candidateQuery/include/exclude`.
   - Done: emit `IntakeEvent` objects so watch/history can replace polling later.
   - Done: persist source cursors and poll timestamps in SQLite.
   - Done: connect runtime to direct Gmail API client factories.
   - Done: add history/watch-shaped source modes while preserving polling fallback.

2. Implement Gmail OAuth/API.
   - Done: resolve per-user OAuth refresh-token material through OpenClaw secrets/config.
   - Done: build direct `googleapis` Gmail clients.
   - Done: fetch metadata, headers, raw duplicate headers, text/html body, snippets, labels, and attachment metadata.
   - Done: do not download attachments.
   - Done: support read-only degradation when `gmailActions.hasModifyScope = false`.
   - Done: support Gmail history deltas and watch registration.

3. Implement the security classifier.
   - Done: use OpenAI Responses API with strict structured output.
   - Done: resolve `OPENAI_API_KEY` from `openaiApiKeyRef` or fallback config-level `OPENAI_API_KEY`.
   - Done: support `openai_model`, defaulting to `gpt-5.5`.
   - Input should be sanitized text, stripped HTML-derived text, normalized links, headers, auth headers, and attachment metadata.
   - Done: fail closed on classifier errors or uncertain verdicts.

4. Implement the router classifier.
   - Done: run only after safe security verdict.
   - Done: use configured tag definitions.
   - Done: keep classifier output constrained to tag ids and rationale.
   - Done: derive wake behavior from config, not classifier authority.

5. Implement side effects with retry safety.
   - Done: Gmail label/archive actions.
   - Done: Slack security alert adapter seam.
   - Done: detached OpenClaw agent wake adapter seam.
   - Done: local durable logs.
   - Done: add SQLite action status tracking so failures are retryable and messages are not marked fully complete prematurely.

6. Implement aggregate queue draining.
   - Done: parse `aggregateCadence` for hourly/daily/weekly due checks.
   - Done: group by source/cadence/wake target.
   - Done: build digest wakes from safe queued items.
   - Done: mark delivered items in SQLite after wake succeeds.

7. Add replay/backfill command.
   - Done: service backfill method accepts source/query/max result bounds.
   - Done: default skip processed messages.
   - Done: `force` option for reclassification.
   - Done: dry-run compatible.

8. Harden release readiness.
   - Add more integration-style tests with mocked Gmail/Slack/OpenClaw clients.
   - Add classifier schema tests.
   - Add action retry/idempotency tests.
   - Add example config docs for common deployments.

9. Remaining after Phase 2 foundation.
   - Done: add operator-grade poll diagnostics for gateway/service startup paths, including redacted stage-specific errors in logs and status output.
   - Done: add a service-level Gmail Pub/Sub notification handoff that drains stored history cursors.
   - Done: add authenticated `POST /gmail-intake-firewall/pubsub` route for host HTTP/PubSub delivery.
   - Done: add full install/runbook examples for Gmail OAuth and Pub/Sub setup.
   - Expand Slack feedback buttons from recorded feedback events into rule/example updates.
   - Add richer thread-aware classifier prompts using bounded thread context.

The highest-leverage next task is a real dry-run install against a test Gmail account: configure OAuth, run watch/history or polling fallback, verify OpenAI security/router output, and inspect the SQLite decision/action logs before enabling Gmail modifications.

## Decisions

See `docs/v1-decisions.md`.
