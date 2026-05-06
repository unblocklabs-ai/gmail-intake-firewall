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
- Security classifier uses OpenAI via an OpenClaw SecretRef for `OPENAI_API_KEY`, with a config-level `OPENAI_API_KEY` fallback for local installs. `openai_model` defaults to `gpt-5.5`.
- Security classification receives body text, stripped/sanitized HTML-derived text, normalized links, headers, and attachment metadata. It does not receive active/raw HTML as executable-looking context, and links are not fetched.
- `uncertain` fails closed by default and quarantines.
- Router classification sees safe normalized/clipped body, metadata, and the security sanitized summary.
- Suspicious alerts are Slack plus local durable log in v1; webhook and OpenClaw-channel sinks remain action-layer extension points.
- `wake_now` targets a named wake policy resolving to agent/workspace/session data and uses detached agent wake semantics, not Slack as orchestration.
- SQLite stores idempotency, decisions, aggregate queues, replay/event inputs, and per-source cursor state.
- Service methods support bounded backfill, aggregate draining, and feedback event recording.

## Privacy And Safety Invariants

- Gmail candidate queries are retrieval filters only.
- Security and business routing decisions come from structured LLM classifier output.
- Suspicious full bodies and attachment contents are never placed in normal agent wake payloads.
- Attachments are represented as metadata only in v1.
- Every processed message gets a durable SQLite decision log entry.
- Idempotency key is `sourceId + Gmail messageId`.
- `dryRun` records intended actions without executing Gmail, Slack, or wake side effects.

## Development

```sh
npm install
npm run preflight
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
   - Wire actual Pub/Sub push delivery from host infrastructure into Gmail history processing.
   - Add full install examples for Gmail OAuth and Pub/Sub setup.
   - Expand Slack feedback buttons from recorded feedback events into rule/example updates.
   - Add richer thread-aware classifier prompts using bounded thread context.

The highest-leverage next task is a real dry-run install against a test Gmail account: configure OAuth, run watch/history or polling fallback, verify OpenAI security/router output, and inspect the SQLite decision/action logs before enabling Gmail modifications.

## Decisions

See `docs/v1-decisions.md`.
