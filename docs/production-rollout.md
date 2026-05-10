# Production Rollout

This plugin should be moved to live side effects in stages. The goal is to prove classification, quarantine, routing, and watch delivery before Gmail, Slack, or wake actions can mutate production systems.

## Rollout Gates

Use `gmail_intake_firewall_status` with `operation: "doctor"` before every rollout step. The `rollout` block is the production gate:

- `verdict: "blocked"` means do not enable live actions.
- `verdict: "caution"` means the plugin can be tested, but at least one production concern remains, commonly `dryRun: true`, dry-run action modes, disabled alert lanes, or watch setup work.
- `verdict: "ready"` means config validation, auth readiness, source readiness, and action capabilities are consistent with live rollout.

The `supportBundle` operation returns the same rollout block plus redacted validation, auth, status, review counters, and notes. It is intended for debugging and handoff, not for exposing raw email content.

## Action Modes

`dryRun: true` is the global kill switch for side effects. When enabled, every action resolves to `dry_run` even if a specific action mode is configured as `live`.

Individual action modes are configured under `actions`:

```json
{
  "dryRun": true,
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
  }
}
```

Recommended live order:

1. Keep `dryRun: true` and all external actions at `dry_run` or `disabled`.
2. Run `validateConfig`, `checkSourceAuth`, `doctor`, and a bounded dry-run backfill.
3. Enable `actions.local.log.mode: "live"` first if local audit artifacts are desired.
4. Enable `actions.gmail.label.mode: "live"` only after quarantine decisions are accurate and the Gmail source has modify scope.
5. Enable `actions.slack.alert.mode: "live"` after alert payloads have been reviewed for safe fields.
6. Enable `actions.wake.aggregate.mode: "live"` before `actions.wake.agent.mode: "live"` so lower-urgency routing is exercised first.
7. Enable archive, quarantine release, and restore actions last.
8. Set `dryRun: false` only when all live action modes are intentional.

## Success Criteria

Before a source is considered production-ready:

- `validateConfig` has no errors.
- `checkSourceAuth` returns `ok: true` for every enabled source.
- `doctor.rollout.verdict` is `ready`, or any `caution` findings are explicitly accepted for the rollout stage.
- `supportBundle` contains no raw OAuth tokens, API keys, raw body, raw HTML, snippets, attachment contents, or bearer tokens.
- A bounded dry-run backfill classifies at least one message and records a decision.
- Duplicate processing skips the same `sourceId + messageId` without appending duplicate non-forced decisions.
- Risky, malicious, and uncertain messages quarantine before router classification.
- Safe messages only wake or aggregate according to configured tag policy.
- Watch-mode sources have a stored cursor and either active watch readiness or an accepted repair plan.

## Operator Checklist

1. Configure secrets with explicit `provider` values, for example:

```json
{
  "openaiApiKeyRef": { "source": "env", "provider": "env", "id": "OPENAI_API_KEY" },
  "sources": [
    {
      "id": "primary",
      "accountEmail": "user@example.com",
      "authRef": { "source": "env", "provider": "env", "id": "GMAIL_PRIMARY_OAUTH_JSON" }
    }
  ]
}
```

2. Run:

```json
{ "operation": "validateConfig" }
```

3. Run:

```json
{ "operation": "checkSourceAuth" }
```

4. Run:

```json
{ "operation": "doctor" }
```

5. If using watch mode, follow `docs/pubsub-watch.md`.
6. Run a bounded backfill with `dryRun: true`.
7. Review `inspectMessage` and `reviewSummary` output.
8. Move one action mode at a time from `dry_run` to `live`.
9. Re-run `doctor` after each change.

