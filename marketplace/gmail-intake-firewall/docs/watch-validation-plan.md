# Watch Validation Plan

This plan is for proving the event-driven path under real gateway conditions before enabling live production actions.

## Test Matrix

Run the matrix with `dryRun: true` first. Repeat the positive path with selected `actions.*.mode` values set to `live` only after dry-run results are correct.

### 1. Version And Load

- package, manifest, runtime export, and `openclaw plugins inspect` report the expected version.
- gateway health is clean.
- plugin is loaded.
- `gmail_intake_firewall_status` exists.

### 2. Config And Auth

Call:

```json
{ "operation": "validateConfig" }
```

Expected:

- no errors for the intended config.
- warnings are actionable and source-specific.
- secret refs include explicit `provider` values where the OpenClaw config schema requires them.

Call:

```json
{ "operation": "checkSourceAuth", "sourceId": "primary" }
```

Expected:

- readiness booleans are present.
- OAuth scopes are visible.
- raw tokens and client secrets are not present.

### 3. Doctor And Support Bundle

Call:

```json
{ "operation": "doctor" }
```

Expected:

- `rollout.verdict` matches the rollout stage.
- `rollout.productionChecklist` identifies missing setup.
- `rollout.suggestedOperations` includes setup, renewal, or repair operations when needed.
- action readiness reflects global `dryRun` and each configured action mode.

Call:

```json
{ "operation": "supportBundle" }
```

Expected:

- auth booleans remain booleans.
- scopes and source ids remain visible.
- no raw OAuth token, OpenAI key, webhook bearer token, raw body, raw HTML, snippet, or attachment contents.

### 4. Watch Setup

Call:

```json
{ "operation": "setupWatch", "sourceId": "primary", "force": true }
```

Expected:

- Gmail returns and stores a `historyId`.
- watch expiration is stored.
- no initial mailbox snapshot is processed.
- status reports `historyCursorPresent: true`.

### 5. Real Pub/Sub Route

Test the gateway route:

```text
POST http://127.0.0.1:<gateway-port>/gmail-intake-firewall/pubsub
```

Expected:

- GET returns 405.
- no token returns 401.
- wrong token returns 401.
- valid bearer or `x-openclaw-token` returns 200.
- first valid notification with no cursor skips safely.
- later valid notification drains stored Gmail history.
- route response does not include raw email content.

### 6. Gmail/OpenAI Dry-Run Smoke

Run bounded backfill:

```json
{
  "operation": "backfill",
  "sourceId": "primary",
  "maxResults": 1,
  "dryRun": true
}
```

Expected:

- Gmail OAuth succeeds.
- OpenAI classification succeeds.
- one candidate is processed or skipped idempotently.
- no Gmail, Slack, local log, or wake mutation executes while global `dryRun` is true.

### 7. Security Fixtures

Run or replay seeded fixtures for:

- safe client email
- irrelevant safe email
- prompt-injection email
- malicious verdict
- uncertain verdict

Expected:

- risky, malicious, and uncertain quarantine before router classification.
- suspicious alert payloads exclude raw body, raw HTML, snippet by default, and attachment contents.
- safe mail routes only through configured policy.

### 8. Renewal And Repair

Force stale watch state in a harness or wait until status reports renewal/repair due.

Expected:

- `renewWatch` drains old history before creating a new watch.
- `repairWatch` drains stored history and updates repair metadata.
- `doctor.rollout.suggestedOperations` changes after successful renewal/repair.

### 9. Idempotency

Repeat the same notification/backfill without `force`.

Expected:

- fetched/processed stay at zero for already-processed messages.
- skipped count increments.
- no new non-forced decision row is appended.

Force replay only when audit append behavior is desired.

### 10. Review Tool

Seed or process one quarantined item.

Expected:

- `reviewSummary` reports pending/reviewed/harmful counters.
- `listQuarantine` returns compact safe fields.
- `getQuarantineItem` excludes raw body, raw HTML, snippet, and attachment contents.
- `wakeNow` requires an explicit `wakeTarget`.
- preferences remain source-scoped and do not override security quarantine.

## Pass Criteria

The watch path is launch-ready when:

- real gateway Pub/Sub route dispatches with valid shared-secret auth.
- Gmail history drains successfully from a real notification using the gateway runtime.
- `doctor.rollout.verdict` is `ready` or any remaining `caution` items are intentional for the rollout stage.
- dry-run mutation counters remain zero while `dryRun: true`.
- duplicate notification and duplicate backfill are idempotent.
- support artifacts are redacted.

