# Gmail Pub/Sub Watch Setup

Watch mode is the preferred production intake path when the OpenClaw gateway can receive Google Pub/Sub push requests. Polling remains useful as a repair and backfill path because Gmail notifications can be delayed or dropped.

## Google Cloud Setup

1. Enable Gmail API and Pub/Sub API in the Google Cloud project that owns the OAuth client.
2. Create a Pub/Sub topic, for example:

```text
projects/my-project/topics/gmail-intake
```

3. Grant Gmail permission to publish to that topic. The topic project must match the developer project used by the Gmail `watch` request.
4. Create a push subscription that targets the OpenClaw gateway route:

```text
https://<gateway-host>/gmail-intake-firewall/pubsub
```

5. Configure the subscription to send the plugin `webhookSecret` as one of these header forms:

- `Authorization: Bearer <secret>`
- `x-openclaw-token: <secret>`

Shared-secret route auth is the v1 path. Do not reuse the OpenAI key, Gmail OAuth tokens, Slack token, or any human account password as the webhook secret. The route also accepts `?token=<secret>` for local/debug compatibility, but do not use query-string secrets in production because gateway, proxy, and monitoring logs commonly retain URLs.

## Plugin Config

```json
{
  "dryRun": true,
  "webhookSecret": "replace-with-long-random-secret",
  "openaiApiKeyRef": { "source": "env", "provider": "env", "id": "OPENAI_API_KEY" },
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
      "enabled": true,
      "intakeMode": "watch",
      "watchTopicName": "projects/my-project/topics/gmail-intake",
      "historyLookback": "2d",
      "authRef": { "source": "env", "provider": "env", "id": "GMAIL_PRIMARY_OAUTH_JSON" },
      "gmailActions": {
        "hasModifyScope": true
      }
    }
  ]
}
```

The Gmail OAuth JSON referenced by `authRef` should include:

```json
{
  "refreshToken": "google-oauth-refresh-token",
  "clientId": "google-oauth-client-id",
  "clientSecret": "google-oauth-client-secret",
  "scopes": ["https://www.googleapis.com/auth/gmail.modify"]
}
```

Use `https://www.googleapis.com/auth/gmail.readonly` when the source should classify only and skip Gmail mutations.

## Setup Runbook

1. Start with `dryRun: true`.
2. Call `gmail_intake_firewall_status`:

```json
{ "operation": "validateConfig" }
```

3. Confirm source auth readiness:

```json
{ "operation": "checkSourceAuth", "sourceId": "primary" }
```

4. Register the Gmail watch:

```json
{ "operation": "setupWatch", "sourceId": "primary", "force": true }
```

5. Confirm `status.sources[].readiness.historyCursorPresent` and `watchActive` are true.
6. Send a test email to the watched account.
7. POST a valid Pub/Sub notification or wait for Google Pub/Sub delivery.
8. Confirm the route returns HTTP 200 and does not include raw message body in the response.
9. Confirm status fields move:

- `lastNotificationAt`
- `lastHistoryAt`
- `lastWatchRenewalAt`
- `watchNeedsRenewal`
- `missedNotificationRepairDue`

10. Run `doctor` and resolve any `rollout.findings`.

## Renewal And Repair

Gmail watches expire. The plugin reports `watchNeedsRenewal` when the watch is expired or inside the configured renewal window.

Renew one source:

```json
{ "operation": "renewWatch", "sourceId": "primary", "force": true }
```

Repair one source after missed notifications:

```json
{ "operation": "repairWatch", "sourceId": "primary", "force": true }
```

Renewal drains old history before registering a new watch. Repair drains stored history without creating a new watch.

## Expected Route Behavior

- `GET /gmail-intake-firewall/pubsub` returns 405.
- `POST` without a valid shared secret returns 401.
- `POST` with a valid bearer token or `x-openclaw-token` reaches the plugin handler.
- First notification with no stored cursor advances the cursor and skips processing rather than replaying the mailbox.
- Later notifications drain Gmail history from the stored cursor.
- Duplicate notification delivery is idempotent by `sourceId + Gmail messageId`.

## Troubleshooting

Use:

```json
{ "operation": "doctor" }
```

and:

```json
{ "operation": "supportBundle" }
```

Useful paths:

- `rollout.verdict`
- `rollout.productionChecklist`
- `rollout.suggestedOperations`
- `status.sources[].readiness`
- `status.sources[].lastPoll`
- `auth.sources[]`

The support bundle is redacted. It should preserve safe readiness booleans while excluding OAuth tokens, API keys, bearer tokens, raw email body, raw HTML, snippets, and attachment contents.
