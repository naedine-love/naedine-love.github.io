# Наедине — Telegram bot access API

Render web service that verifies membership in @zhenazekaa through the @NaedineAccessBot deep-link flow. No Telegram Login Widget or phone-number login is used.

## Required environment variables

- `TELEGRAM_BOT_TOKEN` — token for @NaedineAccessBot. Keep secret.
- `TELEGRAM_CHANNEL_ID` — defaults to `@zhenazekaa`.
- `FIREBASE_SERVICE_ACCOUNT_JSON` — complete Firebase service-account JSON.
- `FIREBASE_PROJECT_ID` — `koloda-app` (optional if present in service-account JSON).
- `PROTECTED_QUESTIONS_JSON` — private JSON object containing blocks 3–7; keep only in Render environment variables.

The bot must be an administrator of @zhenazekaa. On startup, the server configures the Telegram webhook automatically. A visitor taps the site button, the server creates a short-lived session and returns a `https://t.me/NaedineAccessBot?start=...` link. The bot receives `/start <session>`, checks the user's channel membership with `getChatMember`, and marks only that visitor's session verified. The browser polls the session and receives protected questions only after verification.

The webhook secret is derived server-side from the bot token; no additional environment variable is required.

## Endpoints

- `GET /health`
- `POST /api/telegram/start` — Authorization: Bearer Firebase ID token; creates a 10-minute session and returns the bot deep link.
- `POST /api/telegram/status` — Authorization: Bearer Firebase ID token; JSON body `{ "sessionId": "..." }`; returns pending or verified + protected blocks.
- `POST /api/telegram/access` — Authorization: Bearer Firebase ID token; rechecks the previously linked Telegram account on access restore.

Protected questions are never stored in the public repository or sent before successful membership verification.
