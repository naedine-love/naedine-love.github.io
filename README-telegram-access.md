# Наедине — Telegram access API

Render web service for verifying Telegram channel membership before returning protected blocks 3–7.

## Required environment variables

- `TELEGRAM_BOT_TOKEN` — token for @NaedineAccessBot. Keep secret.
- `TELEGRAM_CHANNEL_ID` — defaults to `@zhenazekaa`.
- `FIREBASE_SERVICE_ACCOUNT_JSON` — complete Firebase service-account JSON.
- `FIREBASE_PROJECT_ID` — `koloda-app` (optional if present in service-account JSON).

The bot must be an administrator of @zhenazekaa. Configure the Telegram Login Widget domain with @BotFather for `naedine-love.github.io` using `/setdomain`.

The API verifies Firebase ID tokens, validates Telegram Login Widget HMAC data, calls getChatMember on every access check, stores the Telegram binding privately, and grants/removes a server-only Firestore entitlement. Protected questions live only in this backend repository file, not in the public site HTML.

## Endpoints

- `GET /health`
- `POST /api/telegram/verify` — Authorization: Bearer Firebase ID token; JSON body `{ "telegram": { ...widget data } }`
- `POST /api/telegram/access` — Authorization: Bearer Firebase ID token; rechecks the bound Telegram account's membership.

Deploy as a Node web service with build command `npm install` and start command `npm start`.
