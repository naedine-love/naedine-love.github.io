const express = require("express");
const cors = require("cors");
const crypto = require("node:crypto");
const admin = require("firebase-admin");
const questions = require("./protected-questions.json");

const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: "https://naedine-love.github.io", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization"] }));
app.use(express.json({ limit: "32kb" }));

let firebaseReady = false;
try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (raw) {
    const serviceAccount = JSON.parse(raw);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id
    });
    firebaseReady = true;
  }
} catch (error) {
  console.error("Firebase Admin initialization failed:", error.message);
}

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const CHANNEL_ID = process.env.TELEGRAM_CHANNEL_ID || "@zhenazekaa";
const MAX_AUTH_AGE_SECONDS = 600;

function sendError(res, status, code, message) {
  return res.status(status).json({ ok: false, code, message });
}

function requireConfig(res) {
  if (!firebaseReady || !BOT_TOKEN) {
    sendError(res, 503, "firebase_not_configured", "Сервер проверки ещё не настроен.");
    return false;
  }
  return true;
}

async function firebaseUser(req, res) {
  const header = req.get("authorization") || "";
  const match = header.match(/^Bearer (.+)$/i);
  if (!match) {
    sendError(res, 401, "auth_required", "Нужно войти в игру.");
    return null;
  }
  try {
    return await admin.auth().verifyIdToken(match[1]);
  } catch {
    sendError(res, 401, "invalid_firebase_token", "Сессия игры устарела. Обновите страницу.");
    return null;
  }
}

function verifyTelegramWidget(data) {
  if (!data || typeof data !== "object" || !data.id || !data.auth_date || !data.hash) {
    const error = new Error("Недостаточно данных Telegram.");
    error.code = "telegram_auth_invalid";
    throw error;
  }
  const authDate = Number(data.auth_date);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(authDate) || authDate > now + 30 || now - authDate > MAX_AUTH_AGE_SECONDS) {
    const error = new Error("Время входа через Telegram истекло.");
    error.code = "telegram_auth_expired";
    throw error;
  }
  const checkString = Object.keys(data)
    .filter((key) => key !== "hash" && data[key] !== undefined && data[key] !== null)
    .sort()
    .map((key) => key + "=" + String(data[key]))
    .join("\n");
  const secretKey = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256", secretKey).update(checkString).digest();
  let actual;
  try { actual = Buffer.from(String(data.hash), "hex"); } catch { actual = Buffer.alloc(0); }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    const error = new Error("Не удалось подтвердить вход Telegram.");
    error.code = "telegram_auth_invalid";
    throw error;
  }
  return { id: String(data.id), username: String(data.username || ""), firstName: String(data.first_name || "") };
}

async function getMembership(telegramId) {
  const url = "https://api.telegram.org/bot" + BOT_TOKEN + "/getChatMember";
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ chat_id: CHANNEL_ID, user_id: telegramId })
  });
  const result = await response.json();
  if (!response.ok || !result.ok) {
    const description = String(result.description || "");
    if (/not enough rights|chat not found|member list is inaccessible/i.test(description)) {
      const error = new Error("Боту нужны права администратора канала.");
      error.code = "bot_not_admin";
      throw error;
    }
    const error = new Error("Telegram временно не смог проверить подписку.");
    error.code = "telegram_api_error";
    throw error;
  }
  const member = result.result || {};
  return member.status === "creator" || member.status === "administrator" ||
    member.status === "member" || (member.status === "restricted" && member.is_member === true);
}

function privateTelegramRef(uid) {
  return admin.firestore().doc("users/" + uid + "/private/telegram");
}
function entitlementRef(uid) {
  return admin.firestore().doc("users/" + uid + "/entitlements/telegram");
}

async function grantIfSubscribed(uid, telegramId, profile, res) {
  let subscribed;
  try {
    subscribed = await getMembership(telegramId);
  } catch (error) {
    return sendError(res, error.code === "bot_not_admin" ? 503 : 502, error.code || "telegram_api_error", error.message);
  }
  if (!subscribed) {
    await entitlementRef(uid).delete().catch(() => {});
    return sendError(res, 403, "not_subscribed", "Подписка на канал «Наедине» не найдена.");
  }
  const now = admin.firestore.FieldValue.serverTimestamp();
  await privateTelegramRef(uid).set({
    telegramId: String(telegramId),
    username: profile && profile.username ? profile.username : "",
    linkedAt: now
  }, { merge: true });
  await entitlementRef(uid).set({
    active: true,
    channel: CHANNEL_ID,
    checkedAt: now
  }, { merge: true });
  return res.json({ ok: true, blocks: questions });
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, firebaseConfigured: firebaseReady, telegramConfigured: !!BOT_TOKEN });
});

app.post("/api/telegram/verify", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  try {
    const telegram = verifyTelegramWidget(req.body && req.body.telegram);
    return await grantIfSubscribed(user.uid, telegram.id, telegram, res);
  } catch (error) {
    return sendError(res, 401, error.code || "telegram_auth_invalid", error.message || "Не удалось проверить Telegram.");
  }
});

app.post("/api/telegram/access", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  const linked = await privateTelegramRef(user.uid).get();
  if (!linked.exists || !linked.data().telegramId) {
    await entitlementRef(user.uid).delete().catch(() => {});
    return sendError(res, 403, "telegram_not_linked", "Сначала войдите через Telegram.");
  }
  const telegramId = linked.data().telegramId;
  return grantIfSubscribed(user.uid, telegramId, { username: linked.data().username || "" }, res);
});

app.listen(process.env.PORT || 10000, "0.0.0.0", () => {
  console.log("Naedine Telegram access API started");
});
