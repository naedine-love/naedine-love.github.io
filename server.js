const express = require("express");
const crypto = require("node:crypto");
const admin = require("firebase-admin");

const questions = (() => {
  try { return JSON.parse(process.env.PROTECTED_QUESTIONS_JSON || "null"); }
  catch { return null; }
})();

const app = express();
app.set("trust proxy", 1);
app.use((req, res, next) => {
  const origin = req.get("origin");
  if (!origin || origin === "https://naedine-love.github.io") {
    res.setHeader("Access-Control-Allow-Origin", origin || "https://naedine-love.github.io");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
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
const WEBHOOK_KEY = crypto.createHash("sha256").update("naedine-webhook:" + BOT_TOKEN).digest("hex");
const WEBHOOK_URL = "https://naedine-telegram-access.onrender.com/telegram/webhook/" + WEBHOOK_KEY;
const SESSION_TTL_MS = 10 * 60 * 1000;

function sendError(res, status, code, message) {
  return res.status(status).json({ ok: false, code, message });
}
function requireConfig(res) {
  if (!firebaseReady || !BOT_TOKEN || !questions) {
    sendError(res, 503, "server_not_configured", "Сервер проверки ещё не настроен.");
    return false;
  }
  return true;
}
async function firebaseUser(req, res) {
  const match = String(req.get("authorization") || "").match(/^Bearer (.+)$/i);
  if (!match) {
    sendError(res, 401, "auth_required", "Не удалось определить сессию игры.");
    return null;
  }
  try { return await admin.auth().verifyIdToken(match[1]); }
  catch {
    sendError(res, 401, "invalid_firebase_token", "Сессия игры устарела. Обновите страницу.");
    return null;
  }
}
async function getMembership(telegramId) {
  const response = await fetch("https://api.telegram.org/bot" + BOT_TOKEN + "/getChatMember", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ chat_id: CHANNEL_ID, user_id: Number(telegramId) })
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
async function grantAccess(uid, telegramUser) {
  const now = admin.firestore.FieldValue.serverTimestamp();
  await privateTelegramRef(uid).set({
    telegramId: String(telegramUser.id),
    username: String(telegramUser.username || ""),
    linkedAt: now
  }, { merge: true });
  await entitlementRef(uid).set({
    active: true, channel: CHANNEL_ID, checkedAt: now
  }, { merge: true });
}
async function sendBotMessage(chatId, text, replyMarkup) {
  const payload = { chat_id: chatId, text };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  return fetch("https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
}
const SUCCESS_IMAGE_BASE64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABwUFRkVEhwZFxkgHhwiK0cuKycnK1c+QjRHZ1tta2VbZGJygKSLcnmbe2JkjsKQm6mut7m3bonJ18ey1qS0t7D/2wBDAR4gICslK1QuLlSwdWR1sLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLD/wAARCACgAKADASIAAhEBAxEB/8QAGQAAAwEBAQAAAAAAAAAAAAAAAAECAwQF/8QALxAAAgIBAwQAAwcFAQAAAAAAAAECEQMSITEEQVFhEyIyBRRCUnGRoRUjYoGxwf/EABcBAQEBAQAAAAAAAAAAAAAAAAABAgP/xAAdEQEBAQEAAgMBAAAAAAAAAAAAARECITEDElFB/9oADAMBAAIRAxEAPwD27FYrFZh2VY7IsLBjQCUxhAAwAAATAGSxiIpCGAUh0NIZUSxFUFAJDACB0JooTKiAG0INGmUSl7o0cVoW4SkhkoYQAwHQE0FFCAmgoU27SjW/diU0tn9V1SCrAE1JX/0AGIBAAABA7ABFQC70MYVNFdkgodBAMKHQCGHG7MpZ1dRVgkt9NaFRmssn4LU/zKvYXLE5FtqXMdxNq/kVykjUSioqoqgmpjHTGufYxiATJKmmmQ2RYYEjCrHQDKyTaStvYNmrRnShVrdcey9seO5PZLcB2krboj40e1s5ZZXllfbsjSPBG/p+t1lX5WWpKXDOV5dIvjp8jT6DqM2vJ8OL2XP6metRJkoxuUe/YwSyZ56cSvy+yI6SSRs+op8muPqL2u0RD7NXOTK2/wDFGv8AT1HfHkf6SQ8peuW+Ke+n9jU446sc0pKmmdpqOXcyp3thwMTQRM3bIKaFRFiRhQ0gqxiCysmcvXz04oxX4mdSOT7QjeKMvDC8+3LiZ1L6ThhKmdmKSZHeuTNlalS5MviyT3TR6nTY4xnkbXzXz6Np44ZFU4qS9kxm95ceMskssljjzI9PFGOLGox4/wCmD6XH0+fXBv5lw+xpKVKwz1d9NviGkMh42XrnGdRjf+zr6bqI5Y3H/afYazefDvzQWWHhopySIhK0TaRWWqdlaUzHWVGZUxUo0TRo3qRDQJU0A6CiKlskbEVpSYZILLjlB9xIaYR5E4uE2mqaNMeSjt6np1lWqP1L+TzpRcHuqI7c3XoY8l0+50RkpL/w8qGRpnVjzBOudV1bqcH6MMsv7bN+ovNiWlXJOzmxxcnc1XpkrMjDH0t7yW7JT+7Z0/wvZnoNqMfZyPC+pzxxrvy/CDp/HfGexMsht92guG0vBcccI8RX6lyuGxxrJbOjG7DqIqTikt+Sox0ohWiewzNO3RbKgFYmyQYbEU0KiqkpchRUXTIDhmebp4ZlvtLyat2wKm48rN008T3W3lGSk4ntcqmc+XoseTePyP8AgmOs+T9ccMzTN1kjPnnyc+XpcuLfTa8rczjJxZG/F9N8ra2Z1dDiUcevmUv4OKUtcUu9nfgi4RVbCe2O74xuJvxuxN+SHNLg05HSW73ZEpEuTb2NIY63l+xFVjjtbKYP0YRWmMZKWlNfM/ZU9tWiWisd6fmvna+aHQUxUMAgoVDsOwBRMskY2nJWt6KM5w5aSknu4sEVCeq7VNdh2Rju5tpq33KsCrOXq+nU1rgqa5rudFhZFlxwYIKMre7R1fEFPFvcP2COFv6mkRbdJ5Gxxxzn6XlmsYQjwrfsuyppQhGHG78jYWCqnuVCJWNKWrne16KEA7CxAANiQhhTHYgCKBk2FgwMllBQVm2yW2a6Q0ohrC5DWs20oelBdZLUWrLoAmkAmwsoYCsLAdhZNgABYgCqTGSighCKABDEFgUMlMoIAAABshspktBYTENoRFIB0NIoEiqBIoJr/9k=";
async function sendBotPhoto(chatId, caption, replyMarkup) {
  const form = new FormData();
  form.append("chat_id", String(chatId));
  form.append("caption", caption);
  if (replyMarkup) form.append("reply_markup", JSON.stringify(replyMarkup));
  form.append("photo", new Blob([Buffer.from(SUCCESS_IMAGE_BASE64, "base64")], { type: "image/jpeg" }), "naedine-hearts.jpg");
  return fetch("https://api.telegram.org/bot" + BOT_TOKEN + "/sendPhoto", { method: "POST", body: form });
}
function subscriptionKeyboard(nonce) {
  return { inline_keyboard: [
    [{ text: "♡ Подписаться на канал", url: "https://t.me/zhenazekaa" }],
    [{ text: "✓ Я подписался", callback_data: "check_" + nonce }]
  ] };
}
function returnKeyboard() {
  return { inline_keyboard: [[{ text: "♡ Продолжить наше путешествие", url: "https://naedine-love.github.io/" }]] };
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, firebaseConfigured: firebaseReady, telegramConfigured: !!BOT_TOKEN, questionsConfigured: !!questions });
});

/* Сайт создаёт короткоживущую сессию и получает deep-link бота. */
app.post("/api/telegram/start", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  const nonce = crypto.randomBytes(18).toString("base64url");
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await admin.firestore().collection("telegramLoginSessions").doc(nonce).set({
    uid: user.uid, status: "pending", createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt
  });
  return res.json({ ok: true, sessionId: nonce, botUrl: "https://t.me/NaedineAccessBot?start=" + nonce });
});

/* Сайт опрашивает только свою сессию. В ответе вопросы отдаются лишь после проверки ботом. */
app.post("/api/telegram/status", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  const sessionId = String(req.body && req.body.sessionId || "");
  if (!/^[A-Za-z0-9_-]{20,40}$/.test(sessionId)) return sendError(res, 400, "invalid_session", "Ссылка проверки недействительна.");
  const ref = admin.firestore().collection("telegramLoginSessions").doc(sessionId);
  const snap = await ref.get();
  if (!snap.exists || snap.data().uid !== user.uid) return sendError(res, 404, "session_not_found", "Сессия проверки не найдена. Нажмите кнопку ещё раз.");
  const data = snap.data();
  if (Number(data.expiresAt) < Date.now()) {
    await ref.delete().catch(() => {});
    return sendError(res, 410, "session_expired", "Время проверки истекло. Попробуйте ещё раз.");
  }
  if (data.status !== "verified") return res.json({ ok: true, status: "pending" });
  const linked = await privateTelegramRef(user.uid).get();
  if (!linked.exists || !linked.data().telegramId) return sendError(res, 403, "telegram_not_linked", "Не удалось связать Telegram с игрой.");
  const subscribed = await getMembership(linked.data().telegramId);
  if (!subscribed) {
    await entitlementRef(user.uid).delete().catch(() => {});
    await ref.delete().catch(() => {});
    return sendError(res, 403, "not_subscribed", "Подписка на канал «Наедине» не найдена.");
  }
  await entitlementRef(user.uid).set({ active: true, channel: CHANNEL_ID, checkedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  await ref.delete().catch(() => {});
  return res.json({ ok: true, status: "verified", blocks: questions });
});

/* Telegram webhook: показывает подписку на канал и проверяет её по кнопке. */
app.post("/telegram/webhook/" + WEBHOOK_KEY, async (req, res) => {
  if (!firebaseReady || !BOT_TOKEN) return res.sendStatus(503);
  const headerSecret = req.get("x-telegram-bot-api-secret-token") || "";
  if (headerSecret !== WEBHOOK_KEY) return res.sendStatus(401);
  res.sendStatus(200);
  try {
    const update = req.body || {};
    if (update.callback_query) {
      const query = update.callback_query;
      const callbackData = String(query.data || "");
      const match = callbackData.match(/^check_([A-Za-z0-9_-]{20,40})$/);
      const chatId = query.message && query.message.chat && query.message.chat.id;
      const telegramUser = query.from;
      await fetch("https://api.telegram.org/bot" + BOT_TOKEN + "/answerCallbackQuery", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ callback_query_id: query.id, text: "Проверяю подписку…" })
      });
      if (!match || !chatId || !telegramUser) return;
      const nonce = match[1];
      const ref = admin.firestore().collection("telegramLoginSessions").doc(nonce);
      const snap = await ref.get();
      if (!snap.exists || snap.data().status !== "pending" || Number(snap.data().expiresAt) < Date.now()) {
        await sendBotMessage(chatId, "Ссылка проверки устарела. Вернитесь на сайт и нажмите «Подписаться на Telegram» ещё раз.");
        return;
      }
      const subscribed = await getMembership(telegramUser.id);
      if (!subscribed) {
        await sendBotMessage(chatId, "Пока не вижу вашу подписку на канал «Наедине» 💚\n\nПодпишитесь на канал, а затем нажмите «Я подписался».", subscriptionKeyboard(nonce));
        return;
      }
      await grantAccess(snap.data().uid, telegramUser);
      await ref.set({ status: "verified", telegramId: String(telegramUser.id), verifiedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      await sendBotMessage(chatId, "Подписка подтверждена! 💚\n\nДоступ к оставшимся пяти блокам открыт. Возвращайтесь к вашей колоде.", returnKeyboard());
      return;
    }

    const message = update.message;
    const messageText = String(message && message.text || "");
    const chatId = message && message.chat && message.chat.id;
    const from = message && message.from;
    const startMatch = messageText.match(/^\/start(?:\s+([A-Za-z0-9_-]{20,40}))?/);
    if (!chatId || !from || !startMatch) return;
    const nonce = startMatch[1];
    if (!nonce) {
      await sendBotMessage(chatId, "Привет! ❤️ Чтобы открыть полную колоду, вернитесь на сайт «Наедине» и нажмите «Подписаться на Telegram».");
      return;
    }
    const ref = admin.firestore().collection("telegramLoginSessions").doc(nonce);
    const snap = await ref.get();
    if (!snap.exists || snap.data().status !== "pending" || Number(snap.data().expiresAt) < Date.now()) {
      await sendBotMessage(chatId, "Ссылка проверки устарела. Вернитесь на сайт и нажмите «Подписаться на Telegram» ещё раз.");
      return;
    }
    const subscribed = await getMembership(from.id);
    if (!subscribed) {
      await sendBotMessage(chatId, "Привет! ❤️\n\nЧтобы открыть оставшиеся 5 блоков колоды для пар, подпишитесь на наш Telegram-канал, а затем нажмите «Я подписался».", subscriptionKeyboard(nonce));
      return;
    }
    await grantAccess(snap.data().uid, from);
    await ref.set({ status: "verified", telegramId: String(from.id), verifiedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    await sendBotMessage(chatId, "Вы уже подписаны! 💚\n\nДоступ к оставшимся пяти блокам открыт. Возвращайтесь к вашей колоде.", returnKeyboard());
  } catch (error) {
    console.error("Telegram webhook error:", error.message);
  }
});

/* Совместимость с уже выданным доступом: при каждом восстановлении подписка проверяется заново. */
app.post("/api/telegram/access", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  const linked = await privateTelegramRef(user.uid).get();
  if (!linked.exists || !linked.data().telegramId) {
    await entitlementRef(user.uid).delete().catch(() => {});
    return sendError(res, 403, "telegram_not_linked", "Сначала подтвердите подписку через бота.");
  }
  const telegramId = linked.data().telegramId;
  try {
    const subscribed = await getMembership(telegramId);
    if (!subscribed) {
      await entitlementRef(user.uid).delete().catch(() => {});
      return sendError(res, 403, "not_subscribed", "Подписка на канал «Наедине» не найдена.");
    }
    await entitlementRef(user.uid).set({ active: true, channel: CHANNEL_ID, checkedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.json({ ok: true, blocks: questions });
  } catch (error) {
    return sendError(res, error.code === "bot_not_admin" ? 503 : 502, error.code || "telegram_api_error", error.message);
  }
});

async function configureWebhook() {
  if (!BOT_TOKEN) return;
  try {
    const response = await fetch("https://api.telegram.org/bot" + BOT_TOKEN + "/setWebhook", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        url: WEBHOOK_URL,
        secret_token: WEBHOOK_KEY,
        allowed_updates: ["message", "callback_query"]
      })
    });
    const result = await response.json();
    if (!result.ok) console.error("Telegram setWebhook failed:", result.description || "unknown error");
    else console.log("Telegram webhook configured");
  } catch (error) {
    console.error("Telegram webhook setup failed:", error.message);
  }
}
app.listen(process.env.PORT || 10000, "0.0.0.0", () => {
  console.log("Naedine Telegram access API started");
  configureWebhook();
});
