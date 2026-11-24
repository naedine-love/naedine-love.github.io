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
const ADMIN_IDS = new Set(String(process.env.ADMIN_TELEGRAM_IDS || "").split(",").map(x => x.trim()).filter(x => /^\d+$/.test(x)));
const ADMIN_CHALLENGE_TTL_MS = 2 * 60 * 1000;
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
function sha256(value) { return crypto.createHash("sha256").update(String(value)).digest("hex"); }
function adminAuthorized(req, res, next) {
  const match = String(req.get("authorization") || "").match(/^Bearer (.+)$/i);
  if (!match) return sendError(res, 401, "admin_auth_required", "Сначала войдите через Telegram.");
  const ref = admin.firestore().collection("adminSessions").doc(sha256(match[1]));
  ref.get().then(snap => {
    if (!snap.exists || Number(snap.data().expiresAt) < Date.now()) return sendError(res, 401, "admin_session_expired", "Сессия завершилась. Войдите ещё раз.");
    req.adminSessionRef = ref;
    next();
  }).catch(() => sendError(res, 503, "admin_auth_unavailable", "Не удалось проверить доступ администратора."));
}

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
async function grantDeviceAccess(deviceKeyHash, telegramUser) {
  if (!deviceKeyHash) return;
  await admin.firestore().collection("deviceEntitlements").doc(deviceKeyHash).set({
    telegramId: String(telegramUser.id),
    active: true,
    channel: CHANNEL_ID,
    checkedAt: admin.firestore.FieldValue.serverTimestamp()
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
const SUCCESS_IMAGE_URL = "https://images.stockcake.com/public/3/1/1/31146775-fa4c-4de6-9491-cb4f71e9f224_large/intertwined-pastel-hearts-stockcake.jpg";
async function sendBotPhoto(chatId, caption, replyMarkup) {
  const form = new FormData();
  form.append("chat_id", String(chatId));
  form.append("caption", caption);
  if (replyMarkup) form.append("reply_markup", JSON.stringify(replyMarkup));
  form.append("photo", SUCCESS_IMAGE_URL);
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


/* Закрытая статистика: вход подтверждается Telegram ID из серверного allowlist. */
app.post("/api/admin/login/start", async (_req, res) => {
  if (!firebaseReady || !BOT_TOKEN || ADMIN_IDS.size === 0) return sendError(res, 503, "admin_not_configured", "Администраторский доступ ещё не настроен.");
  try {
    const challengeId = crypto.randomBytes(24).toString("base64url");
    const expiresAt = Date.now() + ADMIN_CHALLENGE_TTL_MS;
    await admin.firestore().collection("adminLoginChallenges").doc(challengeId).set({
      status: "pending", createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt
    });
    return res.json({ ok: true, challengeId, expiresAt, botUrl: "https://t.me/NaedineAccessBot?start=admin_" + challengeId });
  } catch (error) {
    return sendError(res, 503, "admin_login_start_failed", "Не удалось начать вход. Попробуйте ещё раз.");
  }
});

app.get("/api/admin/login/status", async (req, res) => {
  if (!firebaseReady) return sendError(res, 503, "server_not_configured", "Сервер ещё не настроен.");
  const challengeId = String(req.query.challengeId || "");
  if (!/^[A-Za-z0-9_-]{24,40}$/.test(challengeId)) return sendError(res, 400, "invalid_challenge", "Ссылка входа недействительна.");
  const ref = admin.firestore().collection("adminLoginChallenges").doc(challengeId);
  try {
    const snap = await ref.get();
    if (!snap.exists) return sendError(res, 404, "challenge_not_found", "Запрос входа не найден.");
    const data = snap.data();
    if (Number(data.expiresAt) < Date.now()) {
      await ref.delete().catch(() => {});
      return sendError(res, 410, "challenge_expired", "Время входа истекло. Начните заново.");
    }
    if (data.status !== "approved") return res.json({ ok: true, status: "pending" });
    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = sha256(token);
    const sessionRef = admin.firestore().collection("adminSessions").doc(tokenHash);
    const db = admin.firestore();
    const outcome = await db.runTransaction(async tx => {
      const fresh = await tx.get(ref);
      if (!fresh.exists || fresh.data().status !== "approved" || fresh.data().consumed === true || Number(fresh.data().expiresAt) < Date.now()) return false;
      tx.set(sessionRef, {
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        expiresAt: Date.now() + ADMIN_SESSION_TTL_MS,
        telegramId: String(fresh.data().telegramId || "")
      });
      tx.update(ref, { status: "consumed", consumed: true, consumedAt: admin.firestore.FieldValue.serverTimestamp() });
      return true;
    });
    if (!outcome) return res.json({ ok: true, status: "pending" });
    return res.json({ ok: true, status: "approved", token, expiresAt: Date.now() + ADMIN_SESSION_TTL_MS });
  } catch (error) {
    return sendError(res, 503, "admin_login_status_failed", "Не удалось проверить подтверждение входа.");
  }
});

app.get("/api/admin/stats", adminAuthorized, async (req, res) => {
  const windowKey = ["today", "7d", "all"].includes(String(req.query.window || "7d")) ? String(req.query.window || "7d") : "7d";
  const now = Date.now();
  const todayStart = new Date(); todayStart.setUTCHours(0, 0, 0, 0);
  const cutoff = windowKey === "today" ? todayStart.getTime() : windowKey === "7d" ? now - 7 * 24 * 60 * 60 * 1000 : 0;
  try {
    const db = admin.firestore();
    const roomSnap = await db.collection("rooms").get();
    const rooms = roomSnap.docs;
    const uniqueParticipants = new Set();
    const blockUsers = Array.from({ length: 7 }, () => new Set());
    const blockRooms = Array.from({ length: 7 }, () => new Set());
    const daily = new Map();
    let completedBlockEvents = 0;
    let completedToday = 0;
    let completed7d = 0;
    let fullyCompletedRooms = 0;
    let roomsCreatedInWindow = 0;
    const dayKey = ms => new Date(ms).toISOString().slice(0, 10);
    const todayKey = dayKey(todayStart.getTime());
    for (const roomDoc of rooms) {
      const room = roomDoc.data() || {};
      const members = Array.isArray(room.members) ? room.members : [];
      members.forEach(uid => uniqueParticipants.add(String(uid)));
      if (Number(room.created || 0) >= cutoff) roomsCreatedInWindow++;
      const doneSnap = await roomDoc.ref.collection("done").get();
      const perMember = new Map();
      for (const doneDoc of doneSnap.docs) {
        const d = doneDoc.data() || {};
        const block = Number(d.block);
        const uid = String(d.uid || "");
        const ts = Number(d.ts || 0);
        if (!uid || block < 1 || block > 7) continue;
        completedBlockEvents++;
        blockUsers[block - 1].add(roomDoc.id + ":" + uid);
        blockRooms[block - 1].add(roomDoc.id);
        const set = perMember.get(uid) || new Set(); set.add(block); perMember.set(uid, set);
        if (ts >= todayStart.getTime()) completedToday++;
        if (ts >= now - 7 * 24 * 60 * 60 * 1000) completed7d++;
        if (ts >= cutoff) {
          const key = dayKey(ts);
          daily.set(key, (daily.get(key) || 0) + 1);
        }
      }
      if (members.length === 2 && members.every(uid => (perMember.get(String(uid)) || new Set()).size === 7)) fullyCompletedRooms++;
    }
    const entSnap = await db.collectionGroup("entitlements").get();
    const activeTelegramUsers = new Set();
    let telegramChecksToday = 0, telegramChecks7d = 0;
    for (const doc of entSnap.docs) {
      const entitlement = doc.data() || {};
      if (entitlement.active !== true) continue;
      const uid = doc.ref.parent.parent && doc.ref.parent.parent.id;
      if (uid) activeTelegramUsers.add(uid);
      const checkedAt = entitlement.checkedAt;
      const ms = checkedAt && typeof checkedAt.toMillis === "function" ? checkedAt.toMillis() : 0;
      if (ms >= todayStart.getTime()) telegramChecksToday++;
      if (ms >= now - 7 * 24 * 60 * 60 * 1000) telegramChecks7d++;
    }
    const dailySeries = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now - i * 24 * 60 * 60 * 1000);
      const key = dayKey(d.getTime());
      dailySeries.push({ date: key, completions: daily.get(key) || 0 });
    }
    return res.json({
      ok: true,
      generatedAt: now,
      window: windowKey,
      totals: {
        participants: uniqueParticipants.size,
        roomsCreated: rooms.length,
        fullyCompletedRooms,
        completedBlockEvents,
        activeTelegramUsers: activeTelegramUsers.size
      },
      period: {
        roomsCreated: roomsCreatedInWindow,
        completedBlocks: windowKey === "today" ? completedToday : windowKey === "7d" ? completed7d : completedBlockEvents,
        telegramChecks: windowKey === "today" ? telegramChecksToday : windowKey === "7d" ? telegramChecks7d : activeTelegramUsers.size
      },
      blocks: blockUsers.map((users, i) => ({ block: i + 1, participants: users.size, rooms: blockRooms[i].size })),
      daily: dailySeries
    });
  } catch (error) {
    console.error("Admin stats error:", error.message);
    return sendError(res, 503, "admin_stats_failed", "Не удалось загрузить статистику.");
  }
});


app.get("/health", (_req, res) => {
  res.json({ ok: true, firebaseConfigured: firebaseReady, telegramConfigured: !!BOT_TOKEN, questionsConfigured: !!questions });
});

/* Сайт создаёт короткоживущую сессию и получает deep-link бота. */
app.post("/api/telegram/start", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  const nonce = crypto.randomBytes(18).toString("base64url");
  const deviceKey = String(req.body && req.body.deviceKey || "");
  const deviceKeyHash = /^[a-f0-9]{64}$/i.test(deviceKey) ? sha256(deviceKey) : null;
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await admin.firestore().collection("telegramLoginSessions").doc(nonce).set({
    uid: user.uid, deviceKeyHash, status: "pending", createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
  const data = snap.exists ? snap.data() : null;
  const deviceKey = String(req.body && req.body.deviceKey || "");
  const deviceKeyHash = /^[a-f0-9]{64}$/i.test(deviceKey) ? sha256(deviceKey) : null;
  const sessionMatches = data && (data.deviceKeyHash
    ? data.deviceKeyHash === deviceKeyHash
    : data.uid === user.uid);
  if (!sessionMatches) return sendError(res, 404, "session_not_found", "Сессия проверки не найдена. Нажмите кнопку ещё раз.");
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
        await sendBotMessage(chatId, "Пока не вижу вашу подписку на канал «Наедине» 💚 Подпишитесь на канал, а затем нажмите «Я подписался».", subscriptionKeyboard(nonce));
        return;
      }
      await grantAccess(snap.data().uid, telegramUser);
      await grantDeviceAccess(snap.data().deviceKeyHash, telegramUser);
      await ref.set({ status: "verified", telegramId: String(telegramUser.id), verifiedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      await sendBotPhoto(chatId, "💗 Вы уже подписаны! Все оставшиеся темы «Наедине» для вас открыты. Продолжайте отвечать, делиться сокровенным и узнавать друг друга ещё ближе. ♡", returnKeyboard());
      return;
    }

    const message = update.message;
    const messageText = String(message && message.text || "");
    const chatId = message && message.chat && message.chat.id;
    const from = message && message.from;
    if (chatId && from && message && message.chat && message.chat.type === "private") {
      const adminStart = messageText.match(/^\/start\s+admin_([A-Za-z0-9_-]{24,40})$/);
      if (adminStart) {
        if (!ADMIN_IDS.has(String(from.id))) {
          await sendBotMessage(chatId, "У этого аккаунта нет доступа к панели статистики.");
          return;
        }
        const challengeRef = admin.firestore().collection("adminLoginChallenges").doc(adminStart[1]);
        const challengeSnap = await challengeRef.get();
        if (!challengeSnap.exists || challengeSnap.data().status !== "pending" || Number(challengeSnap.data().expiresAt) < Date.now()) {
          await sendBotMessage(chatId, "Запрос входа устарел. Вернитесь на страницу статистики и начните вход заново.");
          return;
        }
        await challengeRef.set({ status: "approved", telegramId: String(from.id), approvedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        await sendBotMessage(chatId, "Доступ администратора подтверждён 💚 Вернитесь на страницу статистики.");
        return;
      }
    }
    if (chatId && from && message && message.chat && message.chat.type === "private" && /^\/myid(?:@NaedineAccessBot)?$/.test(messageText.trim())) {
      await sendBotMessage(chatId, "Ваш числовой Telegram ID: " + String(from.id) + "\\n\\nОтправьте этот номер в чат с ChatGPT, чтобы настроить закрытый доступ администратора. Не публикуйте его в открытых каналах.");
      return;
    }
    const startMatch = messageText.match(/^\/start(?:\s+([A-Za-z0-9_-]{20,40}))?/);
    if (!chatId || !from || !startMatch) return;
    const nonce = startMatch[1];
    if (!nonce) {
      await sendBotMessage(chatId, "Привет! ❤️ Чтобы открыть все оставшиеся темы, вернитесь на сайт «Наедине» и нажмите «Подписаться на Telegram».");
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
      await sendBotMessage(chatId, "Привет! ❤️ Чтобы открыть оставшиеся 5 тем, подпишитесь на наш Telegram-канал, а затем нажмите «Я подписался».", subscriptionKeyboard(nonce));
      return;
    }
    await grantAccess(snap.data().uid, from);
    await ref.set({ status: "verified", telegramId: String(from.id), verifiedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    await sendBotPhoto(chatId, "💗 Вы уже подписаны! Все оставшиеся темы «Наедине» для вас открыты. Продолжайте отвечать, делиться сокровенным и узнавать друг друга ещё ближе. ♡", returnKeyboard());
  } catch (error) {
    console.error("Telegram webhook error:", error.message);
  }
});

/* Совместимость с уже выданным доступом: при каждом восстановлении подписка проверяется заново. */
app.post("/api/telegram/access", async (req, res) => {
  if (!requireConfig(res)) return;
  const user = await firebaseUser(req, res);
  if (!user) return;
  const deviceKey = String(req.body && req.body.deviceKey || "");
  const deviceKeyHash = /^[a-f0-9]{64}$/i.test(deviceKey) ? sha256(deviceKey) : null;
  try {
    const db = admin.firestore();
    if (deviceKeyHash) {
      const deviceRef = db.collection("deviceEntitlements").doc(deviceKeyHash);
      const deviceSnap = await deviceRef.get();
      if (deviceSnap.exists && deviceSnap.data().active && deviceSnap.data().telegramId) {
        const subscribed = await getMembership(deviceSnap.data().telegramId);
        if (!subscribed) {
          await deviceRef.delete().catch(() => {});
          return sendError(res, 403, "not_subscribed", "Подписка на канал «Наедине» не найдена.");
        }
        await deviceRef.set({ checkedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        return res.json({ ok: true, blocks: questions });
      }
    }
    const linked = await privateTelegramRef(user.uid).get();
    if (!linked.exists || !linked.data().telegramId) {
      await entitlementRef(user.uid).delete().catch(() => {});
      return sendError(res, 403, "telegram_not_linked", "Сначала подтвердите подписку через бота.");
    }
    const telegramId = linked.data().telegramId;
    const subscribed = await getMembership(telegramId);
    if (!subscribed) {
      await entitlementRef(user.uid).delete().catch(() => {});
      if (deviceKeyHash) await db.collection("deviceEntitlements").doc(deviceKeyHash).delete().catch(() => {});
      return sendError(res, 403, "not_subscribed", "Подписка на канал «Наедине» не найдена.");
    }
    await entitlementRef(user.uid).set({ active: true, channel: CHANNEL_ID, checkedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    if (deviceKeyHash) {
      await db.collection("deviceEntitlements").doc(deviceKeyHash).set({
        telegramId: String(telegramId), active: true, channel: CHANNEL_ID,
        checkedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }
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
