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
const SUCCESS_IMAGE_BASE64 = "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";
async function sendBotPhoto(chatId, caption, replyMarkup) {
  const form = new FormData();
  form.append("chat_id", String(chatId));
  form.append("caption", caption);
  if (replyMarkup) form.append("reply_markup", JSON.stringify(replyMarkup));
  form.append("photo", new Blob([Buffer.from(SUCCESS_IMAGE_BASE64, "base64")], { type: "image/jpeg" }), "naedine-after-subscription.jpg");
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
    /* Full access can be shared only with the authenticated second member
       of the same two-person room. Re-check the original subscriber live. */
    const roomSnap = await db.collection("rooms").where("members", "array-contains", user.uid).limit(5).get();
    let verifiedRoomPartner = null;
    for (const roomDoc of roomSnap.docs) {
      const members = Array.isArray(roomDoc.data().members) ? roomDoc.data().members : [];
      if (members.length !== 2 || !members.includes(user.uid)) continue;
      const partnerUid = members.find(uid => uid !== user.uid);
      if (!partnerUid) continue;
      const partnerEntSnap = await entitlementRef(partnerUid).get();
      if (!partnerEntSnap.exists || partnerEntSnap.data().active !== true) continue;
      const partnerTelegramSnap = await privateTelegramRef(partnerUid).get();
      const partnerTelegramId = partnerTelegramSnap.exists ? String(partnerTelegramSnap.data().telegramId || "") : "";
      if (!partnerTelegramId) continue;
      if (await getMembership(partnerTelegramId)) {
        verifiedRoomPartner = { uid: partnerUid, telegramId: partnerTelegramId, roomId: roomDoc.id };
        break;
      }
    }
    if (verifiedRoomPartner) {
      await entitlementRef(user.uid).set({
        active: true, channel: CHANNEL_ID,
        sharedFromRoom: verifiedRoomPartner.roomId,
        sharedFromUid: verifiedRoomPartner.uid,
        checkedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
      return res.json({ ok: true, access: "couple", blocks: questions });
    }
    /* A previous couple grant is revoked when no current subscribed member
       remains in the linked room. */
    const previousEntitlement = await entitlementRef(user.uid).get();
    if (previousEntitlement.exists && previousEntitlement.data().sharedFromRoom) {
      await entitlementRef(user.uid).delete().catch(() => {});
    }
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


const COUPLE_IDEAS = new Set([
  "phone-free-evening","cook-together","sunset-walk","dream-trip","first-date-replay",
  "home-spa","board-game-night","new-hobby","memory-album","breakfast-in-bed",
  "kindness-day","future-letter"
]);
function requireFirebaseReady(res) {
  if (!firebaseReady) {
    sendError(res, 503, "firebase_not_configured", "Сервис пары временно недоступен.");
    return false;
  }
  return true;
}
async function coupleContext(req, res) {
  const user = await firebaseUser(req, res);
  if (!user) return null;
  const roomCode = String(req.body && req.body.roomCode || "").trim().toUpperCase();
  if (!/^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){2}$/.test(roomCode)) {
    sendError(res, 400, "invalid_room", "Проверьте код комнаты.");
    return null;
  }
  try {
    const db = admin.firestore();
    const roomRef = db.collection("rooms").doc(roomCode);
    const roomSnap = await roomRef.get();
    if (!roomSnap.exists) {
      sendError(res, 404, "room_not_found", "Комната не найдена.");
      return null;
    }
    const room = roomSnap.data() || {};
    const members = Array.isArray(room.members) ? room.members.map(String) : [];
    if (!members.includes(user.uid)) {
      sendError(res, 403, "not_room_member", "У вас нет доступа к этой комнате.");
      return null;
    }
    if (members.length < 1 || members.length > 2) {
      sendError(res, 409, "invalid_room_members", "Состав комнаты некорректен.");
      return null;
    }
    return { db, user, roomRef, room, roomCode, members, partnerUid: members.find(uid => uid !== user.uid) || null };
  } catch (error) {
    console.error("Couple room lookup failed:", error.message);
    sendError(res, 503, "room_lookup_failed", "Не удалось загрузить комнату. Попробуйте ещё раз.");
    return null;
  }
}
function validCoupleDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || "")) && Number.isFinite(Date.parse(String(value) + "T00:00:00Z"));
}
async function addCoupleActivity(ctx, fields) {
  if (!ctx.partnerUid) return;
  const ref = ctx.roomRef.collection("activities").doc(crypto.randomUUID());
  await ref.set({
    toUid: ctx.partnerUid,
    fromUid: ctx.user.uid,
    type: String(fields.type || "activity"),
    title: String(fields.title || "Новое событие"),
    availableAt: Number(fields.availableAt || Date.now()),
    createdAt: Date.now(),
    readBy: []
  });
}
app.post("/api/couple/sync", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  try {
    const now = Date.now();
    const date = validCoupleDate(req.body && req.body.date) ? String(req.body.date) : new Date().toISOString().slice(0, 10);
    const name = String(req.body && req.body.name || "").trim().slice(0, 40);
    if (name) await ctx.roomRef.collection("profiles").doc(ctx.user.uid).set({ uid: ctx.user.uid, name, updatedAt: now }, { merge: true });
    const profileRefs = ctx.members.map(uid => ctx.roomRef.collection("profiles").doc(uid));
    const [profileSnaps, mineDailySnap, partnerDailySnap, ideasSnap, lettersSnap, activitiesSnap, doneSnap, memoriesSnap] = await Promise.all([
      Promise.all(profileRefs.map(ref => ref.get())),
      ctx.roomRef.collection("dailyAnswers").doc(date + "_" + ctx.user.uid).get(),
      ctx.partnerUid ? ctx.roomRef.collection("dailyAnswers").doc(date + "_" + ctx.partnerUid).get() : Promise.resolve(null),
      ctx.roomRef.collection("ideas").limit(40).get(),
      ctx.roomRef.collection("letters").orderBy("createdAt", "desc").limit(100).get(),
      ctx.roomRef.collection("activities").orderBy("createdAt", "desc").limit(60).get(),
      ctx.roomRef.collection("done").get(),
      ctx.roomRef.collection("coupleMemories").orderBy("createdAt", "desc").limit(100).get()
    ]);
    const [mineComplimentSnap, partnerComplimentSnap, datesSnap, guessSnap, truthSnap] = await Promise.all([
      ctx.roomRef.collection("compliments").doc(date + "_" + ctx.user.uid).get(),
      ctx.partnerUid ? ctx.roomRef.collection("compliments").doc(date + "_" + ctx.partnerUid).get() : Promise.resolve(null),
      ctx.roomRef.collection("coupleDates").orderBy("date", "asc").limit(100).get(),
      ctx.roomRef.collection("games").doc("guess").get(),
      ctx.roomRef.collection("games").doc("truth").get()
    ]);
    const profiles = {};
    profileSnaps.forEach((snap, i) => { profiles[ctx.members[i]] = snap.exists ? (snap.data().name || "") : ""; });
    const entitlementSnaps = ctx.members.length === 2
      ? await Promise.all(ctx.members.map(uid => entitlementRef(uid).get()))
      : [];
    const canReadProtectedHistory = ctx.members.length === 2 &&
      entitlementSnaps.every(snap => snap.exists && snap.data().active === true);
    const mineDaily = mineDailySnap.exists ? mineDailySnap.data() : null;
    const partnerDaily = partnerDailySnap && partnerDailySnap.exists ? partnerDailySnap.data() : null;
    const bothDaily = !!(mineDaily && partnerDaily);
    const ideas = ideasSnap.docs.map(doc => {
      const d = doc.data() || {};
      return { id: doc.id, doneBy: Array.isArray(d.doneBy) ? d.doneBy : [], wantBy: Array.isArray(d.wantBy) ? d.wantBy : [], updatedAt: Number(d.updatedAt || 0) };
    });
    const letters = lettersSnap.docs.map(doc => {
      const d = doc.data() || {};
      if (d.fromUid !== ctx.user.uid && d.toUid !== ctx.user.uid) return null;
      const received = d.toUid === ctx.user.uid;
      const available = Number(d.openAt || 0) <= now;
      return {
        id: doc.id, fromUid: d.fromUid, toUid: d.toUid, openAt: Number(d.openAt || 0),
        createdAt: Number(d.createdAt || 0), openedAt: Number(d.openedAt || 0),
        body: !received || available ? String(d.body || "") : "",
        locked: received && !available,
        senderName: profiles[d.fromUid] || ""
      };
    }).filter(Boolean).sort((a, b) => b.createdAt - a.createdAt);
    const notifications = activitiesSnap.docs.map(doc => {
      const d = doc.data() || {};
      if (d.toUid !== ctx.user.uid || Number(d.availableAt || 0) > now) return null;
      return {
        id: doc.id, type: String(d.type || "activity"), title: String(d.title || "Новое событие"),
        createdAt: Number(d.createdAt || 0), read: Array.isArray(d.readBy) && d.readBy.includes(ctx.user.uid)
      };
    }).filter(Boolean).sort((a, b) => b.createdAt - a.createdAt).slice(0, 30);
    const doneMap = {};
    doneSnap.docs.forEach(doc => {
      const d = doc.data() || {};
      const block = Number(d.block), uid = String(d.uid || "");
      if (block >= 1 && block <= 7 && ctx.members.includes(uid)) {
        (doneMap[block] || (doneMap[block] = {}))[uid] = Number(d.ts || 0);
      }
    });
    const history = [];
    for (let block = 1; block <= 7; block++) {
      const completed = doneMap[block] || {};
      if (block > 2 && !canReadProtectedHistory) continue;
      if (!ctx.partnerUid || !completed[ctx.user.uid] || !completed[ctx.partnerUid]) continue;
      const [mine, partner] = await Promise.all([
        ctx.roomRef.collection("answers").doc(block + "_" + ctx.user.uid).get(),
        ctx.roomRef.collection("answers").doc(block + "_" + ctx.partnerUid).get()
      ]);
      if (!mine.exists || !partner.exists) continue;
      history.push({
        block,
        completedAt: Math.max(completed[ctx.user.uid], completed[ctx.partnerUid]),
        answers: {
          [ctx.user.uid]: (mine.data() || {}).a || {},
          [ctx.partnerUid]: (partner.data() || {}).a || {}
        }
      });
    }
    history.sort((a, b) => a.completedAt - b.completedAt);
    return res.json({
      ok: true, roomCode: ctx.roomCode, uid: ctx.user.uid, partnerUid: ctx.partnerUid,
      members: ctx.members, profiles, roomCreatedAt: Number(ctx.room.created || 0),
      date, daily: {
        mine: mineDaily ? { answer: String(mineDaily.answer || ""), questionId: String(mineDaily.questionId || "") } : null,
        partnerAnswered: !!partnerDaily,
        bothAnswered: bothDaily,
        partnerAnswer: bothDaily ? String(partnerDaily.answer || "") : ""
      },
      ideas, letters, notifications, history,
      coupleMemories: memoriesSnap.docs.map(doc => {
        const d = doc.data() || {};
        return { id: doc.id, title: String(d.title || ""), date: String(d.date || ""),
          note: String(d.note || ""), favorite: !!d.favorite, createdBy: String(d.createdBy || ""),
          createdAt: Number(d.createdAt || 0) };
      }),
      compliment: {
        mine: mineComplimentSnap.exists ? String((mineComplimentSnap.data() || {}).text || "") : "",
        partnerSent: !!partnerComplimentSnap && partnerComplimentSnap.exists,
        bothSent: mineComplimentSnap.exists && !!partnerComplimentSnap && partnerComplimentSnap.exists,
        partnerText: mineComplimentSnap.exists && partnerComplimentSnap && partnerComplimentSnap.exists
          ? String((partnerComplimentSnap.data() || {}).text || "") : ""
      },
      coupleDates: datesSnap.docs.map(doc => {
        const d = doc.data() || {};
        return { id: doc.id, title: String(d.title || ""), date: String(d.date || ""),
          note: String(d.note || ""), createdBy: String(d.createdBy || ""), createdAt: Number(d.createdAt || 0) };
      }),
      games: {
        guess: guessSnap.exists ? {
          round: Number((guessSnap.data() || {}).round || 0),
          completed: !!(guessSnap.data() || {}).completed,
          rounds: Array.isArray((guessSnap.data() || {}).rounds) ? (guessSnap.data() || {}).rounds : [],
          answeredByMe: !!((guessSnap.data() || {}).answers || {})[ctx.user.uid],
          partnerAnswered: !!(ctx.partnerUid && ((guessSnap.data() || {}).answers || {})[ctx.partnerUid])
        } : null,
        truth: truthSnap.exists ? (truthSnap.data() || {}) : null
      }
    });
  } catch (error) {
    console.error("Couple sync failed:", error.message);
    return sendError(res, 503, "couple_sync_failed", "Не удалось обновить пространство пары.");
  }
});
app.post("/api/couple/daily", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const date = String(req.body && req.body.date || "");
  const questionId = String(req.body && req.body.questionId || "");
  const answer = String(req.body && req.body.answer || "").trim();
  if (!validCoupleDate(date) || !/^[a-z0-9_-]{1,40}$/i.test(questionId) || !answer || answer.length > 2000) {
    return sendError(res, 400, "invalid_daily_answer", "Напишите ответ длиной до 2000 символов.");
  }
  try {
    const ref = ctx.roomRef.collection("dailyAnswers").doc(date + "_" + ctx.user.uid);
    const existed = await ref.get();
    await ref.set({ uid: ctx.user.uid, date, questionId, answer, updatedAt: Date.now() }, { merge: true });
    if (!existed.exists) await addCoupleActivity(ctx, { type: "daily_answer", title: "Партнёр ответил на вопрос дня" });
    return res.json({ ok: true, saved: true });
  } catch (error) {
    console.error("Daily answer save failed:", error.message);
    return sendError(res, 503, "daily_save_failed", "Не удалось сохранить ответ. Попробуйте ещё раз.");
  }
});
app.post("/api/couple/idea/toggle", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const ideaId = String(req.body && req.body.ideaId || "");
  if (!COUPLE_IDEAS.has(ideaId)) return sendError(res, 400, "invalid_idea", "Такой идеи нет в списке.");
  try {
    const ref = ctx.roomRef.collection("ideas").doc(ideaId);
    const mode = String(req.body && req.body.mode || "done");
    if (!["done", "want"].includes(mode)) return sendError(res, 400, "invalid_idea_mode", "Неизвестное действие.");
    let completed = false;
    await ctx.db.runTransaction(async tx => {
      const snap = await tx.get(ref);
      const data = snap.exists ? snap.data() : {};
      const field = mode === "want" ? "wantBy" : "doneBy";
      const values = Array.isArray(data[field]) ? data[field].slice() : [];
      const had = values.includes(ctx.user.uid);
      const next = had ? values.filter(uid => uid !== ctx.user.uid) : values.concat(ctx.user.uid);
      completed = !had;
      tx.set(ref, { id: ideaId, [field]: next, updatedAt: Date.now(), updatedBy: ctx.user.uid }, { merge: true });
    });
    if (completed) await addCoupleActivity(ctx, { type: mode === "want" ? "idea_wanted" : "idea_completed", title: mode === "want" ? "Партнёр хочет попробовать идею для свидания" : "Партнёр отметил идею для свидания" });
    return res.json({ ok: true, completed });
  } catch (error) {
    console.error("Date idea update failed:", error.message);
    return sendError(res, 503, "idea_update_failed", "Не удалось обновить идею.");
  }
});
app.post("/api/couple/letter/send", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const body = String(req.body && req.body.body || "").trim();
  const openAt = Number(req.body && req.body.openAt || 0);
  const now = Date.now();
  if (!body || body.length > 3000 || !Number.isFinite(openAt) || openAt < now || openAt > now + 366 * 24 * 60 * 60 * 1000) {
    return sendError(res, 400, "invalid_letter", "Проверьте текст и дату открытия послания.");
  }
  try {
    const id = crypto.randomUUID();
    await ctx.roomRef.collection("letters").doc(id).set({
      fromUid: ctx.user.uid, toUid: ctx.partnerUid, body, openAt, createdAt: now, openedAt: 0
    });
    await addCoupleActivity(ctx, { type: "letter", title: "Для тебя приготовлено послание", availableAt: openAt });
    return res.json({ ok: true, letterId: id });
  } catch (error) {
    console.error("Secret letter save failed:", error.message);
    return sendError(res, 503, "letter_send_failed", "Не удалось отправить послание.");
  }
});
app.post("/api/couple/compliment/send", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  if (!ctx.partnerUid) return sendError(res, 409, "partner_not_joined", "Сначала пригласите вторую половинку в комнату.");
  const date = String(req.body && req.body.date || "");
  const text = String(req.body && req.body.text || "").trim();
  if (!validCoupleDate(date) || !text || text.length > 500) return sendError(res, 400, "invalid_compliment", "Напишите комплимент длиной до 500 символов.");
  try {
    const ref = ctx.roomRef.collection("compliments").doc(date + "_" + ctx.user.uid);
    const existed = await ref.get();
    await ref.set({ uid: ctx.user.uid, date, text, updatedAt: Date.now() }, { merge: true });
    if (!existed.exists) await addCoupleActivity(ctx, { type: "compliment", title: "Партнёр отправил комплимент дня" });
    return res.json({ ok: true });
  } catch (error) {
    console.error("Compliment save failed:", error.message);
    return sendError(res, 503, "compliment_save_failed", "Не удалось сохранить комплимент.");
  }
});
app.post("/api/couple/date/add", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const title = String(req.body && req.body.title || "").trim().slice(0, 80);
  const date = String(req.body && req.body.date || "");
  const note = String(req.body && req.body.note || "").trim().slice(0, 300);
  if (!title || !validCoupleDate(date)) return sendError(res, 400, "invalid_couple_date", "Укажите название и корректную дату.");
  try {
    const id = crypto.randomUUID();
    await ctx.roomRef.collection("coupleDates").doc(id).set({ title, date, note, createdBy: ctx.user.uid, createdAt: Date.now() });
    await addCoupleActivity(ctx, { type: "couple_date", title: "В календаре пары появилась новая дата" });
    return res.json({ ok: true, id });
  } catch (error) {
    console.error("Couple date save failed:", error.message);
    return sendError(res, 503, "couple_date_save_failed", "Не удалось добавить дату.");
  }
});
app.post("/api/couple/memory/add", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const title = String(req.body && req.body.title || "").trim().slice(0, 100);
  const date = String(req.body && req.body.date || "");
  const note = String(req.body && req.body.note || "").trim().slice(0, 1500);
  const favorite = req.body && req.body.favorite === true;
  if (!title || !validCoupleDate(date)) return sendError(res, 400, "invalid_couple_memory", "Укажите название и корректную дату воспоминания.");
  try {
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    await ctx.roomRef.collection("coupleMemories").doc(id).set({
      title, date, note, favorite, createdBy: ctx.user.uid, createdAt, updatedAt: createdAt
    });
    await addCoupleActivity(ctx, { type: "couple_memory", title: "В общей истории появилось новое воспоминание" });
    return res.json({ ok: true, id, saved: true });
  } catch (error) {
    console.error("Couple memory save failed:", error.message);
    return sendError(res, 503, "couple_memory_save_failed", "Не удалось сохранить воспоминание.");
  }
});

app.post("/api/couple/game/guess/start", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  if (!ctx.partnerUid) return sendError(res, 409, "partner_not_joined", "Для игры нужны оба участника комнаты.");
  try {
    const ref = ctx.roomRef.collection("games").doc("guess");
    let state;
    await ctx.db.runTransaction(async tx => {
      const snap = await tx.get(ref);
      const current = snap.exists ? snap.data() : null;
      if (!current || current.completed || req.body && req.body.restart === true) {
        state = { round: 0, answers: {}, rounds: [], completed: false, startedAt: Date.now(), updatedAt: Date.now() };
        tx.set(ref, state);
      } else state = current;
    });
    return res.json({ ok: true, state: { round: Number(state.round || 0), completed: !!state.completed, rounds: Array.isArray(state.rounds) ? state.rounds : [], answeredByMe: !!((state.answers || {})[ctx.user.uid]), partnerAnswered: !!(ctx.partnerUid && (state.answers || {})[ctx.partnerUid]) } });
  } catch (error) {
    console.error("Guess game start failed:", error.message);
    return sendError(res, 503, "guess_start_failed", "Не удалось открыть игру.");
  }
});
app.post("/api/couple/game/guess/answer", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const round = Number(req.body && req.body.round);
  const choice = String(req.body && req.body.choice || "");
  if (!Number.isInteger(round) || round < 0 || round > 9 || !["0", "1"].includes(choice)) return sendError(res, 400, "invalid_guess_answer", "Выберите один из двух вариантов.");
  try {
    const ref = ctx.roomRef.collection("games").doc("guess");
    let state;
    await ctx.db.runTransaction(async tx => {
      const snap = await tx.get(ref);
      if (!snap.exists) throw new Error("game_not_started");
      const current = snap.data() || {};
      if (current.completed || Number(current.round) !== round) throw new Error("round_closed");
      const answers = Object.assign({}, current.answers || {});
      if (answers[ctx.user.uid] !== undefined) throw new Error("already_answered");
      answers[ctx.user.uid] = choice;
      const next = Object.assign({}, current, { answers, updatedAt: Date.now() });
      if (ctx.partnerUid && answers[ctx.partnerUid] !== undefined) {
        const rounds = Array.isArray(current.rounds) ? current.rounds.slice() : [];
        rounds.push({ round, answers: { [ctx.user.uid]: answers[ctx.user.uid], [ctx.partnerUid]: answers[ctx.partnerUid] } });
        next.rounds = rounds;
        next.round = round + 1;
        next.answers = {};
        next.completed = next.round >= 10;
        if (next.completed) next.completedAt = Date.now();
      }
      tx.set(ref, next, { merge: true });
      state = next;
    });
    return res.json({ ok: true, state: { round: Number(state.round || 0), completed: !!state.completed, rounds: Array.isArray(state.rounds) ? state.rounds : [], answeredByMe: !!((state.answers || {})[ctx.user.uid]), partnerAnswered: !!(ctx.partnerUid && (state.answers || {})[ctx.partnerUid]) } });
  } catch (error) {
    const code = error.message === "already_answered" ? "already_answered" : error.message === "round_closed" ? "round_closed" : "guess_answer_failed";
    return sendError(res, code === "guess_answer_failed" ? 503 : 409, code, "Не удалось сохранить ответ. Обновите игру.");
  }
});
app.post("/api/couple/game/truth/choose", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const category = String(req.body && req.body.category || "");
  const kind = String(req.body && req.body.kind || "");
  const prompt = String(req.body && req.body.prompt || "").trim().slice(0, 500);
  if (!["romance", "humor", "honesty", "adult"].includes(category) || !["truth", "action"].includes(kind) || !prompt) return sendError(res, 400, "invalid_truth_prompt", "Выберите категорию и задание.");
  try {
    const ref = ctx.roomRef.collection("games").doc("truth");
    let state;
    await ctx.db.runTransaction(async tx => {
      const snap = await tx.get(ref);
      const current = snap.exists ? snap.data() : {};
      const turnUid = current.currentTurnUid || ctx.members[0];
      if (turnUid !== ctx.user.uid) throw new Error("not_your_turn");
      if (current.pending) throw new Error("turn_pending");
      state = Object.assign({}, current, {
        currentTurnUid: turnUid, turnNo: Number(current.turnNo || 0) + 1,
        pending: { category, kind, prompt, byUid: ctx.user.uid, createdAt: Date.now() },
        history: Array.isArray(current.history) ? current.history : [], updatedAt: Date.now()
      });
      tx.set(ref, state, { merge: true });
    });
    return res.json({ ok: true, state });
  } catch (error) {
    const conflict = error.message === "not_your_turn" || error.message === "turn_pending";
    return sendError(res, conflict ? 409 : 503, error.message || "truth_choose_failed", "Сейчас нельзя начать этот ход.");
  }
});
app.post("/api/couple/game/truth/complete", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  try {
    const ref = ctx.roomRef.collection("games").doc("truth");
    let state;
    await ctx.db.runTransaction(async tx => {
      const snap = await tx.get(ref);
      if (!snap.exists) throw new Error("no_active_turn");
      const current = snap.data() || {};
      if (!current.pending || current.pending.byUid !== ctx.user.uid || current.currentTurnUid !== ctx.user.uid) throw new Error("not_your_turn");
      const history = Array.isArray(current.history) ? current.history.slice(-49) : [];
      history.push(Object.assign({}, current.pending, { completedAt: Date.now() }));
      state = Object.assign({}, current, { history, pending: null, currentTurnUid: ctx.partnerUid || ctx.user.uid, updatedAt: Date.now() });
      tx.set(ref, state, { merge: true });
    });
    return res.json({ ok: true, state });
  } catch (error) {
    const conflict = error.message === "not_your_turn" || error.message === "no_active_turn";
    return sendError(res, conflict ? 409 : 503, error.message || "truth_complete_failed", "Не удалось завершить ход.");
  }
});

app.post("/api/couple/notifications/read", async (req, res) => {
  if (!requireFirebaseReady(res)) return;
  const ctx = await coupleContext(req, res);
  if (!ctx) return;
  const activityId = String(req.body && req.body.activityId || "");
  if (!/^[A-Za-z0-9_-]{10,80}$/.test(activityId)) return sendError(res, 400, "invalid_activity", "Уведомление не найдено.");
  try {
    const ref = ctx.roomRef.collection("activities").doc(activityId);
    const snap = await ref.get();
    if (!snap.exists || snap.data().toUid !== ctx.user.uid) return sendError(res, 404, "activity_not_found", "Уведомление не найдено.");
    await ref.update({ readBy: admin.firestore.FieldValue.arrayUnion(ctx.user.uid) });
    return res.json({ ok: true });
  } catch (error) {
    console.error("Notification read failed:", error.message);
    return sendError(res, 503, "notification_update_failed", "Не удалось отметить уведомление.");
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
