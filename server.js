// ===== Мини-мессенджер: СЕРВЕР =====
// Сервер — это "почтальон": проверяет, кто ты, принимает сообщения и раздаёт их всем.

const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto"); // встроен в Node.js, устанавливать не нужно
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Код приглашения: без него нельзя создать аккаунт.
// На Render задай его в Environment -> ROOM_CODE.
const ROOM_CODE = process.env.ROOM_CODE || "karim123";
const MAX_ACCOUNTS = 10;   // максимум аккаунтов
const HISTORY_SIZE = 100;  // сколько последних сообщений помнит сервер
const DATA_FILE = path.join(__dirname, "users.json");

// ================== АККАУНТЫ ==================
// users = { "77011234567": { uid, name, salt, hash, tokens: [] } }
let users = {};
try {
  users = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
} catch {
  users = {}; // файла ещё нет — начинаем с нуля
}

function saveUsers() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

// "+7 (701) 123-45-67" и "87011234567" -> "77011234567"
function normalizePhone(raw) {
  let digits = String(raw || "").replace(/\D/g, ""); // оставляем только цифры
  if (digits.length === 11 && digits.startsWith("8")) digits = "7" + digits.slice(1);
  return digits.length >= 10 && digits.length <= 15 ? digits : null;
}

// Пароль НИКОГДА не хранится как есть. Храним только его "отпечаток" (хэш).
// salt — случайная добавка, чтобы одинаковые пароли давали разные отпечатки.
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function checkPassword(user, password) {
  const attempt = Buffer.from(hashPassword(password, user.salt), "hex");
  return crypto.timingSafeEqual(attempt, Buffer.from(user.hash, "hex"));
}

// Токен — длинный случайный "пропуск". Браузер хранит его,
// чтобы не вводить пароль при каждом открытии сайта.
function newToken(user) {
  const token = crypto.randomBytes(24).toString("hex");
  user.tokens = [...(user.tokens || []), token].slice(-5); // максимум 5 устройств
  saveUsers();
  return token;
}

function findByToken(token) {
  if (!token) return null;
  return Object.values(users).find((u) => (u.tokens || []).includes(token)) || null;
}

// ================== ЧАТ ==================
const history = [];       // последние сообщения
const online = new Map(); // socket.id -> user

app.use(express.static(path.join(__dirname, "public")));

function sendOnlineList() {
  const names = [...new Set([...online.values()].map((u) => u.name))];
  io.emit("online", names);
}

function isOnline(user) {
  return [...online.values()].some((u) => u.uid === user.uid);
}

io.on("connection", (socket) => {
  let fails = 0; // защита от подбора пароля

  function fail(text) {
    fails++;
    socket.emit("auth-error", text);
    if (fails >= 5) socket.disconnect(true); // 5 ошибок — отключаем
  }

  function enter(user, token) {
    if (online.has(socket.id)) return;
    const wasOnline = isOnline(user);
    online.set(socket.id, user);
    // Номер телефона другим НЕ отправляем — только имя и uid
    socket.emit("joined", { me: { uid: user.uid, name: user.name }, token, history });
    if (!wasOnline) io.emit("system", `${user.name} в сети`);
    sendOnlineList();
  }

  // 1. Регистрация
  socket.on("register", ({ name, phone, password, code } = {}) => {
    name = String(name || "").trim().slice(0, 20);
    phone = normalizePhone(phone);
    password = String(password || "");

    if (code !== ROOM_CODE) return fail("Неверный код приглашения");
    if (!name) return fail("Введи имя");
    if (!phone) return fail("Неверный номер телефона");
    if (password.length < 6) return fail("Пароль: минимум 6 символов");
    if (users[phone]) return fail("Этот номер уже зарегистрирован — войди");
    if (Object.keys(users).length >= MAX_ACCOUNTS) return fail("Мест нет: уже 10 аккаунтов");

    const salt = crypto.randomBytes(16).toString("hex");
    const user = { uid: crypto.randomUUID(), name, salt, hash: hashPassword(password, salt), tokens: [] };
    users[phone] = user;
    enter(user, newToken(user)); // newToken ещё и сохраняет файл
  });

  // 2. Вход по номеру и паролю
  socket.on("login", ({ phone, password } = {}) => {
    const user = users[normalizePhone(phone)];
    // Одинаковая ошибка, чтобы нельзя было узнать, какие номера зарегистрированы
    if (!user || !checkPassword(user, String(password || ""))) {
      return fail("Неверный номер или пароль");
    }
    enter(user, newToken(user));
  });

  // 3. Автовход по сохранённому токену
  socket.on("resume", ({ token } = {}) => {
    const user = findByToken(token);
    if (!user) return socket.emit("resume-failed");
    enter(user, token);
  });

  // 4. Выход из аккаунта на этом устройстве
  socket.on("logout", ({ token } = {}) => {
    const user = online.get(socket.id);
    if (!user) return;
    user.tokens = (user.tokens || []).filter((t) => t !== token);
    saveUsers();
    online.delete(socket.id);
    if (!isOnline(user)) io.emit("system", `${user.name} вышел`);
    sendOnlineList();
  });

  // 5. Новое сообщение
  socket.on("message", (text) => {
    const user = online.get(socket.id);
    if (!user) return; // не вошёл — не пишет
    text = String(text || "").trim().slice(0, 1000);
    if (!text) return;

    const msg = { id: crypto.randomUUID(), uid: user.uid, name: user.name, text, time: Date.now() };
    history.push(msg);
    if (history.length > HISTORY_SIZE) history.shift();

    io.emit("message", msg); // рассылаем ВСЕМ
  });

  // 6. "Печатает..."
  socket.on("typing", () => {
    const user = online.get(socket.id);
    if (user) socket.broadcast.emit("typing", user.name);
  });

  // 7. Вкладку закрыли
  socket.on("disconnect", () => {
    const user = online.get(socket.id);
    if (!user) return;
    online.delete(socket.id);
    if (!isOnline(user)) io.emit("system", `${user.name} вышел`);
    sendOnlineList();
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Мессенджер работает на порту ${PORT}`));
