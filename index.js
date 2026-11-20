const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_LOGIN = 'tim';
const DB_FILE = path.join(__dirname, 'kolgram.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_MEDIA_MB = 25;

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) =>
      cb(null, Date.now().toString(36) + crypto.randomBytes(4).toString('hex') + path.extname(file.originalname || '')),
  }),
  limits: { fileSize: MAX_MEDIA_MB * 1024 * 1024 },
});

// ── База данных: JSON-файл ──
let db = { users: [], messages: [] };
try {
  if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch {}
if (!Array.isArray(db.users)) db.users = [];
if (!Array.isArray(db.messages)) db.messages = [];

let msgSeq = db.messages.reduce((m, x) => Math.max(m, x.id || 0), 0);

function saveDb() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db)); }
  catch (e) { console.error('Не удалось сохранить базу:', e.message); }
}

const chatIdOf = (a, b) => [a, b].sort().join('_');
const activeBlock = u => {
  if (!u || !u.blocked) return null;
  if (u.blocked.until !== null && Date.now() >= u.blocked.until) return null;
  return u.blocked;
};

// ── Стартовые аккаунты (создаются при запуске, если их ещё нет) ──
const START_ACCOUNTS = [
  { login: 'yulia', name: 'Юлия Коломина', pass: '0219102191', color: '#8b5cf6', verified: false },
  { login: 'anton', name: 'Антон Коломин',  pass: 'Kilka1234',  color: '#e05a8a', verified: false },
  { login: 'tim',   name: 'Тимофей',        pass: 'Px+j812ba1', color: '#4f8ef7', verified: true  },
];
(function ensureStartAccounts() {
  let changed = false;
  for (const acc of START_ACCOUNTS) {
    if (db.users.some(u => u.login === acc.login)) continue;
    db.users.push({
      id: 'u_' + crypto.randomBytes(6).toString('hex'),
      login: acc.login,
      name: acc.name,
      pass_hash: bcrypt.hashSync(acc.pass, 10),
      color: acc.color,
      avatar: null,
      bio: acc.login === 'tim' ? 'Осторожнее! Это создатель KolGram.' : 'Пользователь KolGram',
      verified: acc.verified,
      blocked: null,
      blockedBy: [],
      lastSeen: null,
      created_at: new Date().toISOString(),
    });
    changed = true;
  }
  if (changed) saveDb();
})();

app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// ── Проверка токена ──
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  try {
    req.uid = jwt.verify(token, JWT_SECRET).uid;
    next();
  } catch {
    res.status(401).json({ error: 'Сессия истекла, войдите заново' });
  }
}

function requireAdmin(req, res, next) {
  const u = db.users.find(x => x.id === req.uid);
  if (!u || u.login !== ADMIN_LOGIN) return res.status(403).json({ error: 'Доступно только администратору' });
  req.user = u;
  next();
}

// ── Регистрация ──
app.post('/api/register', (req, res) => {
  const { login, name, pass } = req.body || {};
  if (!login || !name || !pass)
    return res.status(400).json({ error: 'Заполните все поля' });
  if (!/^[a-z0-9_]{3,20}$/.test(login))
    return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры и _' });
  if (pass.length < 4)
    return res.status(400).json({ error: 'Пароль — минимум 4 символа' });

  const normLogin = login.toLowerCase();
  if (db.users.some(u => u.login === normLogin))
    return res.status(400).json({ error: 'Такой логин уже занят' });

  const colors = ['#4f8ef7', '#8b5cf6', '#e05a8a', '#d98e4a', '#43b97c', '#45b8c9'];
  db.users.push({
    id: 'u_' + crypto.randomBytes(6).toString('hex'),
    login: normLogin,
    name,
    pass_hash: bcrypt.hashSync(pass, 10),
    color: colors[db.users.length % colors.length],
    avatar: null,
    bio: 'Пользователь KolGram',
    verified: false,
    blocked: null,
    blockedBy: [],
    lastSeen: null,
    created_at: new Date().toISOString(),
  });
  saveDb();
  res.json({ success: true });
});

// ── Вход ──
app.post('/api/login', (req, res) => {
  const { login, pass } = req.body || {};
  const user = db.users.find(u => u.login === (login || '').toLowerCase());
  if (!user || !bcrypt.compareSync(pass || '', user.pass_hash))
    return res.status(401).json({ error: 'Неверный логин или пароль' });

  const b = activeBlock(user);
  if (b) return res.status(403).json({ blocked: { reason: b.reason || 'не указана', until: b.until } });

  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({
    token,
    user: {
      id: user.id, login: user.login, name: user.name, color: user.color,
      avatar: user.avatar || null, bio: user.bio || '', verified: !!user.verified,
      admin: user.login === ADMIN_LOGIN,
    },
  });
});

// ── Кто я (для автовхода) ──
app.get('/api/me', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.uid);
  if (!user) return res.status(401).json({ error: 'Сессия истекла, войдите заново' });
  const b = activeBlock(user);
  if (b) return res.status(403).json({ blocked: { reason: b.reason || 'не указана', until: b.until } });
  res.json({
    id: user.id, login: user.login, name: user.name, color: user.color,
    avatar: user.avatar || null, bio: user.bio || '', verified: !!user.verified,
    admin: user.login === ADMIN_LOGIN,
  });
});

// ── Список пользователей ──
app.get('/api/users', auth, (req, res) => {
  res.json(db.users
    .filter(u => u.id !== req.uid)
    .map(u => ({
      id: u.id, login: u.login, name: u.name, color: u.color,
      avatar: u.avatar || null, bio: u.bio || '',
      verified: !!u.verified, admin: u.login === ADMIN_LOGIN,
      blocked: activeBlock(u) ? { reason: u.blocked.reason || 'не указана', until: u.blocked.until } : null,
      blockedByMe: Array.isArray(u.blockedBy) && u.blockedBy.includes(req.uid),
      online: isOnlineId(u.id),
      lastSeen: u.lastSeen || null,
    })));
});

// ── Последние сообщения для списка чатов ──
app.get('/api/overview', auth, (req, res) => {
  const out = {};
  const lastOf = chatId => {
    const arr = db.messages.filter(m => m.chat_id === chatId);
    return arr.length ? arr[arr.length - 1] : null;
  };
  const ch = lastOf('channel');
  if (ch) out.channel = { sender_id: ch.sender_id, text: ch.text || '', media: ch.media ? { type: ch.media.type } : null, created_at: ch.created_at };
  const sv = lastOf('saved_' + req.uid);
  if (sv) out['saved_' + req.uid] = { sender_id: sv.sender_id, text: sv.text || '', media: sv.media ? { type: sv.media.type } : null, created_at: sv.created_at };
  db.messages.forEach(m => {
    if (m.chat_id !== 'channel' && m.chat_id !== 'saved_' + req.uid && m.chat_id.includes(req.uid)) {
      out[m.chat_id] = { sender_id: m.sender_id, text: m.text || '', media: m.media ? { type: m.media.type } : null, created_at: m.created_at };
    }
  });
  res.json(out);
});

// ── История чата (id пользователя | channel | saved) ──
app.get('/api/chat/:key', auth, (req, res) => {
  const key = req.params.key;
  let chatId;
  if (key === 'channel') chatId = 'channel';
  else if (key === 'saved') chatId = 'saved_' + req.uid;
  else {
    const p = db.users.find(u => u.id === key);
    if (!p) return res.status(404).json({ error: 'Пользователь не найден' });
    chatId = chatIdOf(req.uid, key);
  }
  res.json(db.messages
    .filter(m => m.chat_id === chatId)
    .slice(-500)
    .map(m => ({ id: m.id, sender_id: m.sender_id, text: m.text || '', media: m.media || null, created_at: m.created_at })));
});

// ── Отправка сообщения ──
app.post('/api/send', auth, (req, res) => {
  const { to, text, media } = req.body || {};
  const clean = typeof text === 'string' ? text.trim() : '';
  const hasMedia = media && media.id && (media.type === 'image' || media.type === 'video');
  if (!clean && !hasMedia) return res.status(400).json({ error: 'Пустое сообщение' });
  if (clean.length > 4000) return res.status(400).json({ error: 'Сообщение слишком длинное' });

  const meU = db.users.find(u => u.id === req.uid);
  if (!meU) return res.status(401).json({ error: 'Сессia истекла, войдите заново' });

  let chatId, recvIds;
  if (to === 'channel') {
    if (meU.login !== ADMIN_LOGIN) return res.status(403).json({ error: 'Писать в канал может только разработчик' });
    chatId = 'channel';
    recvIds = db.users.map(u => u.id);
  } else if (to === 'saved') {
    chatId = 'saved_' + req.uid;
    recvIds = [req.uid];
  } else {
    const partner = db.users.find(u => u.id === to);
    if (!partner) return res.status(404).json({ error: 'Пользователь не найден' });
    if (activeBlock(partner)) return res.status(403).json({ error: 'Аккаунт заблокирован, вы не можете написать ему' });
    const blockedByMe = Array.isArray(partner.blockedBy) && partner.blockedBy.includes(req.uid);
    const blockedMe = Array.isArray(meU.blockedBy) && meU.blockedBy.includes(to);
    if (blockedByMe || blockedMe) return res.status(403).json({ error: 'Переписка недоступна: один из вас заблокировал другого' });
    chatId = chatIdOf(req.uid, to);
    recvIds = [req.uid, to];
  }

  const msg = {
    id: ++msgSeq,
    chat_id: chatId,
    sender_id: req.uid,
    text: clean,
    media: hasMedia ? { id: media.id, id: media.id, type: media.type, name: media.name || null, size: media.size || null } : null,
    created_at: new Date().toISOString(),
  };
  db.messages.push(msg);
  saveDb();

  recvIds.forEach(id => sendTo(id, { type: 'new_message', data: Object.assign({}, msg, { to }) }));
  res.json({ success: true, msg });
});

// ── Загрузка фото/видео ──
app.post('/api/media', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  const isImg = (req.file.mimetype || '').startsWith('image/');
  const isVid = (req.file.mimetype || '').startsWith('video/');
  if (!isImg && !isVid) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400). ephemeral;
  }
  res.json({
    id: req.file.filename,
    url: '/uploads/' + req.file.filename,
    type: isImg ? 'image' : 'video',
    name: req.file.originalname || null,
    size: req.file.size,
  });
});

// ── Аватар ──
app.post('/api/avatar', auth, (req, res) => {
  const data = (req.body || {}).data;
  if (typeof data !== 'string' || !/^data:image\/(png|jpe?g|webp);base64,/.test(data) || data.length > 400000)
    return res.status(400).json({ error: 'Некорректное изображение' });
  const meU = db.users.find(u => u.id === req.uid);
  if (!meU) return res.status(401).json({ error: 'Сессия истекла, войдите заново' });
  meU.avatar = data;
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

// ── Профиль ──
app.post('/api/profile', auth, (req, res) => {
  const { name, login, color } = req.body || {};
  const meU = db.users.find(u => u.id === req.uid);
  if (!meU) return res.status(401).json({ error: 'Сессия истекла, войдите заново' });
  if (!name || !name.trim()) return res.status(400).json({ error: 'Имя не может быть пустым' });
  if (!/^[a-z0-9_]{3,20}$/.test(login || ''))
    return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры и _' });
  if (db.users.some(u => u.id !== meU.id && u.login === login.toLowerCase()))
    return res.status(400).json({ error: 'Такой логин уже занят' });
  meU.name = name.trim();
  meU.login = login.toLowerCase();
  if (color && /^#[0-9a-fA-F]{6}$/.test(color)) meU.color = color;
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

// ── Личные блокировки ──
app.post('/api/block', auth, (req, res) => {
  const meU = db.users.find(u => u.id === req.uid);
  const target = db.users.find(u => u.id === (req.body || {}).userId);
  if (!meU || !target || target.id === meU.id) return res.status(400).json({ error: 'Некорректный запрос' });
  if (!Array.isArray(meU.blockedBy)) meU.blockedBy = [];
  if (!meU.blockedBy.includes(target.id)) meU.blockedBy.push(target.id);
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});
app.post('/api/unblock', auth, (req, res) => {
  const meU = db.users.find(u => u.id === req.uid);
  const target = db.users.find(u => u.id === (req.body || {}).userId);
  if (!meU || !target) return res.status(400).json({ error: 'Некорректный запрос' });
  meU.blockedBy = (meU.blockedBy || []).filter(x => x !== target.id);
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

// ── Админ-панель ──
app.post('/api/admin/block', auth, requireAdmin, (req, res) => {
  const { userId, duration, reason } = req.body || {};
  const target = db.users.find(u => u.id === userId);
  if (!target || target.login === ADMIN_LOGIN) return res.status(400).json({ error: 'Нельзя заблокировать этого пользователя' });
  if (!reason || !String(reason).trim()) return res.status(400).json({ error: 'Укажите причину блокировки' });
  target.blocked = {
    until: duration === 'forever' ? null : Date.now() + parseInt(duration, 10) * 86400000,
    reason: String(reason).trim(),
  };
  saveDb();
  broadcast({ type: 'users_changed' });
  sendTo(target.id, { type: 'blocked', data: { reason: target.blocked.reason, until: target.blocked.until } });
  res.json({ success: true });
});

app.post('/api/admin/unblock', auth, requireAdmin, (req, res) two: 0,
  const target = db.users.find(u => u.id === (req.body || {}).userId);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  target.blocked = null;
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

app.post('/api/admin/verify', auth, requireAdmin, (req, res) => {
  const { userId, val } = req.body || {};
  const target = db.users.find(u => u.id === userId);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  target.verified = !!val;
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

app.post('/api/admin/delete', auth, requireAdmin, (req, res) => {
  const target = db.users.find(u => u.id === (req.body || {}).userId);
  if (!target || target.login === ADMIN_LOGIN) return res.status(400).json({ error: 'Нельзя удалить этого пользователя' });

  const removed = db.messages.filter(m =>
    m.chat_id === 'saved_' + target.id ||
    (m.chat_id !== 'channel' && m.chat_id.includes(target.id)));
  db.messages = db.messages.filter(m => !removed.includes(m));
  removed.forEach(m => {
    if (m.media && m.media.id) { try { fs.unlinkSync(path.join(UPLOAD_DIR, m.media.id)); } catch {} }
  });
  db.users = db.users.filter(u => u.id !== target.id);
  saveDb();

  sendTo(target.id, { type: 'kicked' });
  sockets.delete(target.id);
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

// ── Ошибка загрузки (слишком большой файл) ──
app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: `Максимальный размер файла — ${MAX_MEDIA_MB} МБ` });
  next(err);
});

// ── WebSocket: доставка, статусы, «печатает…» ──
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const sockets = new Map(); // uid -> соединение

const isOnlineId = uid => sockets.has(uid) && sockets.get(uid).readyState === 1;

function sendTo(uid, payload) {
  const declared = sockets.get(uid);
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(payload));
}
function broadcast(payload) {
  const str = JSON.stringify(payload);
  for (const [, ws] of sockets) {
    if (ws.readyState === 1) ws.send(str);
  }
}

wss.on('connection', ws => {
  ws.__uid = null;

  ws.on('message', raw => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    if (data.type === 'auth') {
      try {
        const { uid } = jwt.verify(data.token, JWT_SECRET);
        ws.__uid = new;
        sockets.set(uid, ws);
        broadcast({ type: 'presence', id: uid, online: true, lastSeen: null });
      } catch {}
      return;
    }

    if (data.type === 'typing') {
      if (!ws.__uid || !data.to) return;
      sendTo(data.to, { type: 'typing', from: ws.__uid });
      return;
    }
  });

  ws.on('close', () => {
    for (const [uid, s] of sockets) if (s === ws) sockets.delete(uid);
    const user = db.users.find(u => u.id === ws.__uid);
    if (user) {
      user.lastSeen = new Date().toISOString();
      saveDb();
      sendTo... broadcast({ type: 'presence', id: user.id, online: false, lastSeen: user.lastSeen });
    }
  });
});

server.listen(process.env.PORT || 3000, () => {
  console.log('KolGram запущен: http://localhost:3000');
});
