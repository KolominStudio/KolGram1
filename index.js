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

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) =>
      cb(null, Date.now().toString(36) + crypto.randomBytes(4).toString('hex') + path.extname(file.originalname || '')),
  }),
  limits: { fileSize: MAX_MEDIA_MB * 1024 * 1024 },
});

let db = { users: [], messages: [], groups: [], channels: [] };
try {
  if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch (e) { console.error('Не удалось прочитать базу:', e.message); }
['users', 'messages', 'groups', 'channels'].forEach(k => { if (!Array.isArray(db[k])) db[k] = []; });

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

const sockets = new Map();
function isOnlineId(uid) { const ws = sockets.get(uid); return !!ws && ws.readyState === 1; }
function sendTo(uid, payload) {
  const ws = sockets.get(uid);
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(payload));
}
function broadcast(payload) {
  const s = JSON.stringify(payload);
  for (const [, ws] of sockets) { if (ws.readyState === 1) ws.send(s); }
}

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
    console.log('Создан стартовый аккаунт:', acc.login);
    changed = true;
  }
  if (changed) saveDb();
})();

app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

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

function chatContext(meUid, to) {
  if (to === 'channel') return { chatId: 'channel', recvIds: db.users.map(u => u.id), isChannel: true };
  if (to === 'saved') return { chatId: 'saved_' + meUid, recvIds: [meUid] };
  if (to.startsWith('g_')) {
    const g = db.groups.find(x => x.id === to);
    if (!g || !g.members.includes(meUid)) return { error: 'Группа не найдена или вы не участник' };
    return { chatId: g.id, recvIds: g.members.slice(), group: g };
  }
  if (to.startsWith('ch_')) {
    const c = db.channels.find(x => x.id === to);
    if (!c) return { error: 'Канал не найден' };
    return { chatId: c.id, recvIds: db.users.map(u => u.id), channel: c };
  }
  const partner = db.users.find(u => u.id === to);
  if (!partner) return { error: 'Пользователь не найден' };
  if (activeBlock(partner)) return { error: 'Аккаунт заблокирован, вы не можете написать ему' };
  const meU = db.users.find(u => u.id === meUid);
  const blockedByMe = Array.isArray(partner.blockedBy) && partner.blockedBy.includes(meUid);
  const blockedMe = Array.isArray(meU.blockedBy) && meU.blockedBy.includes(to);
  if (blockedByMe || blockedMe) return { error: 'Переписка недоступна: один из вас заблокировал другого' };
  return { chatId: chatIdOf(meUid, to), recvIds: [meUid, to], partner };
}

function participantsOf(chatId, exceptUid) {
  if (chatId === 'channel' || chatId.startsWith('ch_'))
    return db.users.map(u => u.id).filter(x => x !== exceptUid);
  if (chatId.startsWith('saved_')) return [];
  const g = db.groups.find(x => x.id === chatId);
  if (g) return g.members.filter(x => x !== exceptUid);
  for (let i = 0; i < db.users.length; i++) {
    for (let j = i + 1; j < db.users.length; j++) {
      if (chatIdOf(db.users[i].id, db.users[j].id) === chatId)
        return [db.users[i].id, db.users[j].id].filter(x => x !== exceptUid);
    }
  }
  return [];
}

app.post('/api/register', (req, res) => {
  const { login, name, pass } = req.body || {};
  if (!login || !name || !pass) return res.status(400).json({ error: 'Заполните все поля' });
  if (!/^[a-z0-9_]{3,20}$/.test(login)) return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры и _' });
  if (pass.length < 4) return res.status(400).json({ error: 'Пароль — минимум 4 символа' });

  const normLogin = login.toLowerCase();
  if (db.users.some(u => u.login === normLogin)) return res.status(400).json({ error: 'Такой логин уже занят' });

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

app.get('/api/chats', auth, (req, res) => {
  res.json({
    groups: db.groups
      .filter(g => g.members.includes(req.uid))
      .map(g => ({ id: g.id, name: g.name, owner_id: g.owner_id, members: g.members })),
    channels: db.channels
      .map(c => ({ id: c.id, name: c.name, owner_id: c.owner_id, subscribed: (c.subscribers || []).includes(req.uid) })),
  });
});

function lastMsgMeta(chatId) {
  const arr = db.messages.filter(m => m.chat_id === chatId);
  if (!arr.length) return null;
  const m = arr[arr.length - 1];
  return { sender_id: m.sender_id, text: m.text || '', media: m.media ? { type: m.media.type } : null, created_at: m.created_at };
}

app.get('/api/overview', auth, (req, res) => {
  const out = {};
  const ch = lastMsgMeta('channel');
  if (ch) out.channel = ch;
  const sv = lastMsgMeta('saved_' + req.uid);
  if (sv) out['saved_' + req.uid] = sv;
  db.groups.filter(g => g.members.includes(req.uid)).forEach(g => {
    const m = lastMsgMeta(g.id);
    if (m) out[g.id] = m;
  });
  db.channels.forEach(c => {
    const m = lastMsgMeta(c.id);
    if (m) out[c.id] = m;
  });
  db.messages.forEach(m => {
    if (m.chat_id !== 'channel' && m.chat_id !== 'saved_' + req.uid &&
        !m.chat_id.startsWith('g_') && !m.chat_id.startsWith('ch_') && m.chat_id.includes(req.uid)) {
      out[m.chat_id] = { sender_id: m.sender_id, text: m.text || '', media: m.media ? { type: m.media.type } : null, created_at: m.created_at };
    }
  });
  res.json(out);
});

app.get('/api/chat/:key', auth, (req, res) => {
  const key = req.params.key;
  if (key === 'channel') {
    return res.json(db.messages.filter(m => m.chat_id === 'channel').slice(-500)
      .map(m => ({ id: m.id, sender_id: m.sender_id, text: m.text || '', media: m.media || null, deleted: !!m.deleted, created_at: m.created_at, read_by: m.read_by || [] })));
  }
  if (key === 'saved') {
    return res.json(db.messages.filter(m => m.chat_id === 'saved_' + req.uid).slice(-500)
      .map(m => ({ id: m.id, sender_id: m.sender_id, text: m.text || '', media: m.media || null, deleted: !!m.deleted, created_at: m.created_at })));
  }
  if (key.startsWith('g_')) {
    const g = db.groups.find(x => x.id === key);
    if (!g || !g.members.includes(req.uid)) return res.status(404).json({ error: 'Группа не найдена' });
    return res.json(db.messages.filter(m => m.chat_id === key).slice(-500)
      .map(m => ({ id: m.id, sender_id: m.sender_id, text: m.text || '', media: m.media || null, deleted: !!m.deleted, created_at: m.created_at, read_by: m.read_by || [] })));
  }
  if (key.startsWith('ch_')) {
    const c = db.channels.find(x => x.id === key);
    if (!c) return res.status(404).json({ error: 'Канал не найден' });
    return res.json(db.messages.filter(m => m.chat_id === key).slice(-500)
      .map(m => ({ id: m.id, sender_id: m.sender_id, text: m.text || '', media: m.media || null, deleted: !!m.deleted, created_at: m.created_at })));
  }
  const p = db.users.find(u => u.id === key);
  if (!p) return res.status(404).json({ error: 'Пользователь не найден' });
  const chatId = chatIdOf(req.uid, key);
  res.json(db.messages.filter(m => m.chat_id === chatId).slice(-500)
    .map(m => ({ id: m.id, sender_id: m.sender_id, text: m.text || '', media: m.media || null, deleted: !!m.deleted, created_at: m.created_at, read_by: m.read_by || [] })));
});

app.post('/api/send', auth, (req, res) => {
  const { to, text, media } = req.body || {};
  const clean = typeof text === 'string' ? text.trim() : '';
  const hasMedia = !!(media && media.id && (media.type === 'image' || media.type === 'video'));
  if (!clean && !hasMedia) return res.status(400).json({ error: 'Пустое сообщение' });
  if (clean.length > 4000) return res.status(400).json({ error: 'Сообщение слишком длинное' });

  const meU = db.users.find(u => u.id === req.uid);
  if (!meU) return res.status(401).json({ error: 'Сессия истекла, войдите заново' });

  const ctx = chatContext(req.uid, to);
  if (ctx.error) return res.status(403).json({ error: ctx.error });

  if (ctx.isChannel && meU.login !== ADMIN_LOGIN)
    return res.status(403).json({ error: 'Писать в канал может только владелец' });
  if (ctx.channel && ctx.channel.owner_id !== req.uid)
    return res.status(403).json({ error: 'Писать в канал может только владелец' });

  const msg = {
    id: ++msgSeq,
    chat_id: ctx.chatId,
    sender_id: req.uid,
    text: clean,
    media: hasMedia ? { id: media.id, type: media.type, name: media.name || null, size: media.size || null } : null,
    read_by: [],
    created_at: new Date().toISOString(),
  };
  db.messages.push(msg);
  saveDb();

  ctx.recvIds.forEach(id => sendTo(id, { type: 'new_message', data: Object.assign({}, msg, { to }) }));
  res.json({ success: true, msg });
});

app.post('/api/read', auth, (req, res) => {
  const to = (req.body || {}).to;
  if (to === 'channel' || to.startsWith('ch_') || to === 'saved') return res.json({ success: true });
  const ctx = chatContext(req.uid, to);
  if (ctx.error) return res.status(404).json({ error: ctx.error });
  let changed = false;
  db.messages.forEach(m => {
    if (m.chat_id !== ctx.chatId || m.sender_id === req.uid) return;
    if (!Array.isArray(m.read_by)) m.read_by = [];
    if (!m.read_by.includes(req.uid)) { m.read_by.push(req.uid); changed = true; }
  });
  if (changed) {
    saveDb();
    ctx.recvIds.forEach(id => { if (id !== req.uid) sendTo(id, { type: 'read', chat_id: ctx.chatId, uid: req.uid }); });
  }
  res.json({ success: true });
});

app.post('/api/msg/delete', auth, (req, res) => {
  const id = parseInt((req.body || {}).id, 10);
  const m = db.messages.find(x => x.id === id);
  if (!m) return res.status(404).json({ error: 'Сообщение не найдено' });
  if (m.sender_id !== req.uid) return res.status(403).json({ error: 'Можно удалять только свои сообщения' });
  const hadMedia = m.media && m.media.id;
  m.deleted = true; m.text = ''; m.media = null;
  saveDb();
  participantsOf(m.chat_id, req.uid).forEach(uid =>
    sendTo(uid, { type: 'msg_deleted', chat_id: m.chat_id, id }));
  if (hadMedia) { try { fs.unlinkSync(path.join(UPLOAD_DIR, hadMedia)); } catch (e) {} }
  res.json({ success: true });
});

app.post('/api/media', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  const isImg = (req.file.mimetype || '').startsWith('image/');
  const isVid = (req.file.mimetype || '').startsWith('video/');
  if (!isImg && !isVid) {
    try { fs.unlinkSync(req.file.path); } catch (e) {}
    return res.status(400).json({ error: 'Можно отправлять только фото или видео' });
  }
  res.json({
    id: req.file.filename,
    url: '/uploads/' + req.file.filename,
    type: isImg ? 'image' : 'video',
    name: req.file.originalname || null,
    size: req.file.size,
  });
});

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

app.post('/api/profile', auth, (req, res) => {
  const { name, login, color } = req.body || {};
  const meU = db.users.find(u => u.id === req.uid);
  if (!meU) return res.status(401).json({ error: 'Сессия истекла, войдите заново' });
  if (!name || !name.trim()) return res.status(400).json({ error: 'Имя не может быть пустым' });
  if (!/^[a-z0-9_]{3,20}$/.test(login || '')) return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры и _' });
  if (db.users.some(u => u.id !== meU.id && u.login === login.toLowerCase()))
    return res.status(400).json({ error: 'Такой логин уже занят' });
  meU.name = name.trim();
  meU.login = login.toLowerCase();
  if (color && /^#[0-9a-fA-F]{6}$/.test(color)) meU.color = color;
  saveDb();
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

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

app.post('/api/groups', auth, (req, res) => {
  const { name, memberIds } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Введите название' });
  const members = [req.uid, ...(Array.isArray(memberIds) ? memberIds : [])].filter((v, i, a) => a.indexOf(v) === i);
  db.groups.push({
    id: 'g_' + crypto.randomBytes(6).toString('hex'),
    name: String(name).trim().slice(0, 60),
    owner_id: req.uid,
    members,
    created_at: new Date().toISOString(),
  });
  saveDb();
  broadcast({ type: 'chats_changed' });
  res.json({ success: true });
});

app.post('/api/groups/add', auth, (req, res) => {
  const g = db.groups.find(x => x.id === (req.body || {}).gid);
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.owner_id !== req.uid) return res.status(403).json({ error: 'Только владелец может добавлять участников' });
  (Array.isArray((req.body || {}).memberIds) ? req.body.memberIds : []).forEach(id => {
    if (db.users.some(u => u.id === id) && !g.members.includes(id)) g.members.push(id);
  });
  saveDb();
  broadcast({ type: 'chats_changed' });
  res.json({ success: true });
});

app.post('/api/groups/leave', auth, (req, res) => {
  const g = db.groups.find(x => x.id === (req.body || {}).gid);
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.owner_id === req.uid) {
    db.messages = db.messages.filter(m => m.chat_id !== g.id);
    db.groups = db.groups.filter(x => x !== g);
  } else {
    g.members = g.members.filter(x => x !== req.uid);
  }
  saveDb();
  broadcast({ type: 'chats_changed' });
  res.json({ success: true });
});

app.post('/api/channels', auth, (req, res) => {
  const { name } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Введите название' });
  db.channels.push({
    id: 'ch_' + crypto.randomBytes(6).toString('hex'),
    name: String(name).trim().slice(0, 60),
    owner_id: req.uid,
    subscribers: [req.uid],
    created_at: new Date().toISOString(),
  });
  saveDb();
  broadcast({ type: 'chats_changed' });
  res.json({ success: true });
});

app.post('/api/channels/sub', auth, (req, res) => {
  const c = db.channels.find(x => x.id === (req.body || {}).cid);
  if (!c) return res.status(404).json({ error: 'Канал не найден' });
  c.subscribers = (c.subscribers || []).filter(x => x !== req.uid);
  if ((req.body || {}).val) c.subscribers.push(req.uid);
  saveDb();
  broadcast({ type: 'chats_changed' });
  res.json({ success: true });
});

app.post('/api/channels/delete', auth, (req, res) => {
  const c = db.channels.find(x => x.id === (req.body || {}).cid);
  if (!c) return res.status(404).json({ error: 'Канал не найден' });
  if (c.owner_id !== req.uid) return res.status(403).json({ error: 'Только владелец может удалить канал' });
  db.messages = db.messages.filter(m => m.chat_id !== c.id);
  db.channels = db.channels.filter(x => x !== c);
  saveDb();
  broadcast({ type: 'chats_changed' });
  res.json({ success: true });
});

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

app.post('/api/admin/unblock', auth, requireAdmin, (req, res) => {
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
    (m.chat_id !== 'channel' && !m.chat_id.startsWith('ch_') && m.chat_id.includes(target.id)));
  db.messages = db.messages.filter(m => !removed.includes(m));
  removed.forEach(m => {
    if (m.media && m.media.id) { try { fs.unlinkSync(path.join(UPLOAD_DIR, m.media.id)); } catch (e) {} }
  });
  db.groups.forEach(g => { g.members = g.members.filter(x => x !== target.id); });
  db.channels.forEach(c => { c.subscribers = (c.subscribers || []).filter(x => x !== target.id); });
  db.users = db.users.filter(u => u.id !== target.id);
  saveDb();

  sendTo(target.id, { type: 'kicked' });
  sockets.delete(target.id);
  broadcast({ type: 'users_changed' });
  res.json({ success: true });
});

app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ error: 'Максимальный размер файла — ' + MAX_MEDIA_MB + ' МБ' });
  next(err);
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', ws => {
  ws.__uid = null;

  ws.on('message', raw => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch (e) { return; }

    if (data.type === 'auth') {
      try {
        const payload = jwt.verify(data.token, JWT_SECRET);
        ws.__uid = payload.uid;
        sockets.set(payload.uid, ws);
        broadcast({ type: 'presence', id: payload.uid, online: true, lastSeen: null });
      } catch (e) {}
      return;
    }

    if (data.type === 'typing') {
      if (!ws.__uid || !data.to) return;
      if (data.to.startsWith('g_')) {
        const g = db.groups.find(x => x.id === data.to);
        if (!g) return;
        g.members.forEach(id => {
          if (id !== ws.__uid) sendTo(id, { type: 'typing', from: ws.__uid, chat: data.to });
        });
      } else {
        sendTo(data.to, { type: 'typing', from: ws.__uid, chat: data.to });
      }
      return;
    }
  });

  ws.on('close', () => {
    for (const [uid, s] of sockets) { if (s === ws) sockets.delete(uid); }
    const user = db.users.find(u => u.id === ws.__uid);
    if (user) {
      user.lastSeen = new Date().toISOString();
      saveDb();
      broadcast({ type: 'presence', id: user.id, online: false, lastSeen: user.lastSeen });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('KolGram запущен на порту ' + PORT);
});
