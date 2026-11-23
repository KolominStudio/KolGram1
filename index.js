const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

const ADMIN_LOGIN = 'tim';
const ADMIN_PASS = 'Px+j812ba1';

/* ---------- Хранилище ---------- */
function load(name, def) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8')); }
  catch (e) { return def; }
}
function save(name, data) {
  fs.writeFileSync(path.join(DATA_DIR, name), JSON.stringify(data));
}
let users = load('users.json', []);
let messages = load('messages.json', {});
let groups = load('groups.json', []);
let channels = load('channels.json', []);
let tokens = load('tokens.json', {});

function saveAll() {
  save('users.json', users);
  save('messages.json', messages);
  save('groups.json', groups);
  save('channels.json', channels);
  save('tokens.json', tokens);
}

/* ---------- Утилиты ---------- */
function hashPass(pass, salt) {
  return crypto.scryptSync(pass, salt, 32).toString('hex');
}
function newId() { return crypto.randomBytes(8).toString('hex'); }
function privateKey(a, b) { return [a, b].sort().join('_'); }
function findUser(id) { return users.find(u => u.id === id) || null; }
function userPublic(u, forUserId) {
  return {
    id: u.id, login: u.login, name: u.name, color: u.color,
    avatar: u.avatar || null, bio: u.bio || 'Пользователь KolGram',
    admin: !!u.admin, verified: !!u.verified,
    blocked: u.blocked || null,
    online: !!u.online, lastSeen: u.lastSeen || null,
    blockedByMe: forUserId ? (u.blockedBy || []).includes(forUserId) : false,
  };
}

function chatKeyOf(target, meId) {
  if (target === 'saved') return 'saved_' + meId;
  return target;
}
function isMemberOf(chatKey, meId) {
  if (chatKey === 'channel') return true;
  if (chatKey.startsWith('g_')) {
    const g = groups.find(x => x.id === chatKey);
    return g && g.members.includes(meId);
  }
  if (chatKey.startsWith('ch_')) {
    const c = channels.find(x => x.id === chatKey);
    if (!c) return false;
    if (c.owner_id === meId) return true;
    return (c.subs || []).includes(meId);
  }
  return true;
}
function participantsOf(chatKey, meId) {
  if (chatKey === 'channel') {
    return users.map(u => u.id);
  }
  if (chatKey.startsWith('g_')) {
    const g = groups.find(x => x.id === chatKey);
    return g ? g.members.slice() : [];
  }
  if (chatKey.startsWith('ch_')) {
    const c = channels.find(x => x.id === chatKey);
    if (!c) return [c ? c.owner_id : null].filter(Boolean);
    const set = new Set([c.owner_id, ...(c.subs || [])]);
    return [...set];
  }
  if (chatKey.startsWith('saved_')) return [chatKey.replace('saved_', '')];
  const [a, b] = chatKey.split('_');
  return [a, b];
}
function chatIdForClient(chatKey, meId) {
  if (chatKey === 'channel') return 'channel';
  if (chatKey.startsWith('saved_')) return 'saved_' + meId;
  if (chatKey.startsWith('g_') || chatKey.startsWith('ch_')) return chatKey;
  const [a, b] = chatKey.split('_');
  return a === meId ? b : a;
}
function pushMessage(chatKey, msg) {
  if (!messages[chatKey]) messages[chatKey] = [];
  messages[chatKey].push(msg);
}
function overviewEntry(chatKey) {
  const arr = messages[chatKey];
  if (!arr || !arr.length) return null;
  const last = arr[arr.length - 1];
  return {
    sender_id: last.sender_id,
    text: last.deleted ? '' : (last.text || ''),
    media: last.media ? { type: last.media.type } : null,
    created_at: last.created_at,
  };
}
function buildOverview() {
  const ov = {};
  for (const key of Object.keys(messages)) {
    const e = overviewEntry(key);
    if (e) ov[key] = e;
  }
  return ov;
}

/* ---------- Приложение ---------- */
const app = express();
app.use(express.json({ limit: '12mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + newId() + path.extname(file.originalname)),
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const uid = token && tokens[token];
  const u = uid && findUser(uid);
  if (!u) return res.status(401).json({ error: 'Требуется вход' });
  req.user = u; req.token = token;
  next();
}

/* Регистрация и вход */
app.post('/api/register', (req, res) => {
  const login = String(req.body.login || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim();
  const pass = String(req.body.pass || '');
  if (!name || name.length > 60) return res.status(400).json({ error: 'Введите имя (до 60 символов)' });
  if (!/^[a-z0-9_]{3,20}$/.test(login)) return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры и _' });
  if (pass.length < 6) return res.status(400).json({ error: 'Пароль: минимум 6 символов' });
  if (users.some(u => u.login === login)) return res.status(400).json({ error: 'Такой логин уже занят' });
  const salt = crypto.randomBytes(16).toString('hex');
  const u = {
    id: newId(), login, name,
    salt, passHash: hashPass(pass, salt),
    color: ['#4f8ef7','#8b5cf6','#e05a8a','#d98e4a','#43b97c','#45b8c9'][Math.floor(Math.random() * 6)],
    avatar: null, bio: 'Пользователь KolGram',
    admin: false, verified: false,
    blocked: null, blockedBy: [], online: false, lastSeen: null,
    created: Date.now(),
  };
  users.push(u);
  saveAll();
  broadcast({ type: 'users_changed' });
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const login = String(req.body.login || '').trim().toLowerCase();
  const pass = String(req.body.pass || '');
  const u = users.find(x => x.login === login);
  if (!u || u.passHash !== hashPass(pass, u.salt)) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }
  if (u.blocked) {
    if (u.blocked.until != null && Date.now() > u.blocked.until) {
      u.blocked = null; saveAll();
    } else {
      return res.status(403).json({ blocked: { reason: u.blocked.reason, until: u.blocked.until } });
    }
  }
  const token = crypto.randomBytes(24).toString('hex');
  tokens[token] = u.id;
  saveAll();
  res.json({ token, user: userPublic(u, u.id) });
});

function meData(u) {
  return userPublic(u, u.id);
}
app.get('/api/me', auth, (req, res) => res.json(meData(req.user)));

app.get('/api/users', auth, (req, res) => {
  res.json(users.filter(u => u.id !== req.user.id).map(u => userPublic(u, req.user.id)));
});

app.get('/api/chats', auth, (req, res) => {
  res.json({
    groups: groups.filter(g => g.members.includes(req.user.id)).map(g => ({ id: g.id, name: g.name, members: g.members, owner_id: g.owner_id })),
    channels: channels.map(c => ({ id: c.id, name: c.name, owner_id: c.owner_id, subscribed: (c.subs || []).includes(req.user.id) || c.owner_id === req.user.id })),
  });
});

app.get('/api/overview', auth, (req, res) => {
  const meId = req.user.id;
  const raw = buildOverview();
  const out = {};
  for (const key of Object.keys(raw)) {
    const parts = participantsOf(key, meId);
    if (!parts.includes(meId)) continue;
    if (key.startsWith('ch_') && !isMemberOf(key, meId)) {
      const c = channels.find(x => x.id === key);
      if (!c || c.owner_id !== meId) continue;
    }
    out[key] = raw[key];
  }
  res.json(out);
});

app.get('/api/chat/:target', auth, (req, res) => {
  const key = chatKeyOf(req.params.target, req.user.id);
  const arr = messages[key];
  if (!arr) return res.json([]);
  if (!isMemberOf(key, req.user.id)) return res.status(403).json({ error: 'Нет доступа к этому чату' });
  const list = arr.filter(m => !m.hidden_for || !m.hidden_for.includes(req.user.id));
  res.json(list);
});

app.post('/api/send', auth, (req, res) => {
  const me = req.user;
  const target = String(req.body.to || '');
  const text = String(req.body.text || '').slice(0, 4000);
  const media = req.body.media && req.body.media.id ? { id: req.body.media.id, type: req.body.media.type || 'image', url: '/uploads/' + req.body.media.id } : null;
  if (!text && !media) return res.status(400).json({ error: 'Пустое сообщение' });

  let key;
  if (target === 'saved') key = 'saved_' + me.id;
  else if (target === 'channel') {
    if (!me.admin) return res.status(403).json({ error: 'Публиковать может только админ' });
    key = 'channel';
  }
  else if (target.startsWith('g_')) {
    if (!isMemberOf(target, me.id)) return res.status(403).json({ error: 'Вы не участник группы' });
    key = target;
  }
  else if (target.startsWith('ch_')) {
    const c = channels.find(x => x.id === target);
    if (!c) return res.status(404).json({ error: 'Канал не найден' });
    if (c.owner_id !== me.id) return res.status(403).json({ error: 'Писать может только владелец канала' });
    key = target;
  }
  else {
    const peer = findUser(target);
    if (!peer) return res.status(404).json({ error: 'Пользователь не найден' });
    if (peer.blocked) return res.status(403).json({ error: 'Аккаунт заблокирован' });
    if ((peer.blockedBy || []).includes(me.id)) return res.status(403).json({ error: 'Этот пользователь заблокировал вас' });
    if ((me.blockedBy || []).includes(peer.id)) return res.status(403).json({ error: 'Вы заблокировали этого пользователя' });
    key = privateKey(me.id, peer.id);
  }

  const msg = {
    id: newId(), chat: key, sender_id: me.id,
    text, media,
    created_at: Date.now(),
    read_by: [me.id],
    deleted: false,
  };
  pushMessage(key, msg);
  saveAll();

  participantsOf(key, me.id).forEach(id => sendTo(id, { type: 'new_message', data: msg }));
  res.json({ msg });
});

app.post('/api/read', auth, (req, res) => {
  const key = chatKeyOf(String(req.body.to || ''), req.user.id);
  const arr = messages[key];
  if (arr) {
    let changed = false;
    arr.forEach(m => {
      if (!m.read_by.includes(req.user.id)) { m.read_by.push(req.user.id); changed = true; }
    });
    if (changed) {
      saveAll();
      participantsOf(key, req.user.id).forEach(id => sendTo(id, { type: 'read', chat: key, uid: req.user.id }));
    }
  }
  res.json({ ok: true });
});

app.post('/api/msg/delete', auth, (req, res) => {
  const id = String(req.body.id || '');
  for (const key of Object.keys(messages)) {
    const m = messages[key].find(x => x.id === id);
    if (m) {
      if (m.sender_id !== req.user.id) return res.status(403).json({ error: 'Можно удалять только свои сообщения' });
      m.deleted = true; m.text = ''; m.media = null;
      saveAll();
      participantsOf(key, req.user.id).forEach(pid => sendTo(pid, { type: 'msg_deleted', id }));
      return res.json({ ok: true });
    }
  }
  res.status(404).json({ error: 'Сообщение не найдено' });
});

/* Медиа */
app.post('/api/media', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  const isVideo = (req.file.mimetype || '').startsWith('video/');
  const id = req.file.filename;
  res.json({ id, type: isVideo ? 'video' : 'image', url: '/uploads/' + id });
});

/* Профиль */
app.post('/api/profile', auth, (req, res) => {
  const name = String(req.body.name || '').trim();
  const login = String(req.body.login || '').trim().toLowerCase();
  if (!name || name.length > 60) return res.status(400).json({ error: 'Имя до 60 символов' });
  if (!/^[a-z0-9_]{3,20}$/.test(login)) return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры и _' });
  if (users.some(u => u.login === login && u.id !== req.user.id)) return res.status(400).json({ error: 'Логин занят' });
  req.user.name = name;
  req.user.login = login;
  if (typeof req.body.color === 'string') req.user.color = req.body.color;
  if (typeof req.body.bio === 'string') req.user.bio = req.body.bio.slice(0, 200) || 'Пользователь KolGram';
  saveAll();
  broadcast({ type: 'users_changed' });
  res.json(meData(req.user));
});

app.post('/api/avatar', auth, (req, res) => {
  const data = String(req.body.data || '');
  if (!data.startsWith('data:image/')) return res.status(400).json({ error: 'Нужна картинка' });
  if (data.length > 3 * 1024 * 1024) return res.status(400).json({ error: 'Слишком большое фото (до 3 МБ)' });
  req.user.avatar = data;
  saveAll();
  broadcast({ type: 'users_changed' });
  res.json(meData(req.user));
});

/* Личная блокировка */
app.post('/api/block', auth, (req, res) => {
  const target = findUser(String(req.body.userId || ''));
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (!target.blockedBy) target.blockedBy = [];
  if (!target.blockedBy.includes(req.user.id)) target.blockedBy.push(req.user.id);
  saveAll();
  res.json({ ok: true });
});
app.post('/api/unblock', auth, (req, res) => {
  const target = findUser(String(req.body.userId || ''));
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  target.blockedBy = (target.blockedBy || []).filter(x => x !== req.user.id);
  saveAll();
  res.json({ ok: true });
});

/* Группы */
app.post('/api/groups', auth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Введите название' });
  const ids = (req.body.memberIds || []).filter(id => findUser(id) && id !== req.user.id);
  const g = { id: 'g_' + newId(), name, owner_id: req.user.id, members: [req.user.id, ...ids], created: Date.now() };
  groups.push(g);
  saveAll();
  broadcast({ type: 'chats_changed' });
  res.json({ ok: true, group: g });
});
app.post('/api/groups/leave', auth, (req, res) => {
  const g = groups.find(x => x.id === String(req.body.gid || ''));
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.owner_id === req.user.id) {
    groups = groups.filter(x => x.id !== g.id);
    delete messages[g.id];
    saveAll();
    broadcast({ type: 'chats_changed' });
    return res.json({ ok: true, deleted: true });
  }
  g.members = g.members.filter(id => id !== req.user.id);
  saveAll();
  broadcast({ type: 'chats_changed' });
  res.json({ ok: true });
});

/* Каналы */
app.post('/api/channels', auth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Введите название' });
  const c = { id: 'ch_' + newId(), name, owner_id: req.user.id, subs: [], created: Date.now() };
  channels.push(c);
  saveAll();
  broadcast({ type: 'chats_changed' });
  res.json({ ok: true, channel: c });
});
app.post('/api/channels/sub', auth, (req, res) => {
  const c = channels.find(x => x.id === String(req.body.cid || ''));
  if (!c) return res.status(404).json({ error: 'Канал не найден' });
  if (c.owner_id === req.user.id) return res.status(400).json({ error: 'Владелец не может отписаться от своего канала' });
  c.subs = c.subs || [];
  const want = !!req.body.val;
  const has = c.subs.includes(req.user.id);
  if (want && !has) c.subs.push(req.user.id);
  if (!want && has) c.subs = c.subs.filter(x => x !== req.user.id);
  saveAll();
  broadcast({ type: 'chats_changed' });
  res.json({ ok: true, subscribed: c.subs.includes(req.user.id) });
});
app.post('/api/channels/delete', auth, (req, res) => {
  const c = channels.find(x => x.id === String(req.body.cid || ''));
  if (!c) return res.status(404).json({ error: 'Канал не найден' });
  if (c.owner_id !== req.user.id) return res.status(403).json({ error: 'Только владелец может удалить канал' });
  channels = channels.filter(x => x.id !== c.id);
  delete messages[c.id];
  saveAll();
  broadcast({ type: 'chats_changed' });
  res.json({ ok: true });
});

/* Админ */
function requireAdmin(req, res, next) {
  if (!req.user.admin) return res.status(403).json({ error: 'Только для администратора' });
  next();
}
app.post('/api/admin/block', auth, requireAdmin, (req, res) => {
  const u = findUser(String(req.body.userId || ''));
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  if (u.admin) return res.status(400).json({ error: 'Админа заблокировать нельзя' });
  const d = String(req.body.duration || 'forever');
  const days = { '1': 1, '3': 3, '7': 7, '30': 30 }[d];
  u.blocked = { reason: String(req.body.reason || 'не указана').slice(0, 200), until: days ? Date.now() + days * 86400000 : null };
  saveAll();
  sendTo(u.id, { type: 'blocked', data: u.blocked });
  broadcast({ type: 'users_changed' });
  res.json({ ok: true });
});
app.post('/api/admin/unblock', auth, requireAdmin, (req, res) => {
  const u = findUser(String(req.body.userId || ''));
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  u.blocked = null;
  saveAll();
  broadcast({ type: 'users_changed' });
  res.json({ ok: true });
});
app.post('/api/admin/verify', auth, requireAdmin, (req, res) => {
  const u = findUser(String(req.body.userId || ''));
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  u.verified = !!req.body.val;
  saveAll();
  broadcast({ type: 'users_changed' });
  res.json({ ok: true });
});
app.post('/api/admin/delete', auth, requireAdmin, (req, res) => {
  const u = findUser(String(req.body.userId || ''));
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  if (u.admin) return res.status(400).json({ error: 'Админа удалить нельзя' });
  sendTo(u.id, { type: 'kicked' });
  users = users.filter(x => x.id !== u.id);
  groups.forEach(g => g.members = g.members.filter(id => id !== u.id));
  groups = groups.filter(g => g.members.length > 0);
  channels = channels.filter(c => c.owner_id !== u.id);
  for (const key of Object.keys(messages)) {
    if (key.startsWith('saved_')) {
      if (key === 'saved_' + u.id) delete messages[key];
      continue;
    }
    messages[key] = messages[key].map(m =>
      m.sender_id === u.id ? Object.assign({}, m, { deleted: true, text: '', media: null }) : m
    );
    if (!messages[key].length) delete messages[key];
  }
  saveAll();
  broadcast({ type: 'users_changed' });
  broadcast({ type: 'chats_changed' });
  res.json({ ok: true });
});

/* ---------- WebSocket ---------- */
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const wsByUser = new Map();

function sendTo(userId, obj) {
  const set = wsByUser.get(userId);
  if (!set) return;
  const str = JSON.stringify(obj);
  set.forEach(ws => { if (ws.readyState === 1) ws.send(str); });
}
function broadcast(obj) {
  const str = JSON.stringify(obj);
  wss.clients.forEach(ws => { if (ws.readyState === 1 && ws.userId) ws.send(str); });
}

wss.on('connection', (ws) => {
  ws.userId = null;

  ws.on('message', (buf) => {
    let p;
    try { p = JSON.parse(buf.toString()); } catch (e) { return; }
    if (!p || typeof p !== 'object') return;

    if (p.type === 'auth') {
      const uid = tokens[p.token];
      const u = uid && findUser(uid);
      if (!u) { ws.send(JSON.stringify({ type: 'kicked' })); return; }
      if (u.blocked) { ws.send(JSON.stringify({ type: 'blocked', data: u.blocked })); return; }
      ws.userId = u.id;
      if (!wsByUser.has(u.id)) wsByUser.set(u.id, new Set());
      wsByUser.get(u.id).add(ws);
      const wasOnline = u.online;
      u.online = true;
      saveAll();
      if (!wasOnline) broadcast({ type: 'presence', id: u.id, online: true, lastSeen: null });
      return;
    }
    if (!ws.userId) return;

    if (p.type === 'typing') {
      const target = String(p.to || '');
      const meId = ws.userId;
      if (target === 'channel' || target.startsWith('g_') || target.startsWith('ch_')) {
        if (isMemberOf(target, meId)) {
          participantsOf(target, meId).filter(id => id !== meId)
            .forEach(id => sendTo(id, { type: 'typing', chat: target, from: meId }));
        }
      } else {
        sendTo(target, { type: 'typing', from: meId });
      }
      return;
    }

    /* --- Сигналинг звонков --- */
    if (p.type === 'call_offer' || p.type === 'call_answer' || p.type === 'call_ice' || p.type === 'call_end' || p.type === 'call_busy') {
      const target = findUser(String(p.to || ''));
      if (!target) return;
      const out = { type: p.type, from: ws.userId };
      if (p.sdp) out.sdp = p.sdp;
      if (p.candidate) out.candidate = p.candidate;
      if (p.reason) out.reason = p.reason;
      if (p.callType) out.callType = p.callType;
      if (p.duration != null) out.duration = p.duration;
      sendTo(target.id, out);
      /* Записываем звонок в историю, когда кто-то завершил */
      if (p.type === 'call_end') {
        const meId = ws.userId;
        const key = privateKey(meId, target.id);
        const kind = p.callType === 'video' ? '📹 Видеозвонок' : '📞 Звонок';
        const text = p.reason === 'declined' ? kind + ' — отклонён'
          : p.reason === 'missed' ? kind + ' — пропущен'
          : kind + ' — ' + fmtDur(p.duration || 0);
        const msg = {
          id: newId(), chat: key, sender_id: meId,
          text, media: null, created_at: Date.now(),
          read_by: [meId], deleted: false, service: true,
        };
        pushMessage(key, msg);
        saveAll();
        [meId, target.id].forEach(id => sendTo(id, { type: 'new_message', data: msg }));
      }
      return;
    }
  });

  const markOffline = () => {
    if (!ws.userId) return;
    const u = findUser(ws.userId);
    if (wsByUser.has(ws.userId)) {
      wsByUser.get(ws.userId).delete(ws);
      if (!wsByUser.get(ws.userId).size) wsByUser.delete(ws.userId);
    }
    if (u) {
      const stillOnline = wsByUser.has(u.id);
      if (!stillOnline) {
        u.online = false;
        u.lastSeen = Date.now();
        saveAll();
        broadcast({ type: 'presence', id: u.id, online: false, lastSeen: u.lastSeen });
      }
    }
  };
  ws.on('close', markOffline);
  ws.on('error', markOffline);
});

function fmtDur(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const sec = s % 60;
  if (m === 0) return sec + ' с';
  return m + ' мин ' + (sec < 10 ? '0' : '') + sec + ' с';
}

/* Админ по умолчанию */
(function ensureAdmin() {
  let admin = users.find(u => u.login === ADMIN_LOGIN);
  if (!admin) {
    const salt = crypto.randomBytes(16).toString('hex');
    admin = {
      id: newId(), login: ADMIN_LOGIN, name: 'Тимофей (админ)',
      salt, passHash: hashPass(ADMIN_PASS, salt),
      color: '#4f8ef7', avatar: null, bio: 'Администратор KolGram',
      admin: true, verified: true, blocked: null, blockedBy: [],
      online: false, lastSeen: null, created: Date.now(),
    };
    users.push(admin);
  }
  if (!admin.admin) admin.admin = true;
  saveAll();
})();

server.listen(PORT, () => {
  console.log('KolGram server работает на порту ' + PORT);
}); 
