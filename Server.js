const express = require('express');
const cors = require('cors');
const fetch = (...a) => import('node-fetch').then(({ default: f }) => f(...a));
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors({ origin: ['https://loaderhub1990.github.io', 'http://localhost:3000'] }));

// ════════════════════════════════════════════════
// CONFIG — ใส่ค่าจาก Discord Developer Portal
// ════════════════════════════════════════════════
const CLIENT_ID     = process.env.CLIENT_ID     || '1499108630325366905';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'YOUR_CLIENT_SECRET_HERE';
const REDIRECT_URI  = process.env.REDIRECT_URI  || 'https://loaderhub1990.github.io/Discord/';
const PORT          = process.env.PORT          || 3000;

// ════════════════════════════════════════════════
// IN-MEMORY STORE
// เก็บ session token → ข้อมูล user
// (ถ้าต้องการ persist ให้เปลี่ยนเป็น SQLite / MongoDB)
// ════════════════════════════════════════════════
const sessions  = new Map(); // token → { me, guilds, discord_token, expires }
const allUsers  = new Map(); // user_id → full data (ทุก account ที่เคย auth)

// ════════════════════════════════════════════════
// HELPER — แลก code กับ Discord token
// ════════════════════════════════════════════════
async function exchangeCode(code) {
  const body = new URLSearchParams({
    client_id:     CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type:    'authorization_code',
    code,
    redirect_uri:  REDIRECT_URI,
  });
  const res = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error('Discord token exchange failed: ' + err);
  }
  return res.json(); // { access_token, token_type, expires_in, refresh_token, scope }
}

// ════════════════════════════════════════════════
// HELPER — ดึงข้อมูล user จาก Discord
// ════════════════════════════════════════════════
async function fetchDiscordUser(access_token) {
  const [meRes, guildsRes] = await Promise.all([
    fetch('https://discord.com/api/users/@me',         { headers: { Authorization: `Bearer ${access_token}` } }),
    fetch('https://discord.com/api/users/@me/guilds',  { headers: { Authorization: `Bearer ${access_token}` } }),
  ]);
  if (!meRes.ok) throw new Error('ดึงข้อมูล user ล้มเหลว');
  const me     = await meRes.json();
  const guilds = guildsRes.ok ? await guildsRes.json() : [];
  return { me, guilds };
}

// ════════════════════════════════════════════════
// MIDDLEWARE — ตรวจ session
// ════════════════════════════════════════════════
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  const sess = sessions.get(token);
  if (Date.now() > sess.expires) { sessions.delete(token); return res.status(401).json({ error: 'Session expired' }); }
  req.session = sess;
  next();
}

// ════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════

// POST /api/callback — รับ code จาก frontend แล้วแลก token
app.post('/api/callback', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });

  try {
    const tokenData = await exchangeCode(code);
    const { me, guilds } = await fetchDiscordUser(tokenData.access_token);

    // บันทึก user ลง store
    const userData = {
      id:            me.id,
      username:      me.username,
      discriminator: me.discriminator,
      email:         me.email,
      avatar:        me.avatar,
      verified:      me.verified,
      premium_type:  me.premium_type || 0,
      mfa_enabled:   me.mfa_enabled,
      locale:        me.locale,
      guilds,
      access_token:  tokenData.access_token,
      joined_at:     new Date().toISOString(),
    };
    allUsers.set(me.id, userData);

    // สร้าง session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionToken, {
      userId:  me.id,
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 วัน
    });

    console.log(`[+] New auth: ${me.username}#${me.discriminator} (${me.id})`);
    res.json({ token: sessionToken });
  } catch (e) {
    console.error('[callback]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/me — ข้อมูล user ปัจจุบัน
app.get('/api/me', auth, (req, res) => {
  const user = allUsers.get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  // ไม่ส่ง access_token กลับไปใน /me
  const { access_token, ...safe } = user;
  res.json(safe);
});

// GET /api/accounts — รายการบัญชีทั้งหมดที่เคย auth (เฉพาะ admin หรือ user ที่ผ่าน auth)
// ⚠️  ในระบบจริงควรมี role ตรวจด้วยว่าใครดูได้บ้าง
app.get('/api/accounts', auth, (req, res) => {
  const list = Array.from(allUsers.values()).map(u => {
    // ซ่อน access_token จากรายการ
    const { access_token, ...safe } = u;
    return safe;
  });
  res.json(list);
});

// GET /api/accounts/:id — ดูบัญชีเดี่ยว
app.get('/api/accounts/:id', auth, (req, res) => {
  const user = allUsers.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { access_token, ...safe } = user;
  res.json(safe);
});

// GET /api/stats — สถิติรวม
app.get('/api/stats', auth, (req, res) => {
  const users = Array.from(allUsers.values());
  res.json({
    total:    users.length,
    premium:  users.filter(u => u.premium_type > 0).length,
    verified: users.filter(u => u.verified).length,
    servers:  users.reduce((s, u) => s + (u.guilds?.length || 0), 0),
  });
});

// DELETE /api/accounts/:id — ลบบัญชีออกจาก store
app.delete('/api/accounts/:id', auth, (req, res) => {
  if (!allUsers.has(req.params.id)) return res.status(404).json({ error: 'Not found' });
  allUsers.delete(req.params.id);
  res.json({ ok: true });
});

// Health check
app.get('/', (req, res) => res.json({ status: 'ok', users: allUsers.size }));

// ════════════════════════════════════════════════
app.listen(PORT, () => console.log(`✅  LoaderHub backend running on port ${PORT}`));
