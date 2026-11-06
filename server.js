const crypto = require('crypto');
const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const accessCode = process.env.ACCESS_CODE;
const sessionSecret = process.env.SESSION_SECRET;
const databaseUrl = process.env.DATABASE_URL;
if (!accessCode || !sessionSecret || !databaseUrl) throw new Error('ACCESS_CODE, SESSION_SECRET, and DATABASE_URL must be configured.');

const pool = new Pool({ connectionString: databaseUrl });
app.use(express.json());

function equalCode(code) {
  const supplied = Buffer.from(String(code || ''));
  const expected = Buffer.from(accessCode);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}
function cookieValue(request, name) {
  const part = String(request.headers.cookie || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${name}=`));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : null;
}
function sign(value) { return crypto.createHmac('sha256', sessionSecret).update(value).digest('base64url'); }
function makeSession() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 60 * 60 * 1000 })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}
function hasSession(request) {
  const token = cookieValue(request, 'festival_gate');
  if (!token) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || signature.length !== sign(payload).length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(sign(payload)))) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}
function requireSession(request, response, next) {
  if (!hasSession(request)) return response.status(401).json({ message: '운영 코드가 필요합니다.' });
  next();
}
function parseStudentId(value) {
  const id = String(value || '').trim();
  if (/^14(?:0\d|[12]\d|30)$/.test(id)) return { id, type: 'admin' };
  if (/^[1-3][1-9](0[1-9]|[12]\d|30)$/.test(id)) return { id, type: 'student' };
  return null;
}

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS festival_entry_records (
      id BIGSERIAL PRIMARY KEY,
      student_id VARCHAR(4) NOT NULL,
      entry_type VARCHAR(10) NOT NULL CHECK (entry_type IN ('student', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS festival_one_student_entry
      ON festival_entry_records (student_id) WHERE entry_type = 'student';
  `);

  app.get('/api/session', (request, response) => response.json({ active: hasSession(request) }));
  app.post('/api/login', (request, response) => {
    if (!equalCode(request.body?.code)) return response.status(403).json({ message: '운영 코드가 올바르지 않습니다.' });
    const secure = request.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    response.setHeader('Set-Cookie', `festival_gate=${makeSession()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200${secure}`);
    response.json({ active: true });
  });
  app.post('/api/check', requireSession, async (request, response) => {
    const parsed = parseStudentId(request.body?.studentId);
    if (!parsed) return response.status(422).json({ message: '비정상적 코드입니다.' });
    if (parsed.type === 'admin') return response.json({ ...parsed, available: true });
    const { rows } = await pool.query('SELECT created_at FROM festival_entry_records WHERE student_id = $1 AND entry_type = $2 LIMIT 1', [parsed.id, 'student']);
    response.json({ ...parsed, available: rows.length === 0, firstAt: rows[0]?.created_at || null });
  });
  app.get('/api/entries', requireSession, async (_request, response) => {
    const { rows } = await pool.query('SELECT id, student_id, entry_type, created_at FROM festival_entry_records ORDER BY created_at DESC LIMIT 300');
    response.json({ entries: rows });
  });
  app.post('/api/entries', requireSession, async (request, response) => {
    const parsed = parseStudentId(request.body?.studentId);
    if (!parsed) return response.status(422).json({ message: '비정상적 코드입니다.' });
    try {
      const { rows } = await pool.query('INSERT INTO festival_entry_records (student_id, entry_type) VALUES ($1, $2) RETURNING id, student_id, entry_type, created_at', [parsed.id, parsed.type]);
      response.status(201).json({ entry: rows[0] });
    } catch (error) {
      if (error.code === '23505') {
        const { rows } = await pool.query('SELECT created_at FROM festival_entry_records WHERE student_id = $1 AND entry_type = $2 LIMIT 1', [parsed.id, 'student']);
        return response.status(409).json({ message: '이미 입장한 학번입니다.', firstAt: rows[0]?.created_at || null });
      }
      throw error;
    }
  });
  app.delete('/api/entries/:id', requireSession, async (request, response) => {
    if (!equalCode(request.body?.code)) return response.status(403).json({ message: '관리자 코드가 올바르지 않습니다.' });
    await pool.query('DELETE FROM festival_entry_records WHERE id = $1', [request.params.id]);
    response.json({ deleted: true });
  });
  app.delete('/api/entries', requireSession, async (request, response) => {
    if (!equalCode(request.body?.code)) return response.status(403).json({ message: '관리자 코드가 올바르지 않습니다.' });
    await pool.query('DELETE FROM festival_entry_records');
    response.json({ cleared: true });
  });
  app.use(express.static(path.join(__dirname, 'dist')));
  app.listen(port, () => console.log(`Festival entry server listening on ${port}`));
}
start().catch(error => { console.error(error); process.exit(1); });
