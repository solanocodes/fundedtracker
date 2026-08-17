const express = require('express');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
const PORT = process.env.PORT || 8080;
const TRACKER_PASSWORD = process.env.TRACKER_PASSWORD || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const AI_ENABLED = !!process.env.ANTHROPIC_API_KEY;
const EMAIL_ENABLED = !!(process.env.RESEND_API_KEY && process.env.DIGEST_TO);
const DIGEST_TO = process.env.DIGEST_TO || '';
const DIGEST_FROM = process.env.DIGEST_FROM || 'SOA Tracker <onboarding@resend.dev>';
const DIGEST_TZ = process.env.DIGEST_TZ || 'America/New_York';
const DISCORD_WEBHOOK_RE = /^https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[\w-]+$/;

const anthropic = AI_ENABLED ? new Anthropic() : null;

// Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(cookieParser());

// ── Auth helpers ──
function makeToken() {
  return crypto.createHmac('sha256', SESSION_SECRET).update(TRACKER_PASSWORD + Date.now()).digest('hex');
}

function signToken(token) {
  return token + '.' + crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex').slice(0, 16);
}

function verifyToken(signed) {
  if (!signed || !signed.includes('.')) return false;
  const [token, sig] = signed.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex').slice(0, 16);
  return sig === expected;
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.tracker_session;
  if (!token || !verifyToken(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Init DB ──
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS payouts (
        id TEXT PRIMARY KEY,
        amount NUMERIC NOT NULL,
        date TEXT,
        firm TEXT,
        account TEXT,
        notes TEXT
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id TEXT PRIMARY KEY,
        amount NUMERIC NOT NULL,
        date TEXT,
        type TEXT,
        firm TEXT,
        notes TEXT
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        firm TEXT,
        size INTEGER,
        status TEXT,
        start_date TEXT,
        notes TEXT
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS commissions (
        id TEXT PRIMARY KEY,
        amount NUMERIC NOT NULL,
        date TEXT,
        source TEXT,
        notes TEXT
      )
    `);
    // Business tracker: store monthly data as JSON keyed by YYYY-MM
    await client.query(`
      CREATE TABLE IF NOT EXISTS business_months (
        key TEXT PRIMARY KEY,
        data JSONB NOT NULL
      )
    `);
    // App settings: annual target, Google Sheet sync config, synced closer data, digest state
    await client.query(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL
      )
    `);
    await client.query(
      "INSERT INTO settings (key, value) VALUES ('annualTarget', '900000') ON CONFLICT (key) DO NOTHING"
    );
    // One-time restore: the calc() crash (fixed in 9f55c4e) silently blocked all
    // manual saves, losing the owner's re-entered July 2026 software list. Restore
    // it once, unless the month already carries real software data.
    const seeded = await client.query("SELECT 1 FROM settings WHERE key='restoreJul2026Soft'");
    if (!seeded.rows.length) {
      const JULY_SOFT = [
        { name: 'YouTube tools', amount: 154 },
        { name: 'CRM / sales', amount: 103 },
        { name: 'Claude / AI', amount: 213.20 },
        { name: 'Marketing', amount: 4400 },
        { name: 'Sendblue', amount: 1000 },
        { name: 'Typeform', amount: 137 },
        { name: 'Kit', amount: 126.62 },
        { name: 'Trakyo', amount: 197 },
        { name: 'Manychat', amount: 101.27 },
        { name: 'Retti', amount: 49 },
        { name: 'TradeCopia', amount: 149.99 }
      ];
      const row = await client.query("SELECT data FROM business_months WHERE key='2026-07'");
      const data = row.rows.length ? row.rows[0].data : {
        rev: [0, 0, 0, 0],
        team: [{ name: 'Jesus', role: 'Closer', amount: 0 }, { name: 'Zain', role: 'Setter', amount: 0 }],
        soft: []
      };
      const softHasData = (data.soft || []).some(r => r.name && String(r.name).trim() && (parseFloat(r.amount) || 0) > 0);
      if (!softHasData) {
        data.soft = JULY_SOFT;
        await client.query(
          "INSERT INTO business_months (key, data) VALUES ('2026-07', $1) ON CONFLICT (key) DO UPDATE SET data = $1",
          [JSON.stringify(data)]
        );
        console.log('Restored July 2026 software list (11 tools)');
      }
      await client.query("INSERT INTO settings (key, value) VALUES ('restoreJul2026Soft', 'true') ON CONFLICT (key) DO NOTHING");
    }
    console.log('Database tables ready');
  } finally {
    client.release();
  }
}

// ── Auth routes ──
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password !== TRACKER_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const token = signToken(makeToken());
  res.cookie('tracker_session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  });
  res.json({ ok: true });
});

app.get('/api/check', (req, res) => {
  const token = req.cookies?.tracker_session;
  if (!token || !verifyToken(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ ok: true });
});

// ── Data routes ──

// Run one read independently of the others. A failure in a single table must never
// blank out the whole dashboard, and a missing table repairs itself via initDB.
async function safeRead(label, sql) {
  try {
    return { rows: (await pool.query(sql)).rows };
  } catch (err) {
    if (err.code === '42P01') { // undefined_table
      console.warn(`Table for "${label}" missing — running initDB to repair`);
      try {
        await initDB();
        return { rows: (await pool.query(sql)).rows, repaired: true };
      } catch (retryErr) {
        console.error(`Repair failed for "${label}":`, retryErr.message);
        return { rows: [], error: `${label}: ${retryErr.message}` };
      }
    }
    console.error(`Read failed for "${label}":`, err.message);
    return { rows: [], error: `${label}: ${err.message}` };
  }
}

app.get('/api/data', authMiddleware, async (req, res) => {
  const [payouts, expenses, accounts, commissions] = await Promise.all([
    safeRead('payouts', 'SELECT id, amount::float, date, firm, account, notes FROM payouts ORDER BY date DESC'),
    safeRead('expenses', 'SELECT id, amount::float, date, type, firm, notes FROM expenses ORDER BY date DESC'),
    safeRead('accounts', 'SELECT id, name, firm, size, status, start_date AS "startDate", notes FROM accounts ORDER BY name'),
    safeRead('commissions', 'SELECT id, amount::float, date, source, notes FROM commissions ORDER BY date DESC')
  ]);
  const errors = [payouts, expenses, accounts, commissions].map(r => r.error).filter(Boolean);
  res.json({
    payouts: payouts.rows,
    expenses: expenses.rows,
    accounts: accounts.rows,
    commissions: commissions.rows,
    errors: errors.length ? errors : undefined
  });
});

// Diagnostics: per-table reachability and row counts.
app.get('/api/health', authMiddleware, async (req, res) => {
  const TABLES = ['payouts', 'expenses', 'accounts', 'commissions', 'business_months', 'settings'];
  const tables = {};
  for (const t of TABLES) {
    try {
      const r = await pool.query(`SELECT COUNT(*)::int AS n FROM ${t}`); // fixed identifiers, not user input
      tables[t] = { ok: true, rows: r.rows[0].n };
    } catch (err) {
      tables[t] = { ok: false, error: err.message };
    }
  }
  res.json({ databaseConfigured: !!process.env.DATABASE_URL, tables });
});

// Payouts
app.post('/api/payouts', authMiddleware, async (req, res) => {
  const { id, amount, date, firm, account, notes } = req.body;
  try {
    await pool.query(
      'INSERT INTO payouts (id, amount, date, firm, account, notes) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET amount=$2, date=$3, firm=$4, account=$5, notes=$6',
      [id, amount, date, firm, account, notes]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/payouts error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/payouts/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM payouts WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/payouts error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Expenses
app.post('/api/expenses', authMiddleware, async (req, res) => {
  const { id, amount, date, type, firm, notes } = req.body;
  try {
    await pool.query(
      'INSERT INTO expenses (id, amount, date, type, firm, notes) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET amount=$2, date=$3, type=$4, firm=$5, notes=$6',
      [id, amount, date, type, firm, notes]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/expenses error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/expenses/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM expenses WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/expenses error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Commissions
app.post('/api/commissions', authMiddleware, async (req, res) => {
  const { id, amount, date, source, notes } = req.body;
  try {
    await pool.query(
      'INSERT INTO commissions (id, amount, date, source, notes) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO UPDATE SET amount=$2, date=$3, source=$4, notes=$5',
      [id, amount, date, source, notes]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/commissions error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/commissions/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM commissions WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/commissions error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Accounts
app.post('/api/accounts', authMiddleware, async (req, res) => {
  const { id, name, firm, size, status, startDate, notes } = req.body;
  try {
    await pool.query(
      'INSERT INTO accounts (id, name, firm, size, status, start_date, notes) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET name=$2, firm=$3, size=$4, status=$5, start_date=$6, notes=$7',
      [id, name, firm, size, status, startDate, notes]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/accounts error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/accounts/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM accounts WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/accounts error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Import (replace all)
app.post('/api/import', authMiddleware, async (req, res) => {
  const { payouts, expenses, accounts, commissions } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM payouts');
    await client.query('DELETE FROM expenses');
    await client.query('DELETE FROM accounts');
    await client.query('DELETE FROM commissions');
    for (const p of (payouts || [])) {
      await client.query('INSERT INTO payouts (id,amount,date,firm,account,notes) VALUES ($1,$2,$3,$4,$5,$6)', [p.id, p.amount, p.date, p.firm, p.account, p.notes]);
    }
    for (const e of (expenses || [])) {
      await client.query('INSERT INTO expenses (id,amount,date,type,firm,notes) VALUES ($1,$2,$3,$4,$5,$6)', [e.id, e.amount, e.date, e.type, e.firm, e.notes]);
    }
    for (const a of (accounts || [])) {
      await client.query('INSERT INTO accounts (id,name,firm,size,status,start_date,notes) VALUES ($1,$2,$3,$4,$5,$6,$7)', [a.id, a.name, a.firm, a.size, a.status, a.startDate, a.notes]);
    }
    for (const c of (commissions || [])) {
      await client.query('INSERT INTO commissions (id,amount,date,source,notes) VALUES ($1,$2,$3,$4,$5)', [c.id, c.amount, c.date, c.source, c.notes]);
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('POST /api/import error:', err);
    res.status(500).json({ error: 'Import failed' });
  } finally {
    client.release();
  }
});

// Export
app.get('/api/export', authMiddleware, async (req, res) => {
  try {
    const [payouts, expenses, accounts, commissions] = await Promise.all([
      pool.query('SELECT id, amount::float, date, firm, account, notes FROM payouts'),
      pool.query('SELECT id, amount::float, date, type, firm, notes FROM expenses'),
      pool.query('SELECT id, name, firm, size, status, start_date AS "startDate", notes FROM accounts'),
      pool.query('SELECT id, amount::float, date, source, notes FROM commissions')
    ]);
    res.json({ payouts: payouts.rows, expenses: expenses.rows, accounts: accounts.rows, commissions: commissions.rows });
  } catch (err) {
    console.error('GET /api/export error:', err);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ── Business Tracker routes ──
app.get('/api/business/data', authMiddleware, async (req, res) => {
  try {
    const state = await loadBusinessState();
    res.json({
      months: state.months,
      sync: state.sync,
      closer: state.closer,
      meta: {
        annualTarget: state.annualTarget,
        sheetConfigured: !!(state.sheetCfg && state.sheetCfg.url),
        sheetStartMonth: (state.sheetCfg && state.sheetCfg.startMonth) || null,
        sheetLastSync: state.closerSync ? state.closerSync.syncedAt : null,
        sheetError: state.closerSync ? state.closerSync.error || null : null,
        aiEnabled: AI_ENABLED,
        digestEnabled: EMAIL_ENABLED || !!(await getSetting('discordWebhook'))
      }
    });
  } catch (err) {
    console.error('GET /api/business/data error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/business/months', authMiddleware, async (req, res) => {
  const { key, data } = req.body;
  if (!key || !data) return res.status(400).json({ error: 'key and data required' });
  try {
    await pool.query(
      'INSERT INTO business_months (key, data) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET data = $2',
      [key, JSON.stringify(data)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/business/months error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ── Settings helpers ──
async function getSetting(key) {
  const r = await pool.query('SELECT value FROM settings WHERE key=$1', [key]);
  return r.rows.length ? r.rows[0].value : null;
}
async function setSetting(key, value) {
  await pool.query(
    'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2',
    [key, JSON.stringify(value)]
  );
}

// ── Google Sheet closer-report sync ──
function parseCSV(text) {
  const rows = []; let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else {
      if (c === '"') q = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
      else if (c !== '\r') field += c;
    }
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function colIdx(letter) {
  return [...String(letter).trim().toUpperCase()].reduce((a, ch) => a * 26 + (ch.charCodeAt(0) - 64), 0) - 1;
}
function parseMoney(s) {
  const n = parseFloat(String(s ?? '').replace(/[$,\s]/g, ''));
  return Number.isFinite(n) ? n : 0;
}
function parseYM(s) {
  const str = String(s ?? '').trim();
  let m = str.match(/^(\d{4})-(\d{1,2})/);
  if (m) return m[1] + '-' + String(parseInt(m[2])).padStart(2, '0');
  m = str.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
  if (m) return m[3] + '-' + String(parseInt(m[1])).padStart(2, '0');
  // Date-object fallback only for strings that look like dates (has separators or
  // month names) — otherwise plain numbers like "3000" would parse as year 3000
  if (!/[\/\-A-Za-z]/.test(str) || !str) return null;
  const d = new Date(str);
  if (!isNaN(d)) return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
  return null;
}
function colLetter(idx) {
  let s = ''; idx = idx + 1;
  while (idx > 0) { const r = (idx - 1) % 26; s = String.fromCharCode(65 + r) + s; idx = Math.floor((idx - 1) / 26); }
  return s;
}
// Resolve which columns to read: headers named cashCollected / recurringCash win
// over configured letters, and the date column self-detects if the configured one
// doesn't parse — so the sync works even if the sheet layout shifts.
function detectColumns(rows, cfg) {
  const header = rows[0] || [];
  const norm = s => String(s || '').toLowerCase().replace(/[^a-z]/g, '');
  let ci = header.findIndex(h => norm(h) === 'cashcollected');
  let ri = header.findIndex(h => norm(h) === 'recurringcash');
  if (ci < 0) ci = colIdx(cfg.cashCol || 'L');
  if (ri < 0) ri = colIdx(cfg.recurCol || 'M');
  const scan = idx => { let n = 0; for (let i = 1; i < Math.min(rows.length, 200); i++) { if (parseYM((rows[i] || [])[idx])) n++; } return n; };
  let di = colIdx(cfg.dateCol || 'A');
  if (scan(di) === 0) {
    let best = -1, bestN = 0;
    for (let c = 0; c < header.length; c++) {
      const n = scan(c) + (/date/i.test(String(header[c] || '')) && scan(c) > 0 ? 5 : 0);
      if (n > bestN) { bestN = n; best = c; }
    }
    if (best >= 0) di = best;
  }
  return { di, ci, ri };
}
function sheetIdFromUrl(url) {
  const m = String(url ?? '').match(/\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return m[1];
  if (/^[a-zA-Z0-9_-]{20,}$/.test(String(url ?? '').trim())) return String(url).trim();
  return null;
}

async function syncSheet() {
  const cfg = await getSetting('sheetCfg');
  if (!cfg || !cfg.url) return { error: 'No sheet configured' };
  const id = sheetIdFromUrl(cfg.url);
  if (!id) { const r = { error: 'Could not read a spreadsheet ID from that URL', syncedAt: new Date().toISOString() }; await setSetting('closerSync', r); return r; }
  try {
    let url = `https://docs.google.com/spreadsheets/d/${id}/gviz/tq?tqx=out:csv`;
    if (cfg.tab) url += `&sheet=${encodeURIComponent(cfg.tab)}`;
    const resp = await fetch(url, { redirect: 'follow' });
    const text = await resp.text();
    if (!resp.ok || text.trim().startsWith('<')) {
      const r = { error: 'Sheet is not accessible — set sharing to "Anyone with the link: Viewer"', syncedAt: new Date().toISOString() };
      await setSetting('closerSync', r);
      return r;
    }
    const rows = parseCSV(text);
    const { di, ci, ri } = detectColumns(rows, cfg);
    const data = {}; let matched = 0;
    for (let i = 1; i < rows.length; i++) { // skip header row
      const ym = parseYM(rows[i][di]);
      if (!ym) continue;
      const cash = parseMoney(rows[i][ci]), recur = parseMoney(rows[i][ri]);
      if (!data[ym]) data[ym] = { cash: 0, recurring: 0, total: 0 };
      data[ym].cash += cash; data[ym].recurring += recur; data[ym].total += cash + recur;
      matched++;
    }
    const result = {
      data, rows: matched, syncedAt: new Date().toISOString(),
      cols: { date: colLetter(di), cash: colLetter(ci), recurring: colLetter(ri) }
    };
    if (matched === 0) result.error = 'No rows with readable dates found — check the tab name and date column';
    await setSetting('closerSync', result);
    console.log(`Sheet sync: ${matched} rows across ${Object.keys(data).length} months (date=${result.cols.date} cash=${result.cols.cash} recur=${result.cols.recurring})`);
    return result;
  } catch (err) {
    console.error('Sheet sync error:', err);
    const r = { error: 'Fetch failed: ' + err.message, syncedAt: new Date().toISOString() };
    await setSetting('closerSync', r);
    return r;
  }
}

// Effective per-month business totals, shared by AI + digest.
// rev slots: [0]=mentorship(manual, overridden by sheet from startMonth), [1]=youtube,
// [2]=legacy affiliate (ignored), [3]=other. Affiliate/prop payouts come from funded-tracker sync.
async function loadBusinessState() {
  const [monthsRes, payoutsSync, commissionsSync, sheetCfg, closerSync, annualTarget] = await Promise.all([
    safeRead('business_months', 'SELECT key, data FROM business_months ORDER BY key'),
    safeRead('payouts sync', "SELECT substr(date,1,7) AS ym, SUM(amount)::float AS total FROM payouts WHERE date IS NOT NULL AND date <> '' GROUP BY ym"),
    safeRead('commissions sync', "SELECT substr(date,1,7) AS ym, SUM(amount)::float AS total FROM commissions WHERE date IS NOT NULL AND date <> '' GROUP BY ym"),
    getSetting('sheetCfg'),
    getSetting('closerSync'),
    getSetting('annualTarget')
  ]);
  const months = {}; monthsRes.rows.forEach(r => { months[r.key] = r.data; });
  const sync = {};
  payoutsSync.rows.forEach(r => { if (!sync[r.ym]) sync[r.ym] = { payouts: 0, commissions: 0 }; sync[r.ym].payouts = r.total; });
  commissionsSync.rows.forEach(r => { if (!sync[r.ym]) sync[r.ym] = { payouts: 0, commissions: 0 }; sync[r.ym].commissions = r.total; });
  const startMonth = (sheetCfg && sheetCfg.startMonth) || '9999-99';
  const closer = {};
  if (closerSync && closerSync.data) {
    Object.entries(closerSync.data).forEach(([ym, v]) => { if (ym >= startMonth) closer[ym] = v.total; });
  }
  const keys = [...new Set([...Object.keys(months), ...Object.keys(sync), ...Object.keys(closer)])].sort();
  const monthly = keys.map(ym => {
    const d = months[ym] || {};
    const rev = d.rev || [0, 0, 0, 0];
    const s = sync[ym] || { payouts: 0, commissions: 0 };
    const sheetActive = !!(sheetCfg && ym >= startMonth);
    const mentorship = sheetActive ? (closer[ym] || 0) : (parseFloat(rev[0]) || 0);
    const youtube = parseFloat(rev[1]) || 0;
    const other = parseFloat(rev[3]) || 0;
    const affiliate = s.commissions || 0;
    const propPayouts = s.payouts || 0;
    const team = (d.team || []).reduce((t, r) => t + (parseFloat(r.amount) || 0), 0);
    const software = (d.soft || []).reduce((t, r) => t + (parseFloat(r.amount) || 0), 0);
    const revenue = mentorship + youtube + other + affiliate + propPayouts;
    const expenses = team + software;
    return { ym, mentorship, youtube, other, affiliate, propPayouts, revenue, team, software, expenses, profit: revenue - expenses };
  });
  return { months, sync, closer, monthly, sheetCfg, closerSync, annualTarget: parseFloat(annualTarget) || 900000 };
}

// ── Settings routes ──
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const [annualTarget, sheetCfg, closerSync, discordWebhook] = await Promise.all([
      getSetting('annualTarget'), getSetting('sheetCfg'), getSetting('closerSync'), getSetting('discordWebhook')
    ]);
    res.json({
      annualTarget: parseFloat(annualTarget) || 900000,
      sheetCfg: sheetCfg || null,
      sheetLastSync: closerSync ? closerSync.syncedAt : null,
      sheetError: closerSync ? closerSync.error || null : null,
      sheetRows: closerSync ? closerSync.rows || 0 : 0,
      sheetCols: closerSync ? closerSync.cols || null : null,
      discordWebhook: discordWebhook || '',
      aiEnabled: AI_ENABLED,
      digestEnabled: EMAIL_ENABLED || !!discordWebhook
    });
  } catch (err) {
    console.error('GET /api/settings error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/settings', authMiddleware, async (req, res) => {
  try {
    const { annualTarget, sheetCfg, discordWebhook } = req.body;
    if (annualTarget !== undefined) {
      const t = parseFloat(annualTarget);
      if (!Number.isFinite(t) || t < 0) return res.status(400).json({ error: 'Invalid target' });
      await setSetting('annualTarget', t);
    }
    if (discordWebhook !== undefined) {
      const w = String(discordWebhook || '').trim();
      if (w && !DISCORD_WEBHOOK_RE.test(w)) {
        return res.status(400).json({ error: 'That does not look like a Discord webhook URL (https://discord.com/api/webhooks/…)' });
      }
      await setSetting('discordWebhook', w || null);
    }
    if (sheetCfg !== undefined) {
      if (sheetCfg === null) { await setSetting('sheetCfg', null); await setSetting('closerSync', null); }
      else {
        await setSetting('sheetCfg', {
          url: String(sheetCfg.url || ''), tab: String(sheetCfg.tab || ''),
          dateCol: String(sheetCfg.dateCol || 'A'), cashCol: String(sheetCfg.cashCol || 'L'),
          recurCol: String(sheetCfg.recurCol || 'M'), startMonth: String(sheetCfg.startMonth || '')
        });
      }
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/settings error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/sheet/sync', authMiddleware, async (req, res) => {
  const result = await syncSheet();
  res.json(result);
});

// ── AI endpoints (Claude) ──
async function buildAIContext() {
  const state = await loadBusinessState();
  const today = new Date().toISOString().slice(0, 10);
  const year = today.slice(0, 4);
  const ytd = state.monthly.filter(m => m.ym.startsWith(year));
  const ytdRevenue = ytd.reduce((s, m) => s + m.revenue, 0);
  return {
    today,
    annualRevenueTarget: state.annualTarget,
    ytdRevenue: Math.round(ytdRevenue),
    monthly: state.monthly.map(m => ({
      month: m.ym,
      revenue: Math.round(m.revenue),
      revenueStreams: {
        mentorshipCoaching: Math.round(m.mentorship), youtubeSponsorships: Math.round(m.youtube),
        affiliateCommissions: Math.round(m.affiliate), propFirmPayouts: Math.round(m.propPayouts),
        other: Math.round(m.other)
      },
      expenses: Math.round(m.expenses),
      teamPayroll: Math.round(m.team), software: Math.round(m.software),
      netProfit: Math.round(m.profit),
      teamMembers: ((state.months[m.ym] || {}).team || []).map(t => ({ name: t.name, role: t.role, paid: Math.round(parseFloat(t.amount) || 0) })),
      softwareTools: ((state.months[m.ym] || {}).soft || []).map(t => ({ name: t.name, cost: Math.round(parseFloat(t.amount) || 0) }))
    }))
  };
}

const AI_SYSTEM = `You are the analytics assistant inside a small-business profit tracker used by the owner of a trading-education business (Simply Options Academy). You will receive the business's monthly P&L data as JSON: per-month revenue streams (mentorship/coaching from closer-collected cash, YouTube/sponsorships, affiliate commissions, prop-firm payouts, other), team payroll by person, software costs by tool, and the annual revenue target.

Answer in plain conversational text (no markdown headers or tables — short paragraphs and simple "-" bullet lists are fine). Use round dollar figures like $38,100. Be direct and specific: name the people, tools, and months behind every number. Keep responses focused and brief; lead with the single most important takeaway.`;

app.post('/api/ai', authMiddleware, async (req, res) => {
  if (!AI_ENABLED) return res.status(503).json({ error: 'AI not configured. Add ANTHROPIC_API_KEY in Railway → Variables.' });
  const { mode, question } = req.body || {};
  try {
    const ctx = await buildAIContext();
    let task;
    if (mode === 'narrative') {
      const withData = ctx.monthly.filter(m => m.revenue > 0 || m.expenses > 0);
      const target = withData.length ? withData[withData.length - 1].month : ctx.today.slice(0, 7);
      task = `Write a two-paragraph narrative summary of ${target} for the owner. First paragraph: the headline — revenue, profit, and what drove them. Second paragraph: what changed vs. prior months, anything that needs attention, and pace vs. the annual target.`;
    } else if (mode === 'explain') {
      task = `Look at the most recent month with data and compare it to the trailing 3 months. Identify the 2-4 most notable changes (revenue streams up or down, expense lines that moved, new or removed team members or tools) and explain each in one sentence with the specific numbers and likely cause visible in the data. If nothing moved meaningfully, say so.`;
    } else {
      if (!question || !String(question).trim()) return res.status(400).json({ error: 'Question required' });
      task = `Answer the owner's question using the data: ${String(question).trim().slice(0, 500)}`;
    }
    const response = await anthropic.beta.messages.create({
      model: 'claude-opus-5',
      max_tokens: 16000,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      system: [
        { type: 'text', text: AI_SYSTEM },
        { type: 'text', text: 'BUSINESS DATA:\n' + JSON.stringify(ctx), cache_control: { type: 'ephemeral' } }
      ],
      messages: [{ role: 'user', content: task }]
    });
    if (response.stop_reason === 'refusal') {
      return res.json({ text: 'The AI declined this request. Try rephrasing your question.' });
    }
    const textBlock = response.content.find(b => b.type === 'text');
    res.json({ text: textBlock ? textBlock.text : '(no response)' });
  } catch (err) {
    if (err instanceof Anthropic.AuthenticationError) {
      return res.status(503).json({ error: 'ANTHROPIC_API_KEY is invalid — check it in Railway → Variables.' });
    }
    if (err instanceof Anthropic.RateLimitError) {
      return res.status(429).json({ error: 'AI rate limit hit — try again in a minute.' });
    }
    console.error('POST /api/ai error:', err);
    res.status(500).json({ error: 'AI request failed' });
  }
});

// ── Monday digest (Discord webhook and/or email) ──
function fmtUSD(n) { return '$' + Math.round(n).toLocaleString('en-US'); }

async function buildDigestData() {
  const state = await loadBusinessState();
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const [pay, com, exp] = await Promise.all([
    pool.query('SELECT COALESCE(SUM(amount),0)::float AS t, COUNT(*)::int AS n FROM payouts WHERE date >= $1', [weekAgo]),
    pool.query('SELECT COALESCE(SUM(amount),0)::float AS t, COUNT(*)::int AS n FROM commissions WHERE date >= $1', [weekAgo]),
    pool.query('SELECT COALESCE(SUM(amount),0)::float AS t, COUNT(*)::int AS n FROM expenses WHERE date >= $1', [weekAgo])
  ]);
  const ymNow = now.toISOString().slice(0, 7);
  const year = ymNow.slice(0, 4);
  const cur = state.monthly.find(m => m.ym === ymNow) || { revenue: 0, expenses: 0, profit: 0 };
  const ytdRows = state.monthly.filter(m => m.ym.startsWith(year));
  const ytdRev = ytdRows.reduce((s, m) => s + m.revenue, 0);
  const ytdProfit = ytdRows.reduce((s, m) => s + m.profit, 0);
  const pct = state.annualTarget > 0 ? Math.round((ytdRev / state.annualTarget) * 100) : 0;
  const monthsLeft = 12 - now.getMonth();
  const needPerMo = monthsLeft > 0 ? Math.max(0, state.annualTarget - ytdRev) / monthsLeft : 0;
  return {
    now, ymNow, year,
    week: { payouts: pay.rows[0], commissions: com.rows[0], expenses: exp.rows[0] },
    mtd: cur, ytdRev, ytdProfit, pct, needPerMo, monthsLeft, target: state.annualTarget
  };
}

function discordPayload(d) {
  const bar = (() => {
    const filled = Math.max(0, Math.min(10, Math.round(d.pct / 10)));
    return '█'.repeat(filled) + '░'.repeat(10 - filled);
  })();
  return {
    username: 'SOA Tracker',
    embeds: [{
      title: '📊 Weekly Digest — ' + d.now.toDateString(),
      color: 0xC8A96E,
      fields: [
        {
          name: '💰 Funded tracker (last 7 days)', inline: false,
          value: `Payouts: **${fmtUSD(d.week.payouts.t)}** (${d.week.payouts.n})\nCommissions: **${fmtUSD(d.week.commissions.t)}** (${d.week.commissions.n})\nExpenses: **${fmtUSD(d.week.expenses.t)}** (${d.week.expenses.n})`
        },
        {
          name: '🏢 Business — ' + d.ymNow, inline: false,
          value: `Revenue: **${fmtUSD(d.mtd.revenue)}**\nExpenses: **${fmtUSD(d.mtd.expenses)}**\nNet profit: **${fmtUSD(d.mtd.profit)}**`
        },
        {
          name: `🎯 ${d.year} target — ${fmtUSD(d.target)}`, inline: false,
          value: `\`${bar}\` **${d.pct}%**\nYTD revenue: **${fmtUSD(d.ytdRev)}** · YTD profit: **${fmtUSD(d.ytdProfit)}**\nNeed **${fmtUSD(d.needPerMo)}/mo** for the remaining ${d.monthsLeft} month${d.monthsLeft === 1 ? '' : 's'}`
        }
      ],
      footer: { text: 'Sent every Monday 8am ET by your tracker' }
    }]
  };
}

function digestHTML(d) {
  const row = (l, v) => `<tr><td style="padding:6px 12px 6px 0;color:#666">${l}</td><td style="padding:6px 0;font-weight:600;text-align:right">${v}</td></tr>`;
  return `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:0 auto;color:#1a1a1a">
    <h2 style="margin:0 0 4px">SOA Weekly Digest</h2>
    <p style="color:#888;margin:0 0 20px">${d.now.toDateString()}</p>
    <h3 style="margin:0 0 8px;border-bottom:1px solid #eee;padding-bottom:6px">Funded tracker — last 7 days</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      ${row('Payouts', fmtUSD(d.week.payouts.t) + ` (${d.week.payouts.n})`)}
      ${row('Commissions', fmtUSD(d.week.commissions.t) + ` (${d.week.commissions.n})`)}
      ${row('Expenses', fmtUSD(d.week.expenses.t) + ` (${d.week.expenses.n})`)}
    </table>
    <h3 style="margin:0 0 8px;border-bottom:1px solid #eee;padding-bottom:6px">Business — ${d.ymNow}</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      ${row('Revenue (MTD)', fmtUSD(d.mtd.revenue))}
      ${row('Expenses (MTD)', fmtUSD(d.mtd.expenses))}
      ${row('Net profit (MTD)', fmtUSD(d.mtd.profit))}
    </table>
    <h3 style="margin:0 0 8px;border-bottom:1px solid #eee;padding-bottom:6px">${d.year} vs target</h3>
    <table style="width:100%;border-collapse:collapse;margin-bottom:8px">
      ${row('YTD revenue', `${fmtUSD(d.ytdRev)} (${d.pct}% of ${fmtUSD(d.target)})`)}
      ${row('YTD net profit', fmtUSD(d.ytdProfit))}
      ${row('Needed per remaining month', fmtUSD(d.needPerMo))}
    </table>
    <p style="color:#bbb;font-size:12px">Sent automatically every Monday morning by your tracker.</p>
  </div>`;
}

async function sendDigest() {
  const webhook = await getSetting('discordWebhook');
  const channels = [];
  if (!webhook && !EMAIL_ENABLED) return { error: 'No digest channel configured — add a Discord webhook in Settings.' };
  const d = await buildDigestData();
  if (webhook && DISCORD_WEBHOOK_RE.test(webhook)) {
    const resp = await fetch(webhook, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(discordPayload(d))
    });
    if (resp.ok || resp.status === 204) channels.push('discord');
    else {
      const body = await resp.text();
      console.error('Discord digest failed:', resp.status, body.slice(0, 300));
      return { error: 'Discord rejected the webhook (' + resp.status + ') — re-check the URL in Settings.' };
    }
  }
  if (EMAIL_ENABLED) {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: DIGEST_FROM, to: [DIGEST_TO], subject: 'SOA Weekly Digest — ' + d.now.toDateString(), html: digestHTML(d) })
    });
    if (resp.ok) channels.push('email');
    else console.error('Email digest failed:', resp.status, await resp.text());
  }
  console.log('Digest sent via:', channels.join(', ') || 'nothing');
  return channels.length ? { ok: true, channels } : { error: 'Digest could not be delivered' };
}

app.post('/api/digest/test', authMiddleware, async (req, res) => {
  try { res.json(await sendDigest()); }
  catch (err) { console.error('Digest test error:', err); res.status(500).json({ error: 'Digest failed' }); }
});

function digestTick() {
  const parts = {};
  new Intl.DateTimeFormat('en-US', { timeZone: DIGEST_TZ, weekday: 'short', hour: 'numeric', hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit' })
    .formatToParts(new Date()).forEach(p => { parts[p.type] = p.value; });
  if (parts.weekday !== 'Mon' || parseInt(parts.hour) !== 8) return;
  const todayKey = `${parts.year}-${parts.month}-${parts.day}`;
  getSetting('digestLastSent').then(async last => {
    if (last === todayKey) return;
    const webhook = await getSetting('discordWebhook');
    if (!webhook && !EMAIL_ENABLED) return;
    await setSetting('digestLastSent', todayKey);
    return sendDigest();
  }).catch(err => console.error('Digest tick error:', err));
}

// Serve static files. HTML gets no-cache so deploys are visible on a normal
// refresh (the browser still uses ETag revalidation to skip the body when
// unchanged). Other assets keep default caching.
app.use(express.static(path.join(__dirname, 'site'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'site', 'index.html'));
});

// Start
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Funded Tracker running on port ${PORT}`);
    console.log(`AI: ${AI_ENABLED ? 'enabled' : 'disabled (set ANTHROPIC_API_KEY)'} · Email digest: ${EMAIL_ENABLED ? 'enabled' : 'off'} · Discord digest: configured in Settings`);
  });
  // Sheet re-sync every 30 min (only does work once a sheet is configured)
  setTimeout(() => { syncSheet().catch(() => {}); }, 10_000);
  setInterval(() => { syncSheet().catch(() => {}); }, 30 * 60 * 1000);
  // Monday-morning digest check
  setInterval(digestTick, 60 * 1000);
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
