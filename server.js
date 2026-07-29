const express = require('express');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;
const TRACKER_PASSWORD = process.env.TRACKER_PASSWORD || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

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
    // Seed March 2026 data if business_months is empty
    const count = await client.query('SELECT COUNT(*) FROM business_months');
    if (parseInt(count.rows[0].count) === 0) {
      await client.query(
        "INSERT INTO business_months (key, data) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        ['2026-03', JSON.stringify({
          rev: [41069, 2029.28, 0, 11686],
          team: [
            {name:'Jesus',role:'Closer',amount:2085},
            {name:'Zain',role:'Closer',amount:1237},
            {name:'Keshawn',role:'Setter',amount:4482.75},
            {name:'Shayan',role:'COO',amount:2074},
            {name:'Bryce and Demon',role:'Role',amount:500}
          ],
          soft: [
            {name:'YouTube tools',amount:39},
            {name:'CRM / sales',amount:100},
            {name:'Claude / AI',amount:192.57},
            {name:'Notion',amount:12.79},
            {name:'Sim2Funded',amount:29},
            {name:'Typeform',amount:137.51},
            {name:'Kit',amount:94.7},
            {name:'manychat',amount:101.27},
            {name:'Sendblue',amount:772},
            {name:'Quickbooks',amount:100}
          ]
        })]
      );
      console.log('Seeded March 2026 business data');
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
app.get('/api/data', authMiddleware, async (req, res) => {
  try {
    const [payouts, expenses, accounts, commissions] = await Promise.all([
      pool.query('SELECT id, amount::float, date, firm, account, notes FROM payouts ORDER BY date DESC'),
      pool.query('SELECT id, amount::float, date, type, firm, notes FROM expenses ORDER BY date DESC'),
      pool.query('SELECT id, name, firm, size, status, start_date AS "startDate", notes FROM accounts ORDER BY name'),
      pool.query('SELECT id, amount::float, date, source, notes FROM commissions ORDER BY date DESC')
    ]);
    res.json({
      payouts: payouts.rows,
      expenses: expenses.rows,
      accounts: accounts.rows,
      commissions: commissions.rows
    });
  } catch (err) {
    console.error('GET /api/data error:', err);
    res.status(500).json({ error: 'Database error' });
  }
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
    const [monthsRes, payoutsSync, commissionsSync] = await Promise.all([
      pool.query('SELECT key, data FROM business_months ORDER BY key'),
      pool.query("SELECT substr(date,1,7) AS ym, SUM(amount)::float AS total FROM payouts WHERE date IS NOT NULL AND date <> '' GROUP BY ym"),
      pool.query("SELECT substr(date,1,7) AS ym, SUM(amount)::float AS total FROM commissions WHERE date IS NOT NULL AND date <> '' GROUP BY ym")
    ]);
    const months = {};
    monthsRes.rows.forEach(r => { months[r.key] = r.data; });
    const sync = {};
    payoutsSync.rows.forEach(r => { if (!sync[r.ym]) sync[r.ym] = { payouts: 0, commissions: 0 }; sync[r.ym].payouts = r.total; });
    commissionsSync.rows.forEach(r => { if (!sync[r.ym]) sync[r.ym] = { payouts: 0, commissions: 0 }; sync[r.ym].commissions = r.total; });
    res.json({ months, sync });
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
  });
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
