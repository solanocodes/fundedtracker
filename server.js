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
    // Business tracker: store monthly data as JSON keyed by YYYY-MM
    await client.query(`
      CREATE TABLE IF NOT EXISTS business_months (
        key TEXT PRIMARY KEY,
        data JSONB NOT NULL
      )
    `);
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
    const [payouts, expenses, accounts] = await Promise.all([
      pool.query('SELECT id, amount::float, date, firm, account, notes FROM payouts ORDER BY date DESC'),
      pool.query('SELECT id, amount::float, date, type, firm, notes FROM expenses ORDER BY date DESC'),
      pool.query('SELECT id, name, firm, size, status, start_date AS "startDate", notes FROM accounts ORDER BY name')
    ]);
    res.json({
      payouts: payouts.rows,
      expenses: expenses.rows,
      accounts: accounts.rows
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
  const { payouts, expenses, accounts } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM payouts');
    await client.query('DELETE FROM expenses');
    await client.query('DELETE FROM accounts');
    for (const p of (payouts || [])) {
      await client.query('INSERT INTO payouts (id,amount,date,firm,account,notes) VALUES ($1,$2,$3,$4,$5,$6)', [p.id, p.amount, p.date, p.firm, p.account, p.notes]);
    }
    for (const e of (expenses || [])) {
      await client.query('INSERT INTO expenses (id,amount,date,type,firm,notes) VALUES ($1,$2,$3,$4,$5,$6)', [e.id, e.amount, e.date, e.type, e.firm, e.notes]);
    }
    for (const a of (accounts || [])) {
      await client.query('INSERT INTO accounts (id,name,firm,size,status,start_date,notes) VALUES ($1,$2,$3,$4,$5,$6,$7)', [a.id, a.name, a.firm, a.size, a.status, a.startDate, a.notes]);
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
    const [payouts, expenses, accounts] = await Promise.all([
      pool.query('SELECT id, amount::float, date, firm, account, notes FROM payouts'),
      pool.query('SELECT id, amount::float, date, type, firm, notes FROM expenses'),
      pool.query('SELECT id, name, firm, size, status, start_date AS "startDate", notes FROM accounts')
    ]);
    res.json({ payouts: payouts.rows, expenses: expenses.rows, accounts: accounts.rows });
  } catch (err) {
    console.error('GET /api/export error:', err);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ── Business Tracker routes ──
app.get('/api/business/data', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT key, data FROM business_months ORDER BY key');
    const months = {};
    result.rows.forEach(r => { months[r.key] = r.data; });
    res.json({ months });
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

// Serve static files
app.use(express.static(path.join(__dirname, 'site')));
app.get('*', (req, res) => {
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
