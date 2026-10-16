// Single serverless endpoint: POST /api  { action, ...params }
// Storage: Postgres (DATABASE_URL / POSTGRES_URL). Sessions: signed tokens (SESSION_SECRET).
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const SHIFTS = ['Day', 'Evening', 'Night', 'Other'];
const PRIORITIES = ['Low', 'Normal', 'High', 'Critical'];
const FIELDS = ['date', 'shift', 'outgoing', 'incoming', 'priority', 'title', 'notes', 'decisions', 'incidents', 'actions'];
const MAX_TEXT = 20000;
const SESSION_HOURS = 12;

let pool;
let schemaReady;

function getPool() {
  if (!pool) {
    const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    if (!url) throw httpError(503, 'Database not configured. Set DATABASE_URL in your environment.');
    pool = new Pool({ connectionString: url, max: 3, idleTimeoutMillis: 10000 });
  }
  return pool;
}

function ensureSchema() {
  if (!schemaReady) {
    const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
    schemaReady = getPool().query(sql).catch(e => { schemaReady = null; throw e; });
  }
  return schemaReady;
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// ---------- auth ----------
const b64 = buf => Buffer.from(buf).toString('base64url');

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) throw httpError(503, 'SESSION_SECRET is not set (min 16 characters).');
  return s;
}

function sign(payload) {
  const body = b64(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return body + '.' + sig;
}

function verify(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

function hashPin(pin, salt) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(pin, salt, 64, (err, key) => (err ? reject(err) : resolve(key.toString('hex')))));
}

async function newCredentials(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: await hashPin(pin, salt) };
}

async function requireUser(req, db) {
  const header = req.headers.authorization || '';
  const p = verify(header.startsWith('Bearer ') ? header.slice(7) : '');
  if (!p) throw httpError(401, 'Session expired. Please sign in again.');
  // Re-check against the database so deactivated staff lose access immediately.
  const { rows } = await db.query('SELECT id, name, role, active FROM staff WHERE id = $1', [p.id]);
  if (!rows[0] || !rows[0].active) throw httpError(401, 'Account is inactive.');
  return { id: rows[0].id, name: rows[0].name, role: rows[0].role };
}

function requireAdmin(user) {
  if (user.role !== 'admin') throw httpError(403, 'Administrator access required.');
}

// ---------- helpers ----------
const uuid = () => crypto.randomUUID();

function mapHandover(r) {
  return {
    id: r.id, revision: r.revision,
    date: r.date, shift: r.shift, outgoing: r.outgoing, incoming: r.incoming,
    priority: r.priority, title: r.title, notes: r.notes, decisions: r.decisions,
    incidents: r.incidents, actions: r.actions,
    createdAt: new Date(r.created_at).toISOString(), createdBy: r.created_by, createdByName: r.created_by_name,
    updatedAt: new Date(r.updated_at).toISOString(), updatedBy: r.updated_by, updatedByName: r.updated_by_name,
    history: r.history,
  };
}

async function audit(db, user, action, recordId = '', details = {}) {
  await db.query(
    'INSERT INTO audit (id, actor_id, actor_name, action, record_id, details) VALUES ($1,$2,$3,$4,$5,$6)',
    [uuid(), user?.id || 'setup', user?.name || 'Setup', action, recordId, JSON.stringify(details)]
  );
}

function cleanFields(input) {
  const f = {};
  for (const k of FIELDS) {
    const v = input?.[k];
    f[k] = typeof v === 'string' ? v.trim().slice(0, MAX_TEXT) : '';
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(f.date)) throw httpError(400, 'A valid date is required.');
  if (!f.outgoing) throw httpError(400, 'Outgoing staff is required.');
  if (!SHIFTS.includes(f.shift)) throw httpError(400, 'Invalid shift.');
  if (!PRIORITIES.includes(f.priority)) throw httpError(400, 'Invalid priority.');
  return f;
}

async function tx(fn) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- actions ----------
const publicActions = {
  async status(req, db, p) {
    const staff = await db.query('SELECT id, name FROM staff WHERE active ORDER BY lower(name)');
    const any = await db.query('SELECT 1 FROM staff LIMIT 1');
    return { needsSetup: any.rows.length === 0, staff: staff.rows };
  },

  async setup(req, db, p) {
    const name = String(p.name || '').trim().slice(0, 100);
    const pin = String(p.pin || '');
    if (!name || pin.length < 6) throw httpError(400, 'Enter a name and PIN of at least 6 characters.');
    await tx(async c => {
      await c.query('LOCK TABLE staff IN EXCLUSIVE MODE');
      const n = await c.query('SELECT 1 FROM staff LIMIT 1');
      if (n.rows.length) throw httpError(409, 'Setup has already been completed.');
      const { salt, hash } = await newCredentials(pin);
      const id = uuid();
      await c.query('INSERT INTO staff (id, name, role, salt, hash) VALUES ($1,$2,$3,$4,$5)', [id, name, 'admin', salt, hash]);
      await audit(c, { id, name }, 'setup_admin_created', id);
    });
    return { ok: true };
  },

  async login(req, db, p) {
    const staffId = String(p.staffId || '');
    const validId = /^[0-9a-f-]{36}$/i.test(staffId) ? staffId : '00000000-0000-0000-0000-000000000000';
    const { rows } = await db.query('SELECT * FROM staff WHERE id = $1 AND active', [validId]);
    const s = rows[0];
    const ok = s && crypto.timingSafeEqual(Buffer.from(await hashPin(String(p.pin || ''), s.salt)), Buffer.from(s.hash));
    if (!ok) { await sleep(500); throw httpError(401, 'Incorrect staff account or PIN.'); }
    const user = { id: s.id, name: s.name, role: s.role };
    await audit(db, user, 'login');
    return { token: sign({ id: s.id, exp: Date.now() + SESSION_HOURS * 3600 * 1000 }), user };
  },
};

const authedActions = {
  async me(req, db, p, user) { return { user }; },

  async list(req, db) {
    const { rows } = await db.query('SELECT * FROM handovers ORDER BY updated_at DESC');
    return { handovers: rows.map(mapHandover) };
  },

  async save(req, db, p, user) {
    const f = cleanFields(p.record);
    const id = p.record?.id;
    if (!id) {
      const newId = uuid();
      const history = [{ revision: 1, timestamp: new Date().toISOString(), actorId: user.id, actorName: user.name, action: 'created' }];
      await tx(async c => {
        await c.query(
          `INSERT INTO handovers (id, revision, date, shift, outgoing, incoming, priority, title, notes, decisions, incidents, actions,
             created_by, created_by_name, updated_by, updated_by_name, history)
           VALUES ($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$12,$13,$14)`,
          [newId, f.date, f.shift, f.outgoing, f.incoming, f.priority, f.title, f.notes, f.decisions, f.incidents, f.actions, user.id, user.name, JSON.stringify(history)]
        );
        await audit(c, user, 'handover_created', newId, { revision: 1 });
      });
      return { id: newId, revision: 1 };
    }
    return tx(async c => {
      const cur = (await c.query('SELECT * FROM handovers WHERE id = $1 FOR UPDATE', [id])).rows[0];
      if (!cur) throw httpError(404, 'Handover not found.');
      if (cur.revision !== p.expectedRevision) {
        throw httpError(409, 'Conflict detected: this record changed after you opened it. Reload and try again.');
      }
      const rev = cur.revision + 1;
      const history = [...cur.history, { revision: rev, timestamp: new Date().toISOString(), actorId: user.id, actorName: user.name, action: 'updated' }];
      await audit(c, user, 'snapshot', id, { previous: mapHandover(cur) });
      await c.query(
        `UPDATE handovers SET revision=$2, date=$3, shift=$4, outgoing=$5, incoming=$6, priority=$7, title=$8, notes=$9,
           decisions=$10, incidents=$11, actions=$12, updated_at=now(), updated_by=$13, updated_by_name=$14, history=$15 WHERE id=$1`,
        [id, rev, f.date, f.shift, f.outgoing, f.incoming, f.priority, f.title, f.notes, f.decisions, f.incidents, f.actions, user.id, user.name, JSON.stringify(history)]
      );
      await audit(c, user, 'handover_updated', id, { revision: rev });
      return { id, revision: rev };
    });
  },

  async staffList(req, db, p, user) {
    requireAdmin(user);
    const { rows } = await db.query('SELECT id, name, role, active, created_at FROM staff ORDER BY lower(name)');
    return { staff: rows.map(r => ({ id: r.id, name: r.name, role: r.role, active: r.active })) };
  },

  async addStaff(req, db, p, user) {
    requireAdmin(user);
    const name = String(p.name || '').trim().slice(0, 100);
    const pin = String(p.pin || '');
    const role = p.role === 'admin' ? 'admin' : 'staff';
    if (!name || pin.length < 6) throw httpError(400, 'Enter a name and PIN of at least 6 characters.');
    const { salt, hash } = await newCredentials(pin);
    const id = uuid();
    try {
      await db.query('INSERT INTO staff (id, name, role, salt, hash) VALUES ($1,$2,$3,$4,$5)', [id, name, role, salt, hash]);
    } catch (e) {
      if (e.code === '23505') throw httpError(409, 'That name already exists.');
      throw e;
    }
    await audit(db, user, 'staff_created', id, { name, role });
    return { ok: true };
  },

  async toggleStaff(req, db, p, user) {
    requireAdmin(user);
    if (p.id === user.id) throw httpError(400, 'You cannot change your own status.');
    const { rows } = await db.query('UPDATE staff SET active = NOT active WHERE id = $1 RETURNING name, active', [String(p.id || '')]);
    if (!rows[0]) throw httpError(404, 'Staff member not found.');
    await audit(db, user, 'staff_status_changed', String(p.id), rows[0]);
    return { ok: true };
  },

  async exportBackup(req, db, p, user) {
    requireAdmin(user);
    const [staff, handovers, aud] = await Promise.all([
      db.query('SELECT id, name, role, active, salt, hash, created_at FROM staff'),
      db.query('SELECT * FROM handovers ORDER BY created_at'),
      db.query('SELECT * FROM audit ORDER BY ts'),
    ]);
    await audit(db, user, 'backup_exported');
    return {
      format: 'team-handover-v2', exportedAt: new Date().toISOString(),
      staff: staff.rows.map(r => ({ id: r.id, name: r.name, role: r.role, active: r.active, salt: r.salt, hash: r.hash, createdAt: r.created_at })),
      handovers: handovers.rows.map(mapHandover),
      audit: aud.rows.map(r => ({ id: r.id, timestamp: r.ts, actorId: r.actor_id, actorName: r.actor_name, action: r.action, recordId: r.record_id, details: r.details })),
    };
  },

  async importBackup(req, db, p, user) {
    requireAdmin(user);
    const d = p.data;
    if (!d || !Array.isArray(d.staff) || !Array.isArray(d.handovers) || !Array.isArray(d.audit)) throw httpError(400, 'Invalid backup format.');
    if (!d.staff.some(s => s.role === 'admin' && s.active !== false)) throw httpError(400, 'Backup must contain an active administrator.');
    const isUuid = v => typeof v === 'string' && /^[0-9a-f-]{36}$/i.test(v);
    await tx(async c => {
      await c.query('TRUNCATE handovers, audit, staff');
      for (const s of d.staff) {
        if (!isUuid(s.id)) throw httpError(400, 'Backup contains an invalid staff id.');
        await c.query('INSERT INTO staff (id, name, role, active, salt, hash, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [s.id, s.name, s.role === 'admin' ? 'admin' : 'staff', s.active !== false, s.salt, s.hash, s.createdAt || new Date().toISOString()]);
      }
      for (const h of d.handovers) {
        if (!isUuid(h.id)) throw httpError(400, 'Backup contains an invalid handover id.');
        const f = cleanFields(h);
        await c.query(
          `INSERT INTO handovers (id, revision, date, shift, outgoing, incoming, priority, title, notes, decisions, incidents, actions,
             created_at, created_by, created_by_name, updated_at, updated_by, updated_by_name, history)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
          [h.id, Number(h.revision) || 1, f.date, f.shift, f.outgoing, f.incoming, f.priority, f.title, f.notes, f.decisions, f.incidents, f.actions,
           h.createdAt, isUuid(h.createdBy) ? h.createdBy : null, h.createdByName || '', h.updatedAt, isUuid(h.updatedBy) ? h.updatedBy : null,
           h.updatedByName || '', JSON.stringify(h.history || [])]);
      }
      for (const a of d.audit) {
        if (!isUuid(a.id)) continue;
        await c.query('INSERT INTO audit (id, ts, actor_id, actor_name, action, record_id, details) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [a.id, a.timestamp, String(a.actorId || ''), String(a.actorName || ''), String(a.action || ''), String(a.recordId || ''), JSON.stringify(a.details || {})]);
      }
      await audit(c, user, 'backup_imported');
    });
    return { ok: true };
  },
};

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const action = String(body.action || '');
    const db = getPool();
    await ensureSchema();
    if (Object.hasOwn(publicActions, action)) {
      return res.status(200).json(await publicActions[action](req, db, body));
    }
    if (Object.hasOwn(authedActions, action)) {
      const user = await requireUser(req, db);
      return res.status(200).json(await authedActions[action](req, db, body, user));
    }
    throw httpError(400, 'Unknown action.');
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    return res.status(status).json({ error: status === 500 ? 'Server error. Check the function logs.' : e.message });
  }
};
