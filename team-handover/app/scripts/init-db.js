// Optional: create tables manually.  Usage: DATABASE_URL=... npm run db:init
// (The API also creates them automatically on first request.)
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!url) { console.error('Set DATABASE_URL first.'); process.exit(1); }
const pool = new Pool({ connectionString: url });
pool.query(fs.readFileSync(path.join(__dirname, '../db/schema.sql'), 'utf8'))
  .then(() => { console.log('Schema ready.'); return pool.end(); })
  .catch(e => { console.error(e.message); process.exit(1); });
