CREATE TABLE IF NOT EXISTS staff (
  id          UUID PRIMARY KEY,
  name        TEXT NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('admin','staff')),
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  salt        TEXT NOT NULL,
  hash        TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS staff_name_ci ON staff (lower(name));

CREATE TABLE IF NOT EXISTS handovers (
  id               UUID PRIMARY KEY,
  revision         INTEGER NOT NULL DEFAULT 1,
  date             TEXT NOT NULL,
  shift            TEXT NOT NULL,
  outgoing         TEXT NOT NULL,
  incoming         TEXT NOT NULL DEFAULT '',
  priority         TEXT NOT NULL DEFAULT 'Normal',
  title            TEXT NOT NULL DEFAULT '',
  notes            TEXT NOT NULL DEFAULT '',
  decisions        TEXT NOT NULL DEFAULT '',
  incidents        TEXT NOT NULL DEFAULT '',
  actions          TEXT NOT NULL DEFAULT '',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by       UUID,
  created_by_name  TEXT NOT NULL,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by       UUID,
  updated_by_name  TEXT NOT NULL,
  history          JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS handovers_updated_idx ON handovers (updated_at DESC);

CREATE TABLE IF NOT EXISTS audit (
  id          UUID PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id    TEXT NOT NULL,
  actor_name  TEXT NOT NULL,
  action      TEXT NOT NULL,
  record_id   TEXT NOT NULL DEFAULT '',
  details     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit (ts DESC);
