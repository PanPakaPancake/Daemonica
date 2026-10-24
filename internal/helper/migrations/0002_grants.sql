-- Persisted sessions (grants). Only the SHA-256 hash of the token is stored.
CREATE TABLE grants (
  hash          TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role          TEXT NOT NULL,
  linux_user    TEXT NOT NULL,
  linux_uid     INTEGER NOT NULL CHECK (linux_uid > 0),
  created_at    TEXT NOT NULL,
  last_used_at  TEXT NOT NULL,
  step_up_until TEXT NOT NULL DEFAULT '',
  source_ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX grants_account ON grants(account_id);
