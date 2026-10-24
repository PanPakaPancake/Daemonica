-- Helper-owned trust anchor (SPEC §3.2 rule 3): accounts, passkeys, one-time tokens.
CREATE TABLE accounts (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL CHECK (role IN ('admin','operator','readonly')),
  linux_user   TEXT NOT NULL,
  linux_uid    INTEGER NOT NULL CHECK (linux_uid > 0),
  webauthn_id  BLOB NOT NULL UNIQUE,
  disabled     INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL
);

CREATE TABLE passkeys (
  credential_id   BLOB PRIMARY KEY,
  account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  credential      BLOB NOT NULL,          -- JSON of webauthn.Credential (public key, counters, flags)
  backup_eligible INTEGER NOT NULL DEFAULT 0,
  backup_state    INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  last_used_at    TEXT
);
CREATE INDEX passkeys_account ON passkeys(account_id);

CREATE TABLE tokens (
  hash        TEXT PRIMARY KEY,           -- SHA-256 of the token; clear tokens are never stored
  purpose     TEXT NOT NULL,
  subject     TEXT NOT NULL DEFAULT '',
  expires_at  TEXT NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0,
  meta        TEXT NOT NULL DEFAULT '{}'
);
