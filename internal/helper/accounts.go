package helper

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Errors of the account repository.
var (
	ErrNotFound      = errors.New("not found")
	ErrLastPasskey   = errors.New("refusing to remove the last passkey")
	ErrLastAdmin     = errors.New("refusing to remove or demote the last active admin")
	ErrDuplicateName = errors.New("account name already exists")
)

// Account is a dashboard account.
type Account struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Role       policy.Role `json:"role"`
	LinuxUser  string      `json:"linux_user"`
	LinuxUID   uint32      `json:"linux_uid"`
	WebAuthnID []byte      `json:"-"`
	Disabled   bool        `json:"disabled"`
	CreatedAt  time.Time   `json:"created_at"`
	Passkeys   int         `json:"passkeys"`
}

// Passkey is the public view of a stored credential.
type Passkey struct {
	ID             string     `json:"id"` // hex of the credential ID
	Name           string     `json:"name"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"` // true = synced passkey
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	credential     []byte
	accountID      string
}

// DB wraps the helper's accounts.db.
type DB struct{ sql *sql.DB }

// OpenDB opens /var/lib/daemonia-helper/accounts.db (root 0600) and migrates it.
func OpenDB(ctx context.Context, path string) (*DB, error) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	db, err := store.Open(ctx, path, sub)
	if err != nil {
		return nil, err
	}
	return &DB{sql: db}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// CreateAccount inserts an account. The caller has validated the Linux user.
// handle is the WebAuthn user handle; nil generates a random 32-byte handle.
func (d *DB) CreateAccount(ctx context.Context, name string, role policy.Role, linuxUser string, uid uint32, handle []byte, now time.Time) (Account, error) {
	if uid == 0 || !policy.ValidRole(role) {
		return Account{}, errors.New("invalid account")
	}
	wid := handle
	if wid == nil {
		wid = make([]byte, 32)
		if _, err := rand.Read(wid); err != nil {
			return Account{}, err
		}
	}
	a := Account{ID: randomHex(12), Name: name, Role: role, LinuxUser: linuxUser, LinuxUID: uid, WebAuthnID: wid, CreatedAt: now.UTC()}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO accounts(id,name,role,linux_user,linux_uid,webauthn_id,created_at) VALUES(?,?,?,?,?,?,?)`,
		a.ID, a.Name, string(a.Role), a.LinuxUser, a.LinuxUID, a.WebAuthnID, ts(now))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return Account{}, ErrDuplicateName
	}
	return a, err
}

const accountCols = `a.id,a.name,a.role,a.linux_user,a.linux_uid,a.webauthn_id,a.disabled,a.created_at,
 (SELECT COUNT(*) FROM passkeys p WHERE p.account_id=a.id)`

func scanAccount(row interface{ Scan(...any) error }) (Account, error) {
	var a Account
	var role, created string
	var disabled int
	if err := row.Scan(&a.ID, &a.Name, &role, &a.LinuxUser, &a.LinuxUID, &a.WebAuthnID, &disabled, &created, &a.Passkeys); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return a, ErrNotFound
		}
		return a, err
	}
	a.Role, a.Disabled, a.CreatedAt = policy.Role(role), disabled != 0, parseTS(created)
	return a, nil
}

// AccountByID loads an account.
func (d *DB) AccountByID(ctx context.Context, id string) (Account, error) {
	return scanAccount(d.sql.QueryRowContext(ctx, `SELECT `+accountCols+` FROM accounts a WHERE a.id=?`, id))
}

// AccountByName loads an account by its name.
func (d *DB) AccountByName(ctx context.Context, name string) (Account, error) {
	return scanAccount(d.sql.QueryRowContext(ctx, `SELECT `+accountCols+` FROM accounts a WHERE a.name=?`, name))
}

// AccountByWebAuthnID loads an account by its WebAuthn user handle.
func (d *DB) AccountByWebAuthnID(ctx context.Context, wid []byte) (Account, error) {
	return scanAccount(d.sql.QueryRowContext(ctx, `SELECT `+accountCols+` FROM accounts a WHERE a.webauthn_id=?`, wid))
}

// ListAccounts returns all accounts.
func (d *DB) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+accountCols+` FROM accounts a ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountAccounts returns the number of accounts.
func (d *DB) CountAccounts(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts`).Scan(&n)
	return n, err
}

// AddPasskey stores a new credential for an account.
func (d *DB) AddPasskey(ctx context.Context, accountID, name string, credID, credJSON []byte, be, bs bool, now time.Time) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO passkeys(credential_id,account_id,name,credential,backup_eligible,backup_state,created_at) VALUES(?,?,?,?,?,?,?)`,
		credID, accountID, name, credJSON, b2i(be), b2i(bs), ts(now))
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Passkeys lists the credentials of an account (including raw credential JSON for verification).
func (d *DB) Passkeys(ctx context.Context, accountID string) ([]Passkey, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT credential_id,name,credential,backup_eligible,backup_state,created_at,last_used_at FROM passkeys WHERE account_id=? ORDER BY created_at`, accountID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var id []byte
		var be, bs int
		var created string
		var last sql.NullString
		if err := rows.Scan(&id, &p.Name, &p.credential, &be, &bs, &created, &last); err != nil {
			return nil, err
		}
		p.ID, p.BackupEligible, p.BackupState, p.CreatedAt, p.accountID = hex.EncodeToString(id), be != 0, bs != 0, parseTS(created), accountID
		if last.Valid {
			t := parseTS(last.String)
			p.LastUsedAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePasskeyAfterUse stores the updated credential (sign counter, flags) and last-use time.
func (d *DB) UpdatePasskeyAfterUse(ctx context.Context, credID, credJSON []byte, bs bool, now time.Time) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE passkeys SET credential=?, backup_state=?, last_used_at=? WHERE credential_id=?`, credJSON, b2i(bs), ts(now), credID)
	return err
}

// RenamePasskey changes the label of a passkey owned by accountID.
func (d *DB) RenamePasskey(ctx context.Context, accountID, idHex, name string) error {
	id, err := hex.DecodeString(idHex)
	if err != nil {
		return ErrNotFound
	}
	res, err := d.sql.ExecContext(ctx, `UPDATE passkeys SET name=? WHERE credential_id=? AND account_id=?`, name, id, accountID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemovePasskey deletes a passkey but never the last one of an account (SPEC §3.3).
func (d *DB) RemovePasskey(ctx context.Context, accountID, idHex string) error {
	id, err := hex.DecodeString(idHex)
	if err != nil {
		return ErrNotFound
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkeys WHERE account_id=?`, accountID).Scan(&n); err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastPasskey
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM passkeys WHERE credential_id=? AND account_id=?`, id, accountID)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// RemoveAllPasskeys deletes every passkey of an account (recovery with --revoke-all).
func (d *DB) RemoveAllPasskeys(ctx context.Context, accountID string) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM passkeys WHERE account_id=?`, accountID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- persistent one-time token store (implements auth.TokenStore) ---

// TokenStore returns a persistent auth.TokenStore backed by the tokens table.
func (d *DB) TokenStore() auth.TokenStore { return &dbTokens{d: d} }

type dbTokens struct{ d *DB }

func (t *dbTokens) Put(tok auth.OneTimeToken) error {
	meta, _ := json.Marshal(tok.Meta)
	_, err := t.d.sql.Exec(`INSERT INTO tokens(hash,purpose,subject,expires_at,used,meta) VALUES(?,?,?,?,0,?)`,
		tok.Hash, tok.Purpose, tok.Subject, ts(tok.ExpiresAt), string(meta))
	return err
}

func (t *dbTokens) lookup(tx *sql.Tx, purpose, presented string, now time.Time) (auth.OneTimeToken, error) {
	if !strings.HasPrefix(presented, "dmn_"+purpose+"_") || len(presented) > 128 {
		return auth.OneTimeToken{}, auth.ErrTokenInvalid
	}
	h := auth.Hash(presented)
	var o auth.OneTimeToken
	var exp, meta, stored string
	var used int
	err := tx.QueryRow(`SELECT hash,purpose,subject,expires_at,used,meta FROM tokens WHERE hash=?`, h).Scan(&stored, &o.Purpose, &o.Subject, &exp, &used, &meta)
	if err != nil || subtle.ConstantTimeCompare([]byte(stored), []byte(h)) != 1 {
		return o, auth.ErrTokenInvalid
	}
	o.Hash, o.ExpiresAt, o.Used = stored, parseTS(exp), used != 0
	_ = json.Unmarshal([]byte(meta), &o.Meta)
	if o.Purpose != purpose || o.Used || !now.Before(o.ExpiresAt) {
		return o, auth.ErrTokenInvalid
	}
	return o, nil
}

func (t *dbTokens) Consume(purpose, presented string, now time.Time) (auth.OneTimeToken, error) {
	tx, err := t.d.sql.Begin()
	if err != nil {
		return auth.OneTimeToken{}, err
	}
	defer func() { _ = tx.Rollback() }()
	o, err := t.lookup(tx, purpose, presented, now)
	if err != nil {
		return o, err
	}
	if _, err := tx.Exec(`UPDATE tokens SET used=1 WHERE hash=? AND used=0`, o.Hash); err != nil {
		return o, err
	}
	o.Used = true
	return o, tx.Commit()
}

func (t *dbTokens) Peek(purpose, presented string, now time.Time) (auth.OneTimeToken, error) {
	tx, err := t.d.sql.Begin()
	if err != nil {
		return auth.OneTimeToken{}, err
	}
	defer func() { _ = tx.Rollback() }()
	return t.lookup(tx, purpose, presented, now)
}

func (t *dbTokens) RevokePurpose(purpose, subject string) error {
	if subject == "" {
		_, err := t.d.sql.Exec(`UPDATE tokens SET used=1 WHERE purpose=?`, purpose)
		return err
	}
	_, err := t.d.sql.Exec(`UPDATE tokens SET used=1 WHERE purpose=? AND subject=?`, purpose, subject)
	return err
}

// --- grant persistence (implements GrantPersistence) ---

// SaveGrant inserts or replaces a grant record.
func (d *DB) SaveGrant(r GrantRecord) error {
	su := ""
	if !r.StepUpUntil.IsZero() {
		su = ts(r.StepUpUntil)
	}
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO grants(hash,account_id,role,linux_user,linux_uid,created_at,last_used_at,step_up_until,source_ip) VALUES(?,?,?,?,?,?,?,?,?)`,
		r.Hash, r.Subject.AccountID, string(r.Subject.Role), r.Subject.LinuxUser, r.Subject.LinuxUID, ts(r.Created), ts(r.LastUsed), su, r.SourceIP)
	return err
}

// DeleteGrant removes one grant.
func (d *DB) DeleteGrant(hash string) error {
	_, err := d.sql.Exec(`DELETE FROM grants WHERE hash=?`, hash)
	return err
}

// DeleteAccountGrants removes all grants of an account.
func (d *DB) DeleteAccountGrants(accountID string) error {
	_, err := d.sql.Exec(`DELETE FROM grants WHERE account_id=?`, accountID)
	return err
}

// TouchGrant updates the last-use time.
func (d *DB) TouchGrant(hash string, lastUsed time.Time) error {
	_, err := d.sql.Exec(`UPDATE grants SET last_used_at=? WHERE hash=?`, ts(lastUsed), hash)
	return err
}

// LoadGrants returns all stored grants of enabled accounts.
func (d *DB) LoadGrants() ([]GrantRecord, error) {
	rows, err := d.sql.Query(`SELECT g.hash,g.account_id,g.role,g.linux_user,g.linux_uid,g.created_at,g.last_used_at,g.step_up_until,g.source_ip
	 FROM grants g JOIN accounts a ON a.id=g.account_id WHERE a.disabled=0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []GrantRecord
	for rows.Next() {
		var r GrantRecord
		var role, created, last, su string
		if err := rows.Scan(&r.Hash, &r.Subject.AccountID, &role, &r.Subject.LinuxUser, &r.Subject.LinuxUID, &created, &last, &su, &r.SourceIP); err != nil {
			return nil, err
		}
		r.Subject.Role, r.Created, r.LastUsed = policy.Role(role), parseTS(created), parseTS(last)
		if su != "" {
			r.StepUpUntil = parseTS(su)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
