// Package audit implements the helper's authoritative, tamper-evident audit
// log (SPEC §3.8, Annex C): JSON Lines with a SHA-256 hash chain.
//
// Each record's hash is SHA-256 over its canonical JSON encoding with the
// "hash" field empty; prev_hash links to the previous record. The first
// record of a fresh log links to GenesisHash. Rotation continues the chain:
// the first record of a new file carries the last hash of the previous file.
package audit

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// GenesisHash anchors a new chain.
const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Actor identifies who performed an action.
type Actor struct {
	AccountID string `json:"account_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Role      string `json:"role,omitempty"`
	LinuxUser string `json:"linux_user,omitempty"`
}

// Event is one audit record (Annex C). Params MUST be filled from a
// per-action allowlist and never contain secrets, file contents or terminal input.
type Event struct {
	TS       string            `json:"ts"`
	EventID  string            `json:"event_id"`
	Actor    Actor             `json:"actor"`
	SourceIP string            `json:"source_ip,omitempty"`
	Session  string            `json:"session,omitempty"`
	Action   string            `json:"action"`
	Target   string            `json:"target,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
	StepUp   bool              `json:"step_up"`
	Result   string            `json:"result"`
	Reason   string            `json:"reason,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Result values.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Logger appends events to a file, maintaining the hash chain.
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	path string
	last string
	now  func() time.Time
	// MaxSize starts a new file once the current one reaches it (0: never);
	// Keep is the number of rotated files kept (audit.log.1 … audit.log.Keep).
	MaxSize int64
	Keep    int
	// AppendOnly is set by EnableAppendOnly.
	AppendOnly bool
	// Mirror receives each serialized line (e.g. journald). Optional.
	Mirror func(line []byte)
}

// Open opens (or creates) the log at path with mode 0640 and resumes the chain
// from its last record. If the existing file is empty, prevHash is used as the
// chain anchor (GenesisHash, or the last hash of a rotated predecessor).
func Open(path, prevHash string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o640) //nolint:gosec // fixed path from config
	if err != nil {
		return nil, err
	}
	last, err := lastHash(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if last == "" {
		last = prevHash
		if last == "" {
			last = GenesisHash
		}
	}
	return &Logger{f: f, path: path, last: last, now: time.Now, MaxSize: DefaultMaxSize, Keep: DefaultKeep}, nil
}

// EnableAppendOnly sets "chattr +a" on the log and keeps it on rotated files
// (SPEC §3.8 SOLL). It needs CAP_LINUX_IMMUTABLE and a file system with the
// flag; on failure the log works as before and the error says why.
func (l *Logger) EnableAppendOnly() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := setAppendOnly(l.f, true); err != nil {
		return err
	}
	l.AppendOnly = true
	return nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// LastHash returns the current chain head.
func (l *Logger) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Append completes ev (timestamp, id, chain fields), writes and fsyncs it.
func (l *Logger) Append(ev Event) (Event, error) {
	if ev.Action == "" || ev.Result == "" {
		return ev, errors.New("audit: action and result are required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now().UTC()
	ev.TS = t.Format("2006-01-02T15:04:05.000Z07:00")
	ev.EventID = newULID(t)
	ev.Reason = sanitize(ev.Reason)
	ev.Target = sanitize(ev.Target)
	for k, v := range ev.Params {
		ev.Params[k] = sanitize(v)
	}
	ev.PrevHash = l.last
	h, err := hashEvent(ev)
	if err != nil {
		return ev, err
	}
	ev.Hash = h
	line, err := json.Marshal(ev)
	if err != nil {
		return ev, err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return ev, err
	}
	if err := l.f.Sync(); err != nil {
		return ev, err
	}
	l.last = h
	if l.Mirror != nil {
		l.Mirror(line[:len(line)-1])
	}
	if l.MaxSize > 0 {
		if fi, err := l.f.Stat(); err == nil && fi.Size() >= l.MaxSize {
			// The record is written; a failed rotation is retried on the next one.
			_ = l.rotate()
		}
	}
	return ev, nil
}

// sanitize strips control characters so a record cannot forge extra log lines
// or terminal escape sequences when displayed.
func sanitize(s string) string {
	if len(s) > 1024 {
		s = s[:1024]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

func hashEvent(ev Event) (string, error) {
	ev.Hash = ""
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func lastHash(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var last string
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return "", fmt.Errorf("audit: corrupt record: %w", err)
		}
		last = ev.Hash
	}
	return last, sc.Err()
}

// VerifyResult describes the outcome of a chain verification.
type VerifyResult struct {
	Records  int    `json:"records"`
	OK       bool   `json:"ok"`
	BadLine  int    `json:"bad_line,omitempty"`
	Problem  string `json:"problem,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
	// VerifyAll only: number of files, the file with the problem (BadLine
	// counts within it), and the accepted anchor of the oldest retained file.
	Files  int    `json:"files,omitempty"`
	File   string `json:"file,omitempty"`
	Anchor string `json:"anchor,omitempty"`
}

// Verify checks the chain in r, starting from anchor (GenesisHash or the last
// hash of the preceding rotated file).
func Verify(r io.Reader, anchor string) VerifyResult {
	if anchor == "" {
		anchor = GenesisHash
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	prev := anchor
	n := 0
	for sc.Scan() {
		n++
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return VerifyResult{Records: n - 1, BadLine: n, Problem: "unparseable record"}
		}
		if ev.PrevHash != prev {
			return VerifyResult{Records: n - 1, BadLine: n, Problem: "prev_hash does not match previous record"}
		}
		h, err := hashEvent(ev)
		if err != nil || h != ev.Hash {
			return VerifyResult{Records: n - 1, BadLine: n, Problem: "record hash mismatch (modified record)"}
		}
		prev = ev.Hash
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{Records: n, Problem: err.Error()}
	}
	return VerifyResult{Records: n, OK: true, LastHash: prev}
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULID returns a ULID (48-bit ms timestamp + 80 bits randomness).
func newULID(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli()) //nolint:gosec // time after epoch
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(b[:6], ts[2:])
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	// Encode 128 bits as 26 Crockford base32 chars.
	var out [26]byte
	var acc uint64
	var bits uint
	idx := 0
	// Leading 2 bits padding so 130 bits → 26 chars.
	acc = 0
	bits = 2
	for _, by := range b {
		acc = acc<<8 | uint64(by)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[idx] = crockford[(acc>>bits)&31]
			idx++
		}
	}
	return string(out[:idx])
}
