package helper

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/pty"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// Web terminal limits (SPEC §7.5).
const (
	DefaultTerminalIdle = 15 // minutes without input
	MaxTerminals        = 5  // open terminals per account
	ElevatedTerminalTTL = 30 * time.Minute
	terminalCheck       = 2 * time.Second
	// Throughput limits against floods in either direction.
	terminalOutRate  = 4 << 20 // bytes/s towards the browser
	terminalOutBurst = 1 << 20
	terminalInRate   = 256 << 10 // bytes/s typed or pasted
	terminalInBurst  = 256 << 10
	terminalMaxIn    = 64 << 10 // largest input chunk
)

// Terminal stream protocol (after the ready frame, both directions use rpc
// chunks): client → helper chunks start with a type byte, 'd' followed by
// input bytes or 'r' followed by cols and rows as big-endian uint16; helper
// → client chunks are raw terminal output. The helper sends the end marker
// when the session ends and then the final response (TermEnd).

// TermParams are the inputs of pty.check and pty.open.
type TermParams struct {
	Mode pty.Mode `json:"mode"`
	Cols uint16   `json:"cols,omitempty"`
	Rows uint16   `json:"rows,omitempty"`
}

// TermInfo is the result of pty.check and the ready metadata of pty.open.
type TermInfo struct {
	ID          string    `json:"id,omitempty"`
	Mode        pty.Mode  `json:"mode"`
	User        string    `json:"user"`
	IdleMinutes int       `json:"idle_minutes"`
	Until       time.Time `json:"until,omitzero"` // end of an elevated session
}

// TermEnd is the final result of pty.open.
type TermEnd struct {
	Reason   string `json:"reason"` // exit, closed, idle, expired, session_ended, allowlist, shutdown
	ExitCode int    `json:"exit_code"`
}

// TermOps implements the web terminal (pty.check, pty.open).
type TermOps struct {
	Launcher pty.Launcher
	Grants   *GrantStore
	Config   *ConfigStore
	Audit    *audit.Logger
	Lookup   func(name string) (worker.Identity, error)
	Shell    func(name string) (string, error)
	// TasksMax and MemoryMax limit each terminal session (SOLL).
	TasksMax, MemoryMax uint64
	Now                 func() time.Time

	mu       sync.Mutex
	open     map[string]int       // account ID → open terminals
	consumed map[string]time.Time // session key → step-up already used for an elevated terminal
}

func (t *TermOps) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *TermOps) idle() time.Duration {
	m := t.Config.Get().TerminalIdleMinutes
	if m <= 0 {
		m = DefaultTerminalIdle
	}
	return time.Duration(m) * time.Minute
}

// prepare validates the request and resolves the shell to start. Elevated
// modes need a step-up that has not been used for another elevated terminal
// yet (step-up on every opening, D-09).
func (t *TermOps) prepare(c Call) (TermParams, pty.Spec, error) {
	var p TermParams
	if err := rpc.DecodeStrict(c.Params, &p); err != nil || !p.Mode.Valid() || p.Cols > pty.MaxCols || p.Rows > pty.MaxRows {
		return p, pty.Spec{}, Errf(rpc.CodeBadRequest, "invalid parameters")
	}
	c.AuditKV["mode"] = string(p.Mode)
	if p.Mode.Elevated() {
		switch policy.Decide(*c.Subject, policy.ActTerminalElevated, 0, false) {
		case policy.Deny:
			return p, pty.Spec{}, Errf(rpc.CodeForbidden, "")
		case policy.NeedStepUp:
			return p, pty.Spec{}, Errf(rpc.CodeStepUpNeeded, "")
		case policy.Allow:
		}
		t.mu.Lock()
		used := t.consumed[c.SessionKey]
		t.mu.Unlock()
		if su := t.Grants.StepUpUntil(c.Grant); su.IsZero() || su.Equal(used) {
			return p, pty.Spec{}, Errf(rpc.CodeStepUpNeeded, "")
		}
	}
	t.mu.Lock()
	n := t.open[c.Subject.AccountID]
	t.mu.Unlock()
	if n >= MaxTerminals {
		return p, pty.Spec{}, Errf("limit_exceeded", "too many terminals")
	}
	name := c.Subject.LinuxUser
	if p.Mode == pty.ModeRoot {
		name = "root"
	}
	id, err := t.Lookup(name)
	if err != nil || (id.UID == 0) != (p.Mode == pty.ModeRoot) {
		return p, pty.Spec{}, Errf(rpc.CodeValidation, "no such user")
	}
	shell, err := t.Shell(name)
	if err != nil {
		return p, pty.Spec{}, Errf("no_login_shell", "")
	}
	return p, pty.Spec{User: id, Shell: shell, NoNewPrivs: p.Mode == pty.ModeStandard, TasksMax: t.TasksMax, MemoryMax: t.MemoryMax}, nil
}

// Register installs the terminal operations.
func (t *TermOps) Register(ops map[string]*Op) {
	t.open = map[string]int{}
	t.consumed = map[string]time.Time{}

	Register(ops, &Op{Name: "pty.check", Action: policy.ActTerminal, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			p, spec, err := t.prepare(c)
			if err != nil {
				return nil, err
			}
			info := TermInfo{Mode: p.Mode, User: spec.User.Name, IdleMinutes: int(t.idle() / time.Minute)}
			if p.Mode.Elevated() {
				info.Until = t.now().Add(ElevatedTerminalTTL).UTC()
			}
			return info, nil
		}})

	Register(ops, &Op{Name: "pty.open", Action: policy.ActTerminal, Timeout: MaxAbsolute + time.Hour,
		AuditTarget: func(c Call) string { return c.AuditKV["user"] },
		Stream:      t.serve})
}

func newTermID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (t *TermOps) serve(ctx context.Context, c Call, st *Stream) (any, error) {
	p, spec, err := t.prepare(c)
	if err != nil {
		return nil, err
	}
	start := t.now()
	id := newTermID()
	spec.Name = id
	t.mu.Lock()
	if t.open[c.Subject.AccountID] >= MaxTerminals {
		t.mu.Unlock()
		return nil, Errf("limit_exceeded", "too many terminals")
	}
	t.open[c.Subject.AccountID]++
	if p.Mode.Elevated() {
		t.consumed[c.SessionKey] = t.Grants.StepUpUntil(c.Grant)
	}
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		if t.open[c.Subject.AccountID]--; t.open[c.Subject.AccountID] <= 0 {
			delete(t.open, c.Subject.AccountID)
		}
		t.mu.Unlock()
	}()
	c.AuditKV["user"] = spec.User.Name
	c.AuditKV["terminal"] = id

	sess, err := pty.Open(ctx, t.Launcher, spec, p.Cols, p.Rows)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	info := TermInfo{ID: id, Mode: p.Mode, User: spec.User.Name, IdleMinutes: int(t.idle() / time.Minute)}
	var until time.Time
	if p.Mode.Elevated() {
		until = start.Add(ElevatedTerminalTTL)
		info.Until = until.UTC()
	}
	t.auditStart(c, spec.User.Name, id)
	if err := st.Ready(info); err != nil {
		return nil, err
	}

	conn := st.Duplex()
	ends := make(chan string, 1)
	end := func(r string) {
		select {
		case ends <- r:
		default:
		}
	}
	var lastInput sync.Mutex
	lastIn := t.now()
	touched := lastIn

	// Input: browser → shell.
	go func() {
		in := newBucket(terminalInRate, terminalInBurst)
		for {
			b, err := rpc.ReadChunk(conn)
			if err != nil || len(b) == 0 || len(b) > terminalMaxIn+1 {
				end("closed")
				return
			}
			switch b[0] {
			case 'd':
				in.wait(len(b) - 1)
				if _, err := sess.Master.Write(b[1:]); err != nil {
					end("closed")
					return
				}
			case 'r':
				if len(b) == 5 {
					_ = sess.Resize(binary.BigEndian.Uint16(b[1:3]), binary.BigEndian.Uint16(b[3:5]))
				}
			default:
				end("closed")
				return
			}
			lastInput.Lock()
			lastIn = t.now()
			lastInput.Unlock()
		}
	}()

	// Output: shell → browser.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		out := newBucket(terminalOutRate, terminalOutBurst)
		buf := make([]byte, 32<<10)
		for {
			n, err := sess.Master.Read(buf)
			if n > 0 {
				out.wait(n)
				if rpc.WriteChunk(conn, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	reason := ""
	tick := time.NewTicker(terminalCheck)
	defer tick.Stop()
	for reason == "" {
		select {
		case r := <-ends:
			reason = r
		case <-sess.Done():
			reason = "exit"
		case <-ctx.Done():
			reason = "shutdown"
		case <-tick.C:
			now := t.now()
			lastInput.Lock()
			li := lastIn
			lastInput.Unlock()
			// Typing in the terminal counts as activity of the login session.
			touch := li.After(touched)
			if touch {
				touched = li
			}
			subj, ok := t.Grants.Alive(c.SessionKey, now, touch)
			switch {
			case !ok || subj.Role != c.Subject.Role || subj.LinuxUser != c.Subject.LinuxUser ||
				policy.Decide(subj, policy.ActTerminal, 0, false) == policy.Deny:
				reason = "session_ended"
			case !until.IsZero() && !now.Before(until):
				reason = "expired"
			case now.Sub(li) >= t.idle():
				reason = "idle"
			case !t.allowed(c.SourceIP):
				reason = "allowlist"
			}
		}
	}
	sess.Close()
	select {
	case <-outDone:
	case <-time.After(10 * time.Second):
	}
	if reason != "closed" && reason != "shutdown" {
		_ = rpc.WriteChunk(conn, nil)
	}
	c.AuditKV["end"] = reason
	c.AuditKV["duration_s"] = strconv.Itoa(int(t.now().Sub(start).Seconds()))
	return TermEnd{Reason: reason, ExitCode: sess.ExitCode()}, nil
}

// allowed re-checks the client address against the current allowlist (the
// web process enforces it too; this covers terminals it could not cut).
func (t *TermOps) allowed(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return true // address unknown (tests, admin channel): the web process decides
	}
	pfx, err := netallow.ParseList(t.Config.Get().Allowlist)
	if err != nil {
		return false
	}
	return netallow.New(pfx).Contains(a.Unmap())
}

func (t *TermOps) auditStart(c Call, user, id string) {
	if t.Audit == nil {
		return
	}
	ev := audit.Event{Action: "pty.start", Result: audit.ResultOK, SourceIP: c.SourceIP, Session: c.GrantID, Target: user,
		Params: map[string]string{"mode": c.AuditKV["mode"], "terminal": id}}
	if s := c.Subject; s != nil {
		ev.Actor = audit.Actor{AccountID: s.AccountID, Role: string(s.Role), LinuxUser: s.LinuxUser}
		ev.StepUp = s.StepUp
	}
	_, _ = t.Audit.Append(ev)
}

// bucket is a token bucket that blocks until n bytes may pass.
type bucket struct {
	rate, burst float64
	tokens      float64
	last        time.Time
}

func newBucket(rate, burst int) *bucket {
	return &bucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (b *bucket) wait(n int) {
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	b.tokens -= float64(n)
	if b.tokens < 0 {
		time.Sleep(time.Duration(-b.tokens / b.rate * float64(time.Second)))
	}
}
