package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

// SysOps exposes the system overview and the process table (SPEC §7.2).
type SysOps struct {
	Collector *sysinfo.Collector
	// SelfPID is the helper's own PID (never signalable).
	SelfPID int
	// Kill sends a signal; replaceable in tests.
	Kill func(pid int, sig syscall.Signal) error
}

// allowed signals (SPEC §7.2).
var signals = map[string]syscall.Signal{
	"TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL, "HUP": syscall.SIGHUP, "STOP": syscall.SIGSTOP, "CONT": syscall.SIGCONT,
}

// protectedProcess reports processes that must never be signalled from the UI:
// PID 1, Daemonica's own processes, and the main sshd listener (SPEC §7.2).
func (s *SysOps) protectedProcess(p sysinfo.Process) bool {
	switch {
	case p.PID <= 1, p.PID == s.SelfPID:
		return true
	case strings.HasPrefix(p.Name, "daemonica-"):
		return true
	case (p.Name == "sshd" || p.Name == "sshd-session") && p.PPID == 1:
		return true
	}
	return false
}

// ProcessView adds UI flags to a process.
type ProcessView struct {
	sysinfo.Process
	Protected bool `json:"protected"`
	Mine      bool `json:"mine"`
}

// MaxListed bounds proc.list responses.
const MaxListed = 1500

// ProcessList is the proc.list result.
type ProcessList struct {
	Processes []ProcessView `json:"processes"`
	Truncated bool          `json:"truncated"`
}

// Register installs sysinfo.* and proc.* operations.
func (s *SysOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "sysinfo.overview", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) { return s.Collector.Snapshot(), nil }})

	Register(ops, &Op{Name: "proc.list", Action: policy.ActProcRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			ps := s.Collector.Processes()
			// Stay below the 1 MiB RPC frame: at most MaxListed processes (busiest first).
			truncated := len(ps) > MaxListed
			if truncated {
				ps = sysinfo.TopBy(ps, MaxListed)
			}
			out := ProcessList{Processes: make([]ProcessView, 0, len(ps)), Truncated: truncated}
			for _, p := range ps {
				out.Processes = append(out.Processes, ProcessView{Process: p, Protected: s.protectedProcess(p), Mine: p.UID == c.Subject.LinuxUID})
			}
			return out, nil
		}})

	type sigParams struct {
		PID    int       `json:"pid"`
		Start  time.Time `json:"start"`
		Signal string    `json:"signal"`
	}
	Register(ops, &Op{Name: "proc.signal", Action: policy.ActProcSignal,
		AuditTarget: func(c Call) string {
			var p sigParams
			_ = decode(c, &p)
			return "pid:" + strconv.Itoa(p.PID) + " signal:" + p.Signal
		},
		Handle: func(_ context.Context, c Call) (any, error) {
			var p sigParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			sig, ok := signals[p.Signal]
			if !ok || p.PID <= 0 || p.PID > 1<<22 {
				return nil, Errf(rpc.CodeValidation, "invalid pid or signal")
			}
			cur, err := s.lookup(p.PID)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "process not found")
			}
			// PID reuse guard: the start time must match what the user saw.
			if !cur.Start.Truncate(time.Second).Equal(p.Start.UTC().Truncate(time.Second)) {
				return nil, Errf(rpc.CodeConflict, "process changed")
			}
			if s.protectedProcess(cur) {
				return nil, Errf(rpc.CodeLockout, "protected process")
			}
			switch policy.Decide(*c.Subject, policy.ActProcSignal, cur.UID, true) {
			case policy.Allow:
			case policy.NeedStepUp:
				return nil, Errf(rpc.CodeStepUpNeeded, "")
			default:
				return nil, Errf(rpc.CodeForbidden, "")
			}
			kill := s.Kill
			if kill == nil {
				kill = pidfdKill
			}
			if err := kill(p.PID, sig); err != nil {
				return nil, Errf(rpc.CodeConflict, "signal failed")
			}
			return nil, nil
		}})
}

// lookup re-reads one process from /proc (fresh, not from the cache).
func (s *SysOps) lookup(pid int) (sysinfo.Process, error) {
	ps, err := s.Collector.FS.Processes(nil, 0, 1, s.Collector.FS.Users())
	if err != nil {
		return sysinfo.Process{}, err
	}
	for _, p := range ps {
		if p.PID == pid {
			return p, nil
		}
	}
	return sysinfo.Process{}, errors.New("not found")
}

// pidfdKill signals through a pidfd (os.FindProcess uses pidfd_open on Linux),
// so the target cannot be swapped between lookup and signal.
func pidfdKill(pid int, sig syscall.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer func() { _ = p.Release() }()
	return p.Signal(sig)
}

// --- overview extras ---

// CertDaysFrom returns a provider reading the dashboard certificate.
func CertDaysFrom(tlsDir string) func() (int, error) {
	return func() (int, error) {
		b, err := os.ReadFile(filepath.Join(tlsDir, "fullchain.pem")) //nolint:gosec // fixed path
		if err != nil {
			return 0, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return 0, errors.New("no certificate")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return 0, err
		}
		return int(time.Until(c.NotAfter).Hours() / 24), nil
	}
}

var updatesRE = regexp.MustCompile(`(?m)^(\d+) (?:updates?|Aktualisierung)`)
var securityRE = regexp.MustCompile(`(?m)^(\d+) (?:of these|davon)`)

// UpdatesFromNotifier parses Ubuntu's update-notifier summary (refreshed by
// apt). The full apt integration follows in M1.7.
func UpdatesFromNotifier(path string) func() (sysinfo.Updates, error) {
	return func() (sysinfo.Updates, error) {
		b, err := os.ReadFile(path) //nolint:gosec // fixed path
		if err != nil {
			return sysinfo.Updates{}, err
		}
		var u sysinfo.Updates
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if m := updatesRE.FindStringSubmatch(l); m != nil && u.Total == 0 {
				u.Total, _ = strconv.Atoi(m[1])
			}
			if m := securityRE.FindStringSubmatch(l); m != nil {
				u.Security, _ = strconv.Atoi(m[1])
			}
		}
		return u, nil
	}
}
