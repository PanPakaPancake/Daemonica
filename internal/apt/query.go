package apt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

// Run runs a program (netcfg.ExecRunner in production).
type Run func(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error)

// ExecRun runs programs with execx and a 4 MiB output limit (package
// lists are larger than the usual 256 KiB).
func ExecRun(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error) {
	return execx.Run(ctx, timeout, 4<<20, nil, path, args...)
}

// System answers the read-only questions about the package state.
type System struct {
	Run Run
	// Root is prepended to the files read directly (tests); "" means "/".
	Root string
}

// ErrSim is a failed simulation; the message is apt's error (safe to show).
type ErrSim struct{ Msg string }

func (e *ErrSim) Error() string { return e.Msg }

// simOpts make simulations independent of a running job's locks.
var simOpts = []string{"-s", "-q", "-o", "Debug::NoLocking=true", "-o", "APT::Color=0"}

// Simulate runs apt-get -s for a job kind.
func (s System) Simulate(ctx context.Context, k Kind, pkgs []string) (Sim, error) {
	var args []string
	switch k {
	case KindUpgrade:
		args = []string{"--with-new-pkgs", "upgrade"}
	case KindSelected:
		args = append([]string{"install", "--only-upgrade"}, pkgs...)
	case KindInstall:
		args = append([]string{"install"}, pkgs...)
	case KindRemove:
		args = append([]string{"remove"}, pkgs...)
	case KindPurge:
		args = append([]string{"purge"}, pkgs...)
	case KindAutoremove:
		args = []string{"autoremove"}
	default:
		return Sim{}, fmt.Errorf("apt: no simulation for %s", k)
	}
	res, err := s.Run(ctx, 2*time.Minute, AptGet, append(append([]string{}, simOpts...), args...)...)
	if err != nil {
		return Sim{}, err
	}
	if res.ExitCode != 0 {
		return Sim{}, &ErrSim{Msg: errLines(string(res.Stdout) + "\n" + string(res.Stderr))}
	}
	return ParseSim(string(res.Stdout)), nil
}

// errLines picks apt's E: lines (or the last lines) as a short message.
func errLines(out string) string {
	var es, all []string
	for l := range strings.SplitSeq(out, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		all = append(all, l)
		if strings.HasPrefix(l, "E: ") {
			es = append(es, l)
		}
	}
	if len(es) == 0 && len(all) > 0 {
		es = all[max(len(all)-3, 0):]
	}
	return clip(strings.Join(es, " | "), 1000)
}

// Installed lists the installed packages.
func (s System) Installed(ctx context.Context) ([]Installed, error) {
	res, err := s.Run(ctx, time.Minute, DpkgQ, "-W", "-f", InstalledFormat)
	if err != nil {
		return nil, err
	}
	auto, _ := s.Run(ctx, time.Minute, AptMark, "showauto")
	list := ParseInstalled(string(res.Stdout), ParseLines(string(auto.Stdout)))
	if len(list) > 2500 {
		// Keep the result below the RPC frame limit.
		for i := range list {
			list[i].Summary = ""
		}
	}
	return list, nil
}

// Auto returns which of names are marked automatically installed.
func (s System) Auto(ctx context.Context, names []string) ([]string, error) {
	res, err := s.Run(ctx, time.Minute, AptMark, "showauto")
	if err != nil {
		return nil, err
	}
	set := ParseLines(string(res.Stdout))
	var out []string
	for _, n := range names {
		if set[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

// Search searches the package names and descriptions and adds the
// installed and candidate versions.
func (s System) Search(ctx context.Context, term string) ([]Found, bool, error) {
	res, err := s.Run(ctx, time.Minute, AptCache, "search", term)
	if err != nil && !errors.Is(err, execx.ErrTruncated) {
		return nil, false, err
	}
	list, more := ParseSearch(string(res.Stdout))
	more = more || errors.Is(err, execx.ErrTruncated)
	if len(list) == 0 {
		return list, more, nil
	}
	names := make([]string, 0, len(list))
	for _, f := range list {
		names = append(names, f.Name)
	}
	pol, err := s.Run(ctx, time.Minute, AptCache, append([]string{"policy"}, names...)...)
	if err == nil {
		m := ParsePolicy(string(pol.Stdout))
		for i := range list {
			p := m[list[i].Name]
			list[i].Installed, list[i].Candidate = p.Installed, p.Candidate
		}
	}
	return list, more, nil
}

// NeedRestart runs needrestart in batch mode; Available is false when it
// is not installed.
func (s System) NeedRestart(ctx context.Context) (NeedRestart, error) {
	if _, err := os.Stat(filepath.Join(s.root(), NeedRestartBin)); err != nil {
		return NeedRestart{Services: []string{}, Containers: []string{}, Sessions: []string{}}, nil
	}
	res, err := s.Run(ctx, 2*time.Minute, NeedRestartBin, "-b", "-r", "l")
	if err != nil {
		return NeedRestart{}, err
	}
	return ParseNeedRestart(string(res.Stdout)), nil
}

// Config runs apt-config dump.
func (s System) Config(ctx context.Context) (AptConfig, error) {
	res, err := s.Run(ctx, time.Minute, AptCfg, "dump")
	if err != nil && !errors.Is(err, execx.ErrTruncated) {
		return AptConfig{}, err
	}
	return ParseAptConfig(string(res.Stdout)), nil
}

func (s System) root() string {
	if s.Root == "" {
		return "/"
	}
	return s.Root
}

// Version returns the installed version of a package ("" if not installed).
func (s System) Version(ctx context.Context, name string) string {
	res, err := s.Run(ctx, 30*time.Second, DpkgQ, "-W", "-f", "${db:Status-Abbrev}\t${Version}", name)
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	st, v, _ := strings.Cut(string(res.Stdout), "\t")
	if !strings.HasPrefix(st, "ii") && !strings.HasPrefix(st, "hi") {
		return ""
	}
	return clip(v, 100)
}

// Unattended returns the state of automatic updates.
func (s System) Unattended(ctx context.Context) (UnattendedStatus, error) {
	st := UnattendedStatus{}
	st.Version = s.Version(ctx, "unattended-upgrades")
	st.Installed = st.Version != ""
	if b, err := os.ReadFile(filepath.Join(s.root(), UnattendedFile)); err == nil {
		if u, ok := ParseManaged(string(b)); ok {
			st.Managed, st.Wanted = true, &u
		}
	}
	c, err := s.Config(ctx)
	if err != nil {
		return st, err
	}
	st.Effective(c)
	st.Log = Tail(filepath.Join(s.root(), UnattendedLog), 32<<10)
	st.LastRun = LastRun(st.Log)
	return st, nil
}

// LastUpdate is the time of the last successful apt-get update as far as
// the system records it (the stamp the distribution's hook touches), zero
// if unknown.
func (s System) LastUpdate() time.Time {
	if st, err := os.Stat(filepath.Join(s.root(), "var/lib/apt/periodic/update-success-stamp")); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}
