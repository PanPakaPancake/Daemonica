package sysinfo

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// clkTck is USER_HZ; 100 on all supported Linux architectures (amd64, arm64).
const clkTck = 100

// MaxProcesses bounds the process scan (DoS protection).
const MaxProcesses = 20000

// Process is one entry of the process table.
type Process struct {
	PID     int       `json:"pid"`
	PPID    int       `json:"ppid"`
	UID     uint32    `json:"uid"`
	User    string    `json:"user"`
	State   string    `json:"state"`
	Name    string    `json:"name"`
	Command string    `json:"command"` // untrusted; rendered as text only
	CPU     float64   `json:"cpu"`     // percent of one CPU since previous sample
	RSS     uint64    `json:"rss"`     // bytes
	Start   time.Time `json:"start"`
	Threads int       `json:"threads"`
	// ticks is utime+stime at sample time.
	ticks uint64
}

// procStat parses /proc/<pid>/stat. comm may contain spaces and parentheses,
// so the last ')' delimits it.
func parseProcStat(b []byte) (comm, state string, ppid int, ticks, start uint64, threads int, err error) {
	s := string(b)
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return "", "", 0, 0, 0, 0, errors.New("sysinfo: malformed stat")
	}
	comm = s[l+1 : r]
	fs := strings.Fields(s[r+1:])
	if len(fs) < 20 {
		return "", "", 0, 0, 0, 0, errors.New("sysinfo: short stat")
	}
	// fs[0]=state(3) fs[1]=ppid(4) fs[11]=utime(14) fs[12]=stime(15) fs[17]=num_threads(20) fs[19]=starttime(22)
	state = fs[0]
	ppid, _ = strconv.Atoi(fs[1])
	ut, _ := strconv.ParseUint(fs[11], 10, 64)
	st, _ := strconv.ParseUint(fs[12], 10, 64)
	threads, _ = strconv.Atoi(fs[17])
	start, _ = strconv.ParseUint(fs[19], 10, 64)
	return comm, state, ppid, ut + st, start, threads, nil
}

// BootTime reads btime from /proc/stat.
func (f FS) BootTime() time.Time {
	b, _ := f.read("proc/stat")
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(n, 0)
			}
		}
	}
	return time.Time{}
}

// Users maps UID → name from /etc/passwd.
func (f FS) Users() map[uint32]string {
	b, _ := f.read("etc/passwd")
	out := map[uint32]string{}
	for _, l := range strings.Split(string(b), "\n") {
		p := strings.Split(l, ":")
		if len(p) < 3 {
			continue
		}
		if uid, err := strconv.ParseUint(p[2], 10, 32); err == nil {
			out[uint32(uid)] = p[0]
		}
	}
	return out
}

// SanitizeText removes control characters and invalid UTF-8 from untrusted
// system strings (process names, file names, log lines) and caps the length.
func SanitizeText(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return -1
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi overrides
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Processes scans /proc. cpuTotalDelta is the aggregate jiffies elapsed since
// prev was taken (all CPUs); ncpu converts it to "percent of one CPU".
func (f FS) Processes(prev map[int]uint64, cpuTotalDelta uint64, ncpu int, users map[uint32]string) ([]Process, error) {
	entries, err := os.ReadDir(f.path("proc"))
	if err != nil {
		return nil, err
	}
	boot := f.BootTime()
	page := uint64(os.Getpagesize())
	out := make([]Process, 0, 256)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		if len(out) >= MaxProcesses {
			break
		}
		dir := filepath.Join("proc", e.Name())
		sb, err := f.read(filepath.Join(dir, "stat"))
		if err != nil {
			continue // process exited
		}
		comm, state, ppid, ticks, start, threads, err := parseProcStat(sb)
		if err != nil {
			continue
		}
		p := Process{PID: pid, PPID: ppid, State: state, Name: SanitizeText(comm, 64), Threads: threads, ticks: ticks}
		if !boot.IsZero() {
			p.Start = boot.Add(time.Duration(start) * time.Second / clkTck).UTC()
		}
		if st, err := f.read(filepath.Join(dir, "status")); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(st))
			for sc.Scan() {
				if v, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
					if fs := strings.Fields(v); len(fs) > 0 {
						u, _ := strconv.ParseUint(fs[0], 10, 32)
						p.UID = uint32(u)
					}
					break
				}
			}
		}
		p.User = users[p.UID]
		if p.User == "" {
			p.User = strconv.FormatUint(uint64(p.UID), 10)
		}
		if sm, err := f.read(filepath.Join(dir, "statm")); err == nil {
			if fs := strings.Fields(string(sm)); len(fs) > 1 {
				rss, _ := strconv.ParseUint(fs[1], 10, 64)
				p.RSS = rss * page
			}
		}
		if cl, err := f.read(filepath.Join(dir, "cmdline")); err == nil && len(cl) > 0 {
			p.Command = SanitizeText(strings.TrimRight(strings.ReplaceAll(string(cl), "\x00", " "), " "), 300)
		}
		if p.Command == "" {
			p.Command = "[" + p.Name + "]"
		}
		if old, ok := prev[pid]; ok && cpuTotalDelta > 0 && ticks >= old {
			p.CPU = 100 * float64(ticks-old) * float64(ncpu) / float64(cpuTotalDelta)
		}
		out = append(out, p)
	}
	return out, nil
}

// Ticks returns the pid → ticks map used as "prev" for the next sample.
func Ticks(ps []Process) map[int]uint64 {
	m := make(map[int]uint64, len(ps))
	for _, p := range ps {
		m[p.PID] = p.ticks
	}
	return m
}

// TopBy returns the n processes with the highest CPU (then RSS).
func TopBy(ps []Process, n int) []Process {
	cp := append([]Process(nil), ps...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].CPU != cp[j].CPU {
			return cp[i].CPU > cp[j].CPU
		}
		return cp[i].RSS > cp[j].RSS
	})
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}
