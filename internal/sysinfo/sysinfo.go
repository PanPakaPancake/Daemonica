// Package sysinfo reads host state directly from /proc, /sys and statfs
// (SPEC §4.1: no parsing of command output where avoidable). All readers take
// a root directory so they can be tested against fixture trees.
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
	"syscall"
	"time"
)

// FS points at the filesystem root (normally "/").
type FS struct{ Root string }

func (f FS) path(p string) string { return filepath.Join(f.Root, p) }

func (f FS) read(p string) ([]byte, error) {
	return os.ReadFile(f.path(p)) //nolint:gosec // fixed /proc and /sys paths
}

// CPUTimes is one line of /proc/stat (jiffies).
type CPUTimes struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

// Total returns the sum of all fields.
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// Busy returns non-idle time.
func (c CPUTimes) Busy() uint64 { return c.Total() - c.Idle - c.IOWait }

// CPUStat reads the aggregate "cpu" line and the number of CPUs.
func (f FS) CPUStat() (CPUTimes, int, error) {
	b, err := f.read("proc/stat")
	if err != nil {
		return CPUTimes{}, 0, err
	}
	var agg CPUTimes
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 9 || !strings.HasPrefix(fs[0], "cpu") {
			continue
		}
		if fs[0] != "cpu" {
			n++
			continue
		}
		v := make([]uint64, 8)
		for i := range v {
			v[i], _ = strconv.ParseUint(fs[i+1], 10, 64)
		}
		agg = CPUTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}
	}
	if n == 0 {
		n = 1
	}
	return agg, n, nil
}

// CPUPercent computes utilisation between two samples (0–100).
func CPUPercent(a, b CPUTimes) float64 {
	dt := float64(b.Total() - a.Total())
	if dt <= 0 || b.Total() < a.Total() {
		return 0
	}
	return clampPct(100 * float64(b.Busy()-a.Busy()) / dt)
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// Load holds load averages.
type Load struct {
	One, Five, Fifteen float64
}

// LoadAvg reads /proc/loadavg.
func (f FS) LoadAvg() (Load, error) {
	b, err := f.read("proc/loadavg")
	if err != nil {
		return Load{}, err
	}
	fs := strings.Fields(string(b))
	if len(fs) < 3 {
		return Load{}, errors.New("sysinfo: malformed loadavg")
	}
	var l Load
	l.One, _ = strconv.ParseFloat(fs[0], 64)
	l.Five, _ = strconv.ParseFloat(fs[1], 64)
	l.Fifteen, _ = strconv.ParseFloat(fs[2], 64)
	return l, nil
}

// Memory in bytes.
type Memory struct {
	Total     uint64 `json:"total"`
	Available uint64 `json:"available"`
	Used      uint64 `json:"used"`
	Cached    uint64 `json:"cached"`
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
}

// MemInfo reads /proc/meminfo.
func (f FS) MemInfo() (Memory, error) {
	b, err := f.read("proc/meminfo")
	if err != nil {
		return Memory{}, err
	}
	kv := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) == 0 {
			continue
		}
		v, _ := strconv.ParseUint(fs[0], 10, 64)
		kv[k] = v * 1024
	}
	m := Memory{Total: kv["MemTotal"], Available: kv["MemAvailable"], Cached: kv["Cached"] + kv["Buffers"], SwapTotal: kv["SwapTotal"]}
	if m.Total >= m.Available {
		m.Used = m.Total - m.Available
	}
	if kv["SwapTotal"] >= kv["SwapFree"] {
		m.SwapUsed = kv["SwapTotal"] - kv["SwapFree"]
	}
	return m, nil
}

// Uptime reads /proc/uptime.
func (f FS) Uptime() (time.Duration, error) {
	b, err := f.read("proc/uptime")
	if err != nil {
		return 0, err
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return 0, errors.New("sysinfo: malformed uptime")
	}
	s, err := strconv.ParseFloat(fs[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(s * float64(time.Second)), nil
}

// OSRelease returns PRETTY_NAME, ID and VERSION_ID from /etc/os-release.
func (f FS) OSRelease() (pretty, id, version string) {
	b, err := f.read("etc/os-release")
	if err != nil {
		b, _ = f.read("usr/lib/os-release")
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "PRETTY_NAME":
			pretty = v
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return
}

// Kernel returns the running kernel release (/proc/sys/kernel/osrelease).
func (f FS) Kernel() string {
	b, _ := f.read("proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

// Hostname returns /proc/sys/kernel/hostname.
func (f FS) Hostname() string {
	b, _ := f.read("proc/sys/kernel/hostname")
	return strings.TrimSpace(string(b))
}

// RebootRequired reports whether Debian/Ubuntu flags a pending reboot, and the packages causing it.
func (f FS) RebootRequired() (bool, []string) {
	if _, err := os.Stat(f.path("var/run/reboot-required")); err != nil {
		return false, nil
	}
	b, _ := f.read("var/run/reboot-required.pkgs")
	var pkgs []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !seen[l] && len(pkgs) < 50 {
			seen[l] = true
			pkgs = append(pkgs, l)
		}
	}
	return true, pkgs
}

// Mount is a filesystem with usage.
type Mount struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	FSType      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Available   uint64  `json:"available"`
	UsedPct     float64 `json:"used_pct"`
	InodesTotal uint64  `json:"inodes_total"`
	InodesUsed  uint64  `json:"inodes_used"`
	InodesPct   float64 `json:"inodes_pct"`
	ReadOnly    bool    `json:"read_only"`
}

// pseudo filesystems excluded from the overview.
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "pstore": true, "bpf": true, "debugfs": true, "tracefs": true, "configfs": true, "fusectl": true,
	"mqueue": true, "hugetlbfs": true, "autofs": true, "binfmt_misc": true, "efivarfs": true, "rpc_pipefs": true,
	"nsfs": true, "ramfs": true, "squashfs": true, "overlay": true, "fuse.lxcfs": true, "fuse.portal": true,
}

// unescapeMount decodes octal escapes used in /proc/self/mounts (\040 = space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Mounts lists real filesystems with usage (statfs). tmpfs on /tmp, /dev/shm and
// /run is included because it matters for the overview; other pseudo-fs are skipped.
func (f FS) Mounts(statfs func(path string, st *syscall.Statfs_t) error) ([]Mount, error) {
	b, err := f.read("proc/self/mounts")
	if err != nil {
		return nil, err
	}
	if statfs == nil {
		statfs = syscall.Statfs
	}
	var out []Mount
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 {
			continue
		}
		dev, mp, typ := unescapeMount(fs[0]), unescapeMount(fs[1]), fs[2]
		keepTmp := typ == "tmpfs" && (mp == "/tmp" || mp == "/dev/shm" || mp == "/run")
		if (pseudoFS[typ] && !keepTmp) || strings.HasPrefix(mp, "/snap/") || seen[mp] {
			continue
		}
		seen[mp] = true
		var st syscall.Statfs_t
		if err := statfs(filepath.Join(f.Root, mp), &st); err != nil {
			continue
		}
		bs := uint64(st.Bsize) //nolint:gosec // block size is positive
		m := Mount{Device: dev, Mountpoint: mp, FSType: typ, Total: st.Blocks * bs, Available: st.Bavail * bs,
			InodesTotal: st.Files, ReadOnly: strings.Contains(","+fs[3]+",", ",ro,")}
		if st.Blocks >= st.Bfree {
			m.Used = (st.Blocks - st.Bfree) * bs
		}
		if denom := m.Used + m.Available; denom > 0 {
			m.UsedPct = 100 * float64(m.Used) / float64(denom)
		}
		if st.Files >= st.Ffree {
			m.InodesUsed = st.Files - st.Ffree
		}
		if st.Files > 0 {
			m.InodesPct = 100 * float64(m.InodesUsed) / float64(st.Files)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out, nil
}

// NetCounters are cumulative interface counters.
type NetCounters struct {
	RxBytes, TxBytes, RxErrs, TxErrs uint64
}

// NetDev reads /proc/net/dev (loopback excluded).
func (f FS) NetDev() (map[string]NetCounters, error) {
	b, err := f.read("proc/net/dev")
	if err != nil {
		return nil, err
	}
	out := map[string]NetCounters{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		fs := strings.Fields(rest)
		if name == "lo" || len(fs) < 16 {
			continue
		}
		p := func(i int) uint64 { v, _ := strconv.ParseUint(fs[i], 10, 64); return v }
		out[name] = NetCounters{RxBytes: p(0), RxErrs: p(2), TxBytes: p(8), TxErrs: p(10)}
	}
	return out, nil
}

// InterfaceState returns operstate and MAC from /sys/class/net.
func (f FS) InterfaceState(name string) (state, mac string) {
	s, _ := f.read(filepath.Join("sys/class/net", filepath.Base(name), "operstate"))
	m, _ := f.read(filepath.Join("sys/class/net", filepath.Base(name), "address"))
	return strings.TrimSpace(string(s)), strings.TrimSpace(string(m))
}
