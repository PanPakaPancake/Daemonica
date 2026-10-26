package apt

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Installed is one installed package (dpkg-query).
type Installed struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// Status is dpkg's abbreviation, e.g. "ii", "hi" (held), "rc".
	Status  string `json:"status"`
	Auto    bool   `json:"auto"`
	SizeKiB int64  `json:"size_kib"`
	Section string `json:"section,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// InstalledFormat is the dpkg-query -W -f format ParseInstalled reads.
const InstalledFormat = "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${Section}\t${binary:Summary}\n"

// ParseInstalled parses dpkg-query output in InstalledFormat; auto holds
// the automatically installed names (apt-mark showauto). Packages that are
// not installed (status "un", "pn") are left out.
func ParseInstalled(out string, auto map[string]bool) []Installed {
	list := []Installed{}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 7 {
			continue
		}
		st := strings.TrimSpace(f[0])
		if len(st) < 2 || st[1] == 'n' {
			continue
		}
		size, _ := strconv.ParseInt(f[4], 10, 64)
		sum := f[6]
		if len(sum) > 100 {
			sum = strings.ToValidUTF8(sum[:100], "")
		}
		list = append(list, Installed{Name: f[1], Version: f[2], Arch: f[3], Status: st, SizeKiB: size, Section: f[5], Summary: sum,
			Auto: auto[f[1]] || auto[f[1]+":"+f[3]]})
	}
	return list
}

// ParseLines returns the non-empty lines of out as a set.
func ParseLines(out string) map[string]bool {
	m := map[string]bool{}
	for l := range strings.SplitSeq(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			m[l] = true
		}
	}
	return m
}

// LockFiles are the locks apt and dpkg take, frontend lock first.
var LockFiles = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}

// Holder is a process holding a package lock.
type Holder struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	File string `json:"file"`
}

// LockHolder returns the process holding one of the package locks, or nil.
// It only tests the locks (F_GETLK) and never takes them.
func LockHolder() *Holder {
	for _, f := range LockFiles {
		if h := lockHolder(f); h != nil {
			return h
		}
	}
	return nil
}

func lockHolder(path string) *Holder {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(fd) }()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &lk) != nil || lk.Type == unix.F_UNLCK {
		return nil
	}
	h := &Holder{PID: int(lk.Pid), File: path}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(h.PID) + "/comm"); err == nil {
		h.Comm = strings.TrimSpace(string(b))
	}
	return h
}

// RunningKernel returns the release of the running kernel.
func RunningKernel() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

// RebootRequired reads /run/reboot-required(.pkgs) (written by Debian/Ubuntu
// package hooks).
func RebootRequired(root string) (bool, []string) {
	if _, err := os.Stat(root + "/run/reboot-required"); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	b, _ := os.ReadFile(root + "/run/reboot-required.pkgs") //nolint:gosec // fixed path
	m := ParseLines(string(b))
	pkgs := make([]string, 0, len(m))
	for p := range m {
		if ValidName(p) {
			pkgs = append(pkgs, p)
		}
	}
	return true, sortStrings(pkgs)
}
