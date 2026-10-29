// Package users reads the local account databases and changes them only via
// the shadow-utils programs (useradd, usermod, …) with argv arrays, never by
// editing /etc/passwd directly (SPEC §7.3). The tools take the passwd/shadow
// locks themselves.
package users

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// Paths of the shadow-utils programs (absolute, SPEC §3.2 rule 7).
var (
	Useradd  = "/usr/sbin/useradd"
	Usermod  = "/usr/sbin/usermod"
	Userdel  = "/usr/sbin/userdel"
	Groupadd = "/usr/sbin/groupadd"
	Groupdel = "/usr/sbin/groupdel"
	Gpasswd  = "/usr/bin/gpasswd"   //nolint:gosec // binary paths, not credentials
	Chpasswd = "/usr/sbin/chpasswd" //nolint:gosec // binary paths, not credentials
	Chage    = "/usr/bin/chage"
)

// DB reads the account files below Root (normally "/").
type DB struct{ Root string }

func (d DB) read(p string) []byte {
	b, _ := os.ReadFile(filepath.Join(d.Root, p)) //nolint:gosec // fixed system paths
	return b
}

// User is one Linux account.
type User struct {
	Name       string    `json:"name"`
	UID        uint32    `json:"uid"`
	GID        uint32    `json:"gid"`
	Gecos      string    `json:"gecos"`
	Home       string    `json:"home"`
	Shell      string    `json:"shell"`
	Groups     []string  `json:"groups"`
	System     bool      `json:"system"`
	Locked     bool      `json:"locked"`      // password locked ("!")
	NoPassword bool      `json:"no_password"` // no usable password at all (key-only)
	Expired    bool      `json:"expired"`     // account expiry date passed
	ExpiresOn  string    `json:"expires_on,omitempty"`
	PwChanged  string    `json:"pw_changed,omitempty"`
	PwMaxDays  int       `json:"pw_max_days,omitempty"`
	MustChange bool      `json:"must_change"`
	Sudo       bool      `json:"sudo"`
	KeyCount   int       `json:"key_count"` // filled by the caller (SSH module)
	LastLogin  time.Time `json:"last_login,omitzero"`
}

// Group is one Linux group.
type Group struct {
	Name    string   `json:"name"`
	GID     uint32   `json:"gid"`
	Members []string `json:"members"`
	System  bool     `json:"system"`
}

// Range holds UID_MIN/UID_MAX and GID_MIN/GID_MAX from /etc/login.defs.
type Range struct{ UIDMin, UIDMax, GIDMin, GIDMax uint32 }

// LoginDefs reads the ID ranges (Debian defaults if unset).
func (d DB) LoginDefs() Range {
	r := Range{1000, 60000, 1000, 60000}
	sc := bufio.NewScanner(bytes.NewReader(d.read("etc/login.defs")))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			continue
		}
		switch f[0] {
		case "UID_MIN":
			r.UIDMin = uint32(v)
		case "UID_MAX":
			r.UIDMax = uint32(v)
		case "GID_MIN":
			r.GIDMin = uint32(v)
		case "GID_MAX":
			r.GIDMax = uint32(v)
		}
	}
	return r
}

// Shells returns the allowed login shells from /etc/shells.
func (d DB) Shells() []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(d.read("etc/shells")), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "/") && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return append(out, "/usr/sbin/nologin")
}

// SudoGroups are the groups granting sudo on Debian/Ubuntu.
var SudoGroups = []string{"sudo", "admin"}

func daysToDate(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || s == "" {
		return time.Time{}, false
	}
	return time.Unix(n*86400, 0).UTC(), true
}

// List returns users and groups.
func (d DB) List(now time.Time) ([]User, []Group, error) {
	pw := d.read("etc/passwd")
	if len(pw) == 0 {
		return nil, nil, errors.New("users: /etc/passwd not readable")
	}
	rg := d.LoginDefs()
	shadow := map[string][]string{}
	for _, l := range strings.Split(string(d.read("etc/shadow")), "\n") {
		if f := strings.Split(l, ":"); len(f) >= 9 {
			shadow[f[0]] = f
		}
	}
	var groups []Group
	memberOf := map[string][]string{}
	gidName := map[uint32]string{}
	for _, l := range strings.Split(string(d.read("etc/group")), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		g := Group{Name: f[0], GID: uint32(gid), Members: []string{}, System: uint32(gid) < rg.GIDMin || uint32(gid) > rg.GIDMax}
		gidName[g.GID] = g.Name
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
				memberOf[m] = append(memberOf[m], g.Name)
			}
		}
		groups = append(groups, g)
	}
	var users []User
	for _, l := range strings.Split(string(pw), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		u := User{Name: f[0], UID: uint32(uid), GID: uint32(gid), Gecos: sysinfo.SanitizeText(f[4], 256), Home: f[5], Shell: f[6]}
		u.System = u.UID != 0 && (u.UID < rg.UIDMin || u.UID > rg.UIDMax) || u.UID == 65534
		if u.UID == 0 {
			u.System = false
		}
		u.Groups = []string{}
		if pg := gidName[u.GID]; pg != "" {
			u.Groups = append(u.Groups, pg)
		}
		for _, g := range memberOf[u.Name] {
			if g != gidName[u.GID] {
				u.Groups = append(u.Groups, g)
			}
		}
		for _, g := range u.Groups {
			for _, s := range SudoGroups {
				if g == s {
					u.Sudo = true
				}
			}
		}
		if s, ok := shadow[u.Name]; ok {
			pwf := s[1]
			u.Locked = strings.HasPrefix(pwf, "!")
			u.NoPassword = pwf == "" || pwf == "*" || pwf == "!" || pwf == "!*" || pwf == "*!"
			if t, ok := daysToDate(s[2]); ok {
				if s[2] == "0" {
					u.MustChange = true
				} else {
					u.PwChanged = t.Format("2006-01-02")
				}
			}
			if v, err := strconv.Atoi(s[4]); err == nil && v < 99999 {
				u.PwMaxDays = v
			}
			if t, ok := daysToDate(s[7]); ok {
				u.ExpiresOn = t.Format("2006-01-02")
				u.Expired = !now.Before(t)
			}
		}
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].UID < users[j].UID })
	sort.Slice(groups, func(i, j int) bool { return groups[i].GID < groups[j].GID })
	return users, groups, nil
}

// --- changes (argv only) ---

// Runner executes a program; replaceable in tests.
type Runner func(ctx context.Context, stdin []byte, path string, args ...string) error

// ExecRunner runs programs via execx with a 60 s timeout.
func ExecRunner(ctx context.Context, stdin []byte, path string, args ...string) error {
	var in io.Reader
	if stdin != nil {
		in = bytes.NewReader(stdin)
	}
	res, err := execx.Run(ctx, 60*time.Second, 64<<10, in, path, args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(sysinfo.SanitizeText(string(res.Stderr), 300))
		// Never echo stdin (passwords) – stderr of chpasswd does not contain it.
		return &ToolError{Tool: filepath.Base(path), Code: res.ExitCode, Msg: msg}
	}
	return nil
}

// ToolError is a failed shadow-utils call.
type ToolError struct {
	Tool string
	Code int
	Msg  string
}

func (e *ToolError) Error() string { return e.Tool + ": " + e.Msg }

// Validation helpers.
var (
	ErrName  = errors.New("invalid name")
	ErrShell = errors.New("shell not listed in /etc/shells")
	ErrGecos = errors.New("invalid description")
	ErrHome  = errors.New("invalid home directory")
	ErrPass  = errors.New("password must have at least 12 characters")
	ErrDate  = errors.New("invalid date")
)

// ValidGecos rejects ':' (field separator), ',' and control characters.
func ValidGecos(s string) bool {
	return validate.NoControl(s, 128) == nil && !strings.ContainsAny(s, ":,")
}

// ValidHome accepts absolute, clean paths without special characters.
func ValidHome(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && validate.NoControl(p, 256) == nil &&
		!strings.ContainsAny(p, ":,\\ ")
}

func (d DB) validShell(s string) bool {
	for _, x := range d.Shells() {
		if x == s {
			return true
		}
	}
	return false
}

// CreateSpec describes a new user.
type CreateSpec struct {
	Name       string   `json:"name"`
	Gecos      string   `json:"gecos,omitempty"`
	Shell      string   `json:"shell,omitempty"`
	Home       string   `json:"home,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	CreateHome bool     `json:"create_home"`
}

// CreateArgs validates spec and returns the useradd argv (password locked by default).
func (d DB) CreateArgs(s CreateSpec, existingGroups map[string]bool) ([]string, error) {
	if validate.LinuxUser(s.Name) != nil {
		return nil, ErrName
	}
	args := []string{"--user-group"}
	if s.CreateHome {
		args = append(args, "--create-home")
	} else {
		args = append(args, "--no-create-home")
	}
	if s.Gecos != "" {
		if !ValidGecos(s.Gecos) {
			return nil, ErrGecos
		}
		args = append(args, "--comment", s.Gecos)
	}
	shell := s.Shell
	if shell == "" {
		shell = "/bin/bash"
	}
	if !d.validShell(shell) {
		return nil, ErrShell
	}
	args = append(args, "--shell", shell)
	if s.Home != "" {
		if !ValidHome(s.Home) {
			return nil, ErrHome
		}
		args = append(args, "--home-dir", s.Home)
	}
	if len(s.Groups) > 0 {
		for _, g := range s.Groups {
			if validate.LinuxUser(g) != nil || !existingGroups[g] {
				return nil, ErrName
			}
		}
		args = append(args, "--groups", strings.Join(s.Groups, ","))
	}
	// "--" ends option parsing: the name can never be read as an option.
	return append(args, "--", s.Name), nil
}

// ParseDate validates YYYY-MM-DD (or "" to clear).
func ParseDate(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return "", ErrDate
	}
	return s, nil
}
