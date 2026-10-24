// Package files implements the file manager (SPEC §7.4). Every operation runs
// inside a worker process that has assumed the mapped Linux user's
// credentials (or root in the admin "as root" mode), so Linux permissions are
// the boundary. On top of that the worker enforces Daemonica's own rules on
// the canonical path of the object it actually opened: hard-blocked
// Daemonica data, sensitive paths that need an explicit confirmation, and
// protected top-level directories.
//
// Paths are resolved with openat2: reads may follow symlinks (but never
// /proc magic links); everything that writes resolves its directory with
// RESOLVE_NO_SYMLINKS and acts on the final component with *at() calls that
// do not follow symlinks, so swapping a path component for a symlink during
// an operation cannot redirect it (TOCTOU).
package files

import (
	"encoding/base64"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// Limits.
const (
	MaxPath      = 4096
	MaxName      = 255
	MaxEditBytes = 5 << 20 // editor size limit (SPEC §7.4)
	ListCap      = 100_000 // entries read from one directory at most
	PageMax      = 1000
	TreeMaxDepth = 256
)

// Error codes returned by worker operations (passed through to the UI).
const (
	CodeNotFound    = "not_found"
	CodeDenied      = "permission_denied"
	CodeExists      = "already_exists"
	CodeNotEmpty    = "not_empty"
	CodeSymlink     = "symlink_refused"
	CodeNotDir      = "not_a_directory"
	CodeIsDir       = "is_a_directory"
	CodeNoSpace     = "no_space"
	CodeReadOnlyFS  = "read_only_fs"
	CodeBusy        = "busy"
	CodeBlocked     = "path_blocked"
	CodeSensitive   = "sensitive_path"
	CodeProtected   = "protected_path"
	CodeVirtual     = "virtual_fs"
	CodeTooLarge    = "too_large"
	CodeConflict    = "conflict"
	CodeInvalid     = "validation_failed"
	CodeAborted     = "aborted"
	CodeLimit       = "limit_exceeded"
	CodeUnsupported = "not_supported"
	CodeNotRegular  = "not_regular_file"
	CodeRange       = "range_not_satisfiable"
	CodeMountPoint  = "mount_point"
)

// Codes lists every code a worker may return (the helper passes only these through).
var Codes = []string{CodeNotFound, CodeDenied, CodeExists, CodeNotEmpty, CodeSymlink, CodeNotDir, CodeIsDir,
	CodeNoSpace, CodeReadOnlyFS, CodeBusy, CodeBlocked, CodeSensitive, CodeProtected, CodeVirtual, CodeTooLarge,
	CodeConflict, CodeInvalid, CodeAborted, CodeLimit, CodeUnsupported, CodeNotRegular, CodeRange, CodeMountPoint}

// ValidPath accepts absolute, clean, valid UTF-8 paths without NUL bytes.
func ValidPath(p string) bool {
	return p != "" && len(p) <= MaxPath && p[0] == '/' && utf8.ValidString(p) &&
		!strings.ContainsRune(p, 0) && path.Clean(p) == p
}

// ValidName accepts names for new objects: one component, valid UTF-8,
// no control or invisible formatting characters (bidi overrides etc.).
func ValidName(n string) bool {
	if n == "" || n == "." || n == ".." || len(n) > MaxName || !utf8.ValidString(n) || strings.ContainsAny(n, "/\x00") {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// Target addresses one existing directory entry. Raw (base64 of the name
// bytes) replaces Name for entries whose names are not valid UTF-8, so such
// files can still be renamed or deleted.
type Target struct {
	Dir  string `json:"dir"`
	Name string `json:"name,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

// Resolve validates t and returns the directory and the raw name bytes.
func (t Target) Resolve() (string, string, error) {
	if !ValidPath(t.Dir) {
		return "", "", opErr(CodeInvalid, "invalid directory")
	}
	name := t.Name
	if t.Raw != "" {
		b, err := base64.StdEncoding.DecodeString(t.Raw)
		if err != nil {
			return "", "", opErr(CodeInvalid, "invalid raw name")
		}
		name = string(b)
	} else if !utf8.ValidString(name) {
		return "", "", opErr(CodeInvalid, "invalid name")
	}
	if name == "" || name == "." || name == ".." || len(name) > MaxName || strings.ContainsAny(name, "/\x00") {
		return "", "", opErr(CodeInvalid, "invalid name")
	}
	return t.Dir, name, nil
}

// Path joins the target for display/audit (raw names are escaped).
func (t Target) Path() string {
	n := t.Name
	if t.Raw != "" {
		if b, err := base64.StdEncoding.DecodeString(t.Raw); err == nil {
			n = Display(string(b))
		}
	}
	return Join(t.Dir, n)
}

// Join joins a canonical directory and a single name.
func Join(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// blockedRoots are the directories whose "daemonica*" children are Daemonica's
// own data, keys, logs and sockets (SPEC §7.4 "hart gesperrt").
var blockedRoots = []string{"/etc", "/var/lib", "/var/log", "/run"}

// Blocked reports whether the canonical path p is hard-blocked: not readable
// or writable through the file manager, not even as root.
func Blocked(p string) bool {
	for _, r := range blockedRoots {
		if rest, ok := strings.CutPrefix(p, r+"/"); ok {
			first, _, _ := strings.Cut(rest, "/")
			if strings.HasPrefix(first, "daemonica") {
				return true
			}
		}
	}
	return false
}

// ContainsBlocked reports whether deleting or moving p would take a blocked
// path with it (p is an ancestor of a blocked root's daemonica* entries).
func ContainsBlocked(p string) bool {
	if p == "/" {
		return true
	}
	for _, r := range blockedRoots {
		if r == p || strings.HasPrefix(r, p+"/") {
			return true
		}
	}
	return Blocked(p)
}

// Protected reports paths that must never be deleted, moved or renamed:
// the root directory and its direct children (/etc, /usr, /home, …).
func Protected(p string) bool { return p == "/" || path.Dir(p) == "/" }

// Virtual reports kernel pseudo file systems: listing and small reads only.
func Virtual(p string) bool {
	for _, r := range []string{"/proc", "/sys", "/dev"} {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// Sensitive reports paths that need an additional warning confirmation and a
// fresh step-up before their contents are read or changed (SPEC §7.4).
func Sensitive(p string) bool {
	switch p {
	case "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-":
		return true
	}
	base := path.Base(p)
	dir := path.Dir(p)
	if dir == "/etc/ssh" && strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key") {
		return true
	}
	if path.Base(dir) == ".ssh" && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") {
		return true
	}
	return false
}

// Display escapes a name for display: invalid bytes as \xNN, control and
// invisible formatting characters (e.g. bidi overrides that could disguise an
// extension) as \u{XXXX}. Valid printable names are returned unchanged.
func Display(s string) string {
	clean := utf8.ValidString(s)
	if clean {
		for _, r := range s {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				clean = false
				break
			}
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// ModeString renders permission bits like ls (rwxr-x---, with s/S/t/T).
func ModeString(m uint32) string {
	const rwx = "rwxrwxrwx"
	b := []byte("---------")
	for i := range 9 {
		if m&(1<<(8-i)) != 0 {
			b[i] = rwx[i]
		}
	}
	special := func(bit uint32, idx int, set, unset byte) {
		if m&bit != 0 {
			if b[idx] == 'x' {
				b[idx] = set
			} else {
				b[idx] = unset
			}
		}
	}
	special(0o4000, 2, 's', 'S')
	special(0o2000, 5, 's', 'S')
	special(0o1000, 8, 't', 'T')
	return string(b)
}

func opErr(code, msg string) error { return &worker.OpError{Code: code, Msg: msg} }
