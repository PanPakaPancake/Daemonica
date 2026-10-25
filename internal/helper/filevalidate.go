package helper

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

// Validation of known configuration files before an editor save takes
// effect (SPEC §7.4 SOLL). sudoers is checked on a private copy before
// anything is written (a broken sudoers must never be live, even briefly);
// the others are checked on the live configuration right after the save,
// because their checks need the complete configuration (includes, drop-ins).
// On failure the previous content is restored unless the user chose to
// save anyway or the configuration already failed before the save; for
// sudoers there is no override.

// Validator describes the check for one kind of file.
type Validator struct {
	Tool string // shown to the user, e.g. "sshd -t"
	// Pre runs the check on a private copy before writing; Blocking forbids
	// "save anyway".
	Pre, Blocking bool
	bin           string
	args          func(file string) []string
}

// Validation is reported to the editor.
type Validation struct {
	Tool       string `json:"tool"`
	OK         bool   `json:"ok"`
	Skipped    bool   `json:"skipped,omitempty"` // tool not installed
	Output     string `json:"output,omitempty"`
	Blocking   bool   `json:"blocking,omitempty"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	// Preexisting: the configuration already failed the check before this
	// save, so the save was kept.
	Preexisting bool `json:"preexisting,omitempty"`
}

const (
	validateTimeout = 20 * time.Second
	validateOutMax  = 4 << 10
)

var unitSuffixes = []string{".service", ".socket", ".timer", ".mount", ".automount", ".path", ".target", ".slice", ".swap"}

// ValidatorFor returns the validator for the canonical path p, or nil.
func ValidatorFor(p string) *Validator {
	dir, base := path.Dir(p), path.Base(p)
	switch {
	case p == "/etc/ssh/sshd_config" || (dir == "/etc/ssh/sshd_config.d" && strings.HasSuffix(base, ".conf")):
		return &Validator{Tool: "sshd -t", bin: "/usr/sbin/sshd", args: func(string) []string { return []string{"-t"} }}
	case p == "/etc/sudoers" || dir == "/etc/sudoers.d":
		return &Validator{Tool: "visudo -c", Pre: true, Blocking: true, bin: "/usr/sbin/visudo",
			args: func(f string) []string { return []string{"-c", "-q", "-f", f} }}
	case strings.HasPrefix(p, "/etc/nginx/"):
		return &Validator{Tool: "nginx -t", bin: "/usr/sbin/nginx", args: func(string) []string { return []string{"-t", "-q"} }}
	case p == "/etc/fstab":
		return &Validator{Tool: "findmnt --verify", bin: "/usr/bin/findmnt", args: func(string) []string { return []string{"--verify"} }}
	case strings.HasPrefix(p, "/etc/systemd/system/") && !strings.Contains(strings.TrimPrefix(dir, "/etc/systemd/system"), ".d"):
		for _, s := range unitSuffixes {
			if strings.HasSuffix(base, s) {
				return &Validator{Tool: "systemd-analyze verify", bin: "/usr/bin/systemd-analyze",
					args: func(f string) []string { return []string{"verify", "--", f} }}
			}
		}
	}
	return nil
}

// Run executes the check on file (a private copy for Pre validators, the
// live path otherwise). shown replaces the copy's path in the output.
func (v *Validator) Run(ctx context.Context, file, shown string) Validation {
	res := Validation{Tool: v.Tool, Blocking: v.Blocking}
	if _, err := os.Stat(v.bin); err != nil {
		res.OK, res.Skipped = true, true
		return res
	}
	r, err := execx.Run(ctx, validateTimeout, validateOutMax, nil, v.bin, v.args(file)...)
	out := string(r.Stdout) + string(r.Stderr)
	if file != shown {
		out = strings.ReplaceAll(out, file, shown)
	}
	res.Output = cleanOutput(out)
	res.OK = err == nil && r.ExitCode == 0
	if err != nil && res.Output == "" {
		res.Output = v.Tool + ": " + err.Error()
	}
	return res
}

// cleanOutput keeps printable text (tabs and newlines allowed), limited in size.
func cleanOutput(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= validateOutMax {
			b.WriteString("…")
			break
		}
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && !(r >= 0x80 && r < 0xa0)) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// preCopy writes data into a fresh private directory (below the helper's
// state directory) under the original base name, for Pre validators.
func preCopy(stateDir, base string, data []byte) (string, func(), error) {
	tmpRoot := filepath.Join(stateDir, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return "", nil, err
	}
	d, err := os.MkdirTemp(tmpRoot, "validate-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(d) }
	f := filepath.Join(d, base)
	if err := os.WriteFile(f, data, 0o440); err != nil { //nolint:gosec // private 0700 directory
		cleanup()
		return "", nil, err
	}
	return f, cleanup, nil
}
