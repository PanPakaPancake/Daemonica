package disks

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// FstabPath is the file edited.
const FstabPath = "/etc/fstab"

// Entry is one fstab line.
type Entry struct {
	Spec    string `json:"spec"`    // UUID=…, LABEL=…, PARTUUID=…, /dev/…, tmpfs …
	File    string `json:"file"`    // mount point, or "none"/"swap" for swap
	Type    string `json:"type"`    // ext4, xfs, swap, tmpfs, nfs …
	Options string `json:"options"` // comma-separated
	Freq    int    `json:"freq"`
	Pass    int    `json:"pass"`
	// Line is the 1-based line in the original file (0 for a new entry).
	Line int `json:"line"`
}

// Fstab is a parsed fstab: the entries and the original text, so that
// comments and unchanged lines survive an edit.
type Fstab struct {
	Entries []Entry `json:"entries"`
	Text    string  `json:"text"`
	// Errors are lines that are not valid entries (kept as they are).
	Errors []string `json:"errors,omitempty"`
}

// unescape decodes \040-style octal escapes.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
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

// escape encodes whitespace and backslashes for an fstab field.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\\', '#':
			fmt.Fprintf(&b, `\%03o`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ParseFstab parses fstab text.
func ParseFstab(text string) Fstab {
	f := Fstab{Entries: []Entry{}, Text: text}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		fs := strings.Fields(l)
		if len(fs) < 3 || len(fs) > 6 {
			f.Errors = append(f.Errors, clip(fmt.Sprintf("line %d: %s", n, l), 300))
			continue
		}
		e := Entry{Spec: unescape(fs[0]), File: unescape(fs[1]), Type: fs[2], Options: "defaults", Line: n}
		if len(fs) > 3 {
			e.Options = fs[3]
		}
		if len(fs) > 4 {
			e.Freq, _ = strconv.Atoi(fs[4])
		}
		if len(fs) > 5 {
			e.Pass, _ = strconv.Atoi(fs[5])
		}
		f.Entries = append(f.Entries, e)
	}
	return f
}

// Format renders an entry as an fstab line.
func (e Entry) Format() string {
	opts := e.Options
	if opts == "" {
		opts = "defaults"
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%d", escape(e.Spec), escape(e.File), e.Type, opts, e.Freq, e.Pass)
}

func (e Entry) same(o Entry) bool {
	return e.Spec == o.Spec && e.File == o.File && e.Type == o.Type && e.Options == o.Options && e.Freq == o.Freq && e.Pass == o.Pass
}

// Render builds the new file from the original text: comments, blank and
// unparsable lines stay, unchanged entries keep their formatting, changed
// entries are rewritten in place, removed ones dropped, new ones appended.
func Render(orig Fstab, entries []Entry) string {
	byLine := map[int]Entry{}
	for _, e := range entries {
		if e.Line > 0 {
			byLine[e.Line] = e
		}
	}
	oldByLine := map[int]Entry{}
	for _, e := range orig.Entries {
		oldByLine[e.Line] = e
	}
	var b strings.Builder
	lines := strings.Split(strings.TrimSuffix(orig.Text, "\n"), "\n")
	if orig.Text == "" {
		lines = nil
	}
	for i, l := range lines {
		n := i + 1
		old, isEntry := oldByLine[n]
		if !isEntry {
			b.WriteString(l + "\n")
			continue
		}
		cur, kept := byLine[n]
		switch {
		case !kept:
		case cur.same(old):
			b.WriteString(l + "\n")
		default:
			b.WriteString(cur.Format() + "\n")
		}
	}
	added := false
	for _, e := range entries {
		if e.Line == 0 {
			if !added && b.Len() > 0 && !strings.HasSuffix(b.String(), "\n\n") {
				b.WriteString("\n# Added by Daemonica\n")
			}
			added = true
			b.WriteString(e.Format() + "\n")
		}
	}
	return b.String()
}

// Problem is a validation finding for one entry (Index into the list, -1
// for the whole file).
type Problem struct {
	Index int    `json:"index"`
	Field string `json:"field,omitempty"`
	Code  string `json:"code"`
	// Msg is findmnt's message (for code "verify").
	Msg string `json:"msg,omitempty"`
	// Warning: shown but does not block saving.
	Warning bool `json:"warning,omitempty"`
}

var (
	specRE    = regexp.MustCompile(`^((UUID|PARTUUID|LABEL|PARTLABEL|ID)=[A-Za-z0-9._:+@ -]{1,128}|/dev/[A-Za-z0-9._/:+-]{1,200}|[A-Za-z0-9._-]{1,64}|[A-Za-z0-9._-]+:/[^\s]{0,400}|//[^\s/]+/[^\s]{1,400})$`)
	typeRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	optsRE    = regexp.MustCompile(`^[A-Za-z0-9_.,=:/@+%-]{1,500}$`)
	pathRE    = regexp.MustCompile(`^/[^\x00-\x1f\x7f]{0,1000}$`)
	summaryRE = regexp.MustCompile(`^\d+ parse errors?, `)
	optItem   = regexp.MustCompile(`^[A-Za-z0-9_.-]+(=[^,]*)?$`)
)

// Validate checks the entries (format only; findmnt --verify checks them
// against the system). The original entries are needed for the root rule.
func Validate(entries []Entry, orig []Entry) []Problem {
	var ps []Problem
	seen := map[string]bool{}
	for i, e := range entries {
		add := func(field, code string, warn bool) {
			ps = append(ps, Problem{Index: i, Field: field, Code: code, Warning: warn})
		}
		if !specRE.MatchString(e.Spec) {
			add("spec", "invalid", false)
		}
		swap := e.Type == "swap"
		switch {
		case swap && (e.File == "none" || e.File == "swap"):
		case !pathRE.MatchString(e.File) || filepath.Clean(e.File) != e.File:
			add("file", "invalid", false)
		}
		if !typeRE.MatchString(e.Type) {
			add("type", "invalid", false)
		}
		if e.Options != "" {
			if !optsRE.MatchString(e.Options) {
				add("options", "invalid", false)
			} else {
				for o := range strings.SplitSeq(e.Options, ",") {
					if !optItem.MatchString(o) {
						add("options", "invalid", false)
						break
					}
				}
			}
		}
		if e.Freq < 0 || e.Freq > 1 {
			add("freq", "invalid", false)
		}
		if e.Pass < 0 || e.Pass > 2 {
			add("pass", "invalid", false)
		}
		if !swap && e.File != "none" {
			if seen[e.File] && !strings.Contains(","+e.Options+",", ",noauto,") {
				add("file", "duplicate", false)
			}
			seen[e.File] = true
		}
		opts := ","
		if e.Options != "" {
			opts += e.Options + ","
		}
		kernelName := slices.ContainsFunc([]string{"/dev/sd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/hd", "/dev/mmcblk"}, func(p string) bool { return strings.HasPrefix(e.Spec, p) })
		if kernelName {
			add("spec", "prefer_uuid", true)
		}
		// A data disk that is missing at boot must not stop the boot.
		data := !swap && e.File != "none" && (kernelName || strings.Contains(e.Spec, "UUID=") || strings.Contains(e.Spec, "LABEL="))
		if data && !slices.Contains(systemMounts, e.File) && !strings.Contains(opts, ",nofail,") && !strings.Contains(opts, ",noauto,") {
			add("options", "nofail_recommended", true)
		}
	}
	hadRoot := slices.ContainsFunc(orig, func(e Entry) bool { return e.File == "/" })
	if hadRoot && !slices.ContainsFunc(entries, func(e Entry) bool { return e.File == "/" }) {
		ps = append(ps, Problem{Index: -1, Code: "root_missing"})
	}
	return ps
}

// systemMounts must come up at boot; nofail is not recommended for them.
var systemMounts = []string{"/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/var/log", "/var/lib", "/home", "/tmp"}

// Blocking reports whether any problem blocks saving.
func Blocking(ps []Problem) bool {
	return slices.ContainsFunc(ps, func(p Problem) bool { return !p.Warning })
}

// Verify writes text to a temporary file and runs findmnt --verify on it.
// Errors block saving, warnings are shown.
func Verify(ctx context.Context, run Run, text string) ([]Problem, error) {
	dir, err := os.MkdirTemp("", "daemonica-fstab-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	f := filepath.Join(dir, "fstab")
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		return nil, err
	}
	res, err := run(ctx, time.Minute, Findmnt, "--verify", "--tab-file", f)
	if err != nil {
		return nil, err
	}
	return ParseVerify(string(res.Stdout)+"\n"+string(res.Stderr), f), nil
}

// ParseVerify parses findmnt --verify output: a target line followed by
// indented "[E] …"/"[W] …" lines; parse errors name the file.
func ParseVerify(out, file string) []Problem {
	ps := []Problem{}
	target := ""
	for l := range strings.SplitSeq(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "":
		case strings.HasPrefix(t, "[E]"), strings.HasPrefix(t, "[W]"):
			msg := strings.TrimSpace(t[3:])
			if target != "" {
				msg = target + ": " + msg
			}
			ps = append(ps, Problem{Index: -1, Code: "verify", Msg: clip(msg, 400), Warning: strings.HasPrefix(t, "[W]")})
		case summaryRE.MatchString(t), strings.HasPrefix(t, "["), strings.HasPrefix(t, "Success"):
		case strings.Contains(t, "parse error"):
			ps = append(ps, Problem{Index: -1, Code: "verify", Msg: clip(strings.ReplaceAll(t, file, "fstab"), 400)})
		case l == t:
			target = clip(t, 300)
		}
	}
	return ps
}
