package timehost

import (
	"os"
	"slices"
	"strings"
)

// HostsPath is the file kept consistent with the host name.
const HostsPath = "/etc/hosts"

// RenameHosts returns the hosts text with the host name changed from old to
// new on the Debian-style 127.0.1.1 line: names equal to old or starting
// with "old." are renamed, other aliases stay. If there is no 127.0.1.1
// line, one is added after the localhost lines. Other lines are untouched.
func RenameHosts(text, old, new string) string {
	lines := strings.Split(text, "\n")
	found := false
	for i, l := range lines {
		body, comment, _ := strings.Cut(l, "#")
		f := strings.Fields(body)
		if len(f) < 1 || f[0] != "127.0.1.1" {
			continue
		}
		found = true
		names := []string{}
		for _, n := range f[1:] {
			switch {
			case old != "" && n == old:
				n = new
			case old != "" && strings.HasPrefix(n, old+"."):
				n = new + strings.TrimPrefix(n, old)
			}
			names = append(names, n)
		}
		if !containsName(names, new) {
			names = append(names, new)
		}
		if slices.Equal(names, f[1:]) {
			continue // unchanged: keep the line as written
		}
		nl := "127.0.1.1\t" + strings.Join(names, " ")
		if strings.TrimSpace(comment) != "" {
			nl += "\t#" + comment
		}
		lines[i] = nl
	}
	if found {
		return strings.Join(lines, "\n")
	}
	// Insert after the last localhost line (or at the top).
	at := 0
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == "127.0.0.1" || f[0] == "::1") {
			at = i + 1
			break
		}
	}
	out := append([]string{}, lines[:at]...)
	out = append(out, "127.0.1.1\t"+new)
	out = append(out, lines[at:]...)
	return strings.Join(out, "\n")
}

func containsName(names []string, n string) bool {
	for _, x := range names {
		if x == n || strings.HasPrefix(x, n+".") {
			return true
		}
	}
	return false
}

// CloudInitResets reports whether cloud-init may set the host name back at
// boot (installed and preserve_hostname not set to true).
func CloudInitResets(root string) bool {
	b, err := os.ReadFile(root + "/etc/cloud/cloud.cfg") //nolint:gosec // fixed path
	if err != nil {
		return false
	}
	if preserve(string(b)) {
		return false
	}
	ds, _ := os.ReadDir(root + "/etc/cloud/cloud.cfg.d")
	for _, d := range ds {
		if c, err := os.ReadFile(root + "/etc/cloud/cloud.cfg.d/" + d.Name()); err == nil && preserve(string(c)) { //nolint:gosec // fixed dir
			return false
		}
	}
	return true
}

func preserve(s string) bool {
	for l := range strings.SplitSeq(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if ok && strings.TrimSpace(k) == "preserve_hostname" && strings.EqualFold(strings.TrimSpace(v), "true") {
			return true
		}
	}
	return false
}
