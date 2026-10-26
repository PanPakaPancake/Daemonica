package timehost

import (
	"os"
	"slices"
	"strings"
)

// HostsPath is the file kept consistent with the host name.
const HostsPath = "/etc/hosts"

// RenameHosts returns the hosts text with the host name changed from old to
// new on the Debian-style 127.0.1.1 lines: names equal to old or starting
// with "old." are renamed, other aliases and lines stay as written. If no
// 127.0.1.1 line names the new host afterwards, it is added to the last such
// line, or a line is added after the localhost lines.
func RenameHosts(text, old, new string) string {
	lines := strings.Split(text, "\n")
	last := -1
	found := false
	for i, l := range lines {
		body, comment, _ := strings.Cut(l, "#")
		f := strings.Fields(body)
		if len(f) < 1 || f[0] != "127.0.1.1" {
			continue
		}
		last = i
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
		found = found || containsName(names, new)
		if slices.Equal(names, f[1:]) {
			continue // unchanged: keep the line as written
		}
		lines[i] = hostsLine(names, comment)
	}
	if found {
		return strings.Join(lines, "\n")
	}
	if last >= 0 {
		body, comment, _ := strings.Cut(lines[last], "#")
		lines[last] = hostsLine(append(strings.Fields(body)[1:], new), comment)
		return strings.Join(lines, "\n")
	}
	// Insert after the first localhost line (or at the top).
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

func hostsLine(names []string, comment string) string {
	l := "127.0.1.1\t" + strings.Join(names, " ")
	if strings.TrimSpace(comment) != "" {
		l += "\t#" + comment
	}
	return l
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

// CloudInitManagesHosts reports whether cloud-init rewrites /etc/hosts from
// its template at boot (manage_etc_hosts true or localhost).
func CloudInitManagesHosts(root string) bool {
	on := false
	files := []string{root + "/etc/cloud/cloud.cfg"}
	ds, _ := os.ReadDir(root + "/etc/cloud/cloud.cfg.d")
	for _, d := range ds {
		files = append(files, root+"/etc/cloud/cloud.cfg.d/"+d.Name())
	}
	for _, f := range files { // later files win, like cloud-init's merge
		b, err := os.ReadFile(f) //nolint:gosec // fixed dir
		if err != nil {
			continue
		}
		for l := range strings.SplitSeq(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
			if ok && strings.TrimSpace(k) == "manage_etc_hosts" {
				v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`))
				on = v == "true" || v == "localhost"
			}
		}
	}
	return on
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
