package apt

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// UnattendedFile is the configuration Daemonica manages. It sorts after the
// distribution's 20auto-upgrades and 50unattended-upgrades, so its values win.
const UnattendedFile = "/etc/apt/apt.conf.d/52daemonica-unattended-upgrades"

// UnattendedLog is the result log of unattended-upgrade.
const UnattendedLog = "/var/log/unattended-upgrades/unattended-upgrades.log"

// UnattendedBin is the unattended-upgrade program.
var UnattendedBin = "/usr/bin/unattended-upgrade"

const managedMarker = "// Managed by Daemonica"

// Unattended is the wanted configuration.
type Unattended struct {
	Enabled    bool   `json:"enabled"`
	AutoReboot bool   `json:"auto_reboot"`
	RebootTime string `json:"reboot_time"` // HH:MM
}

var hhmm = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Valid reports whether u can be written.
func (u Unattended) Valid() bool { return !u.AutoReboot || hhmm.MatchString(u.RebootTime) }

// Distro is the distribution from os-release.
type Distro struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Codename string `json:"codename"`
	Pretty   string `json:"pretty"`
}

// ReadDistro reads etc/os-release below root.
func ReadDistro(root string) Distro {
	b, _ := os.ReadFile(filepath.Join(root, "etc/os-release")) //nolint:gosec // fixed path
	var d Distro
	for l := range strings.SplitSeq(string(b), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = clip(strings.Trim(v, `"'`), 100)
		switch k {
		case "ID":
			d.ID = v
		case "VERSION_ID":
			d.Version = v
		case "VERSION_CODENAME":
			d.Codename = v
		case "PRETTY_NAME":
			d.Pretty = v
		}
	}
	return d
}

// SecurityOrigins are the unattended-upgrades origin patterns for the
// security archives of a distribution (ID from os-release).
func SecurityOrigins(id string) ([]string, error) {
	switch id {
	case "debian":
		return []string{
			"origin=Debian,codename=${distro_codename}-security,label=Debian-Security",
			"origin=Debian,codename=${distro_codename},label=Debian-Security",
		}, nil
	case "ubuntu":
		return []string{
			"origin=Ubuntu,archive=${distro_codename}-security",
			"origin=UbuntuESMApps,archive=${distro_codename}-apps-security",
			"origin=UbuntuESM,archive=${distro_codename}-infra-security",
		}, nil
	}
	return nil, fmt.Errorf("unsupported distribution %q", id)
}

// RenderUnattended renders the managed file: security archives only, the
// optional reboot and the periodic switches.
func RenderUnattended(u Unattended, id string) (string, error) {
	if !u.Valid() {
		return "", errors.New("invalid reboot time")
	}
	origins, err := SecurityOrigins(id)
	if err != nil {
		return "", err
	}
	on := "0"
	if u.Enabled {
		on = "1"
	}
	var b strings.Builder
	b.WriteString(managedMarker + ". Changes here are overwritten from the dashboard.\n")
	b.WriteString("// Security updates only (SPEC §7.8); see the distribution's 50unattended-upgrades for the defaults.\n\n")
	fmt.Fprintf(&b, "APT::Periodic::Update-Package-Lists %q;\n", on)
	fmt.Fprintf(&b, "APT::Periodic::Unattended-Upgrade %q;\n\n", on)
	b.WriteString("#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\n")
	b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
	for _, o := range origins {
		fmt.Fprintf(&b, "\t%q;\n", o)
	}
	b.WriteString("};\n")
	fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot %q;\n", strconv.FormatBool(u.AutoReboot))
	if u.AutoReboot {
		fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot-Time %q;\n", u.RebootTime)
	}
	return b.String(), nil
}

// AptConfig is parsed `apt-config dump` output: scalar values and lists
// (keys ending in "::").
type AptConfig struct {
	Values map[string]string
	Lists  map[string][]string
}

var dumpRE = regexp.MustCompile(`^(\S+) "(.*)";$`)

// ParseAptConfig parses apt-config dump output.
func ParseAptConfig(out string) AptConfig {
	c := AptConfig{Values: map[string]string{}, Lists: map[string][]string{}}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := dumpRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if k, ok := strings.CutSuffix(m[1], "::"); ok {
			c.Lists[k] = append(c.Lists[k], m[2])
			continue
		}
		c.Values[m[1]] = m[2]
	}
	return c
}

// on reports an APT::Periodic value as enabled ("1", or a number of days > 0).
func on(v string) bool {
	n, err := strconv.Atoi(v)
	return err == nil && n > 0 || v == "always"
}

// UnattendedStatus is the effective state of automatic updates.
type UnattendedStatus struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	// Managed: the Daemonica file exists; Wanted is its content then.
	Managed bool        `json:"managed"`
	Wanted  *Unattended `json:"wanted,omitempty"`
	// Effective values from apt-config.
	UpdateLists bool     `json:"update_lists"`
	Upgrade     bool     `json:"upgrade"`
	AutoReboot  bool     `json:"auto_reboot"`
	RebootTime  string   `json:"reboot_time,omitempty"`
	Origins     []string `json:"origins"`
	Patterns    []string `json:"patterns"`
	// SecurityOnly: every configured origin is a security archive.
	SecurityOnly bool `json:"security_only"`
	// Log is the tail of the result log; LastRun its last start line's time.
	Log     string `json:"log"`
	LastRun string `json:"last_run,omitempty"`
}

// Effective fills the effective fields from apt-config.
func (s *UnattendedStatus) Effective(c AptConfig) {
	s.UpdateLists = on(c.Values["APT::Periodic::Update-Package-Lists"])
	s.Upgrade = on(c.Values["APT::Periodic::Unattended-Upgrade"])
	s.AutoReboot = c.Values["Unattended-Upgrade::Automatic-Reboot"] == "true"
	s.RebootTime = clip(c.Values["Unattended-Upgrade::Automatic-Reboot-Time"], 20)
	s.Origins, s.Patterns = []string{}, []string{}
	for _, o := range c.Lists["Unattended-Upgrade::Allowed-Origins"] {
		s.Origins = append(s.Origins, clip(o, 200))
	}
	for _, o := range c.Lists["Unattended-Upgrade::Origins-Pattern"] {
		s.Patterns = append(s.Patterns, clip(o, 200))
	}
	s.SecurityOnly = len(s.Origins)+len(s.Patterns) > 0
	for _, o := range append(append([]string{}, s.Origins...), s.Patterns...) {
		s.SecurityOnly = s.SecurityOnly && (strings.Contains(o, "-security") || strings.Contains(o, "Debian-Security"))
	}
}

// ParseManaged reads the wanted values back from the managed file; ok is
// false when the file was not written by Daemonica.
func ParseManaged(text string) (Unattended, bool) {
	if !strings.HasPrefix(text, managedMarker) {
		return Unattended{}, false
	}
	var u Unattended
	for l := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSuffix(v, ";"), `"`)
		switch k {
		case "APT::Periodic::Unattended-Upgrade":
			u.Enabled = v == "1"
		case "Unattended-Upgrade::Automatic-Reboot":
			u.AutoReboot = v == "true"
		case "Unattended-Upgrade::Automatic-Reboot-Time":
			u.RebootTime = v
		}
	}
	return u, true
}

// LastRun returns the time of the last "Starting unattended upgrades script"
// line of the log tail ("2026-10-25 06:12:01").
func LastRun(log string) string {
	last := ""
	for l := range strings.SplitSeq(log, "\n") {
		if strings.Contains(l, "Starting unattended upgrades script") && len(l) >= 19 {
			last = l[:19]
		}
	}
	return last
}

// Tail returns at most n bytes from the end of the file, starting at a line.
func Tail(path string, n int64) string {
	f, err := os.Open(path) //nolint:gosec // fixed paths
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := max(st.Size()-n, 0)
	buf := make([]byte, st.Size()-off)
	k, _ := f.ReadAt(buf, off)
	buf = buf[:k]
	if off > 0 {
		if i := strings.IndexByte(string(buf), '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return strings.ToValidUTF8(string(buf), "")
}
