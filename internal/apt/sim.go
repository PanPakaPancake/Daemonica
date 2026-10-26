// Package apt reads and changes the package state of a Debian/Ubuntu host
// (SPEC §7.8 M1.7, DEC-031): simulations, the upgradable list with the
// security flag, package jobs in transient units, unattended-upgrades,
// needrestart and the package sources (read only).
package apt

import (
	"bufio"
	"regexp"
	"slices"
	"strings"
)

// Programs (absolute paths; execx needs them).
var (
	AptGet   = "/usr/bin/apt-get"
	AptCache = "/usr/bin/apt-cache"
	AptMark  = "/usr/bin/apt-mark"
	AptCfg   = "/usr/bin/apt-config"
	DpkgQ    = "/usr/bin/dpkg-query"
	Dpkg     = "/usr/bin/dpkg"
)

// Pkg is one package in a simulation.
type Pkg struct {
	Name string `json:"name"`
	Arch string `json:"arch,omitempty"`
	// Old is the installed version ("" for a new package).
	Old string `json:"old,omitempty"`
	// New is the version to install ("" for a removal).
	New string `json:"new,omitempty"`
	// Origins are the archives offering New, e.g. "Ubuntu:26.04/resolute-security".
	Origins  []string `json:"origins,omitempty"`
	Security bool     `json:"security"`
}

// Sim is the parsed output of apt-get -s.
type Sim struct {
	Install []Pkg `json:"install"`
	Remove  []Pkg `json:"remove"`
	// Kept lists packages apt keeps back (they need a removal or a decision).
	Kept []string `json:"kept"`
}

var (
	instRE = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) (.*?)(?: \[([^\]]+)\])?\)`)
	remvRE = regexp.MustCompile(`^(?:Remv|Purg) (\S+)(?: \[([^\]]*)\])?`)
)

// Security reports whether an archive name is a security archive (Debian:
// "…-security" or label Debian-Security, Ubuntu: "…-security", ESM:
// "…-apps-security"/"…-infra-security").
func Security(origin string) bool {
	return strings.Contains(origin, "-security") || strings.HasPrefix(origin, "Debian-Security:")
}

// ParseSim parses apt-get -s output (LANG=C).
func ParseSim(out string) Sim {
	s := Sim{Install: []Pkg{}, Remove: []Pkg{}, Kept: []string{}}
	kept := false
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if kept {
			if strings.HasPrefix(l, " ") {
				s.Kept = append(s.Kept, strings.Fields(l)...)
				continue
			}
			kept = false
		}
		switch {
		case strings.HasPrefix(l, "The following packages have been kept back:"):
			kept = true
		case strings.HasPrefix(l, "Inst "):
			m := instRE.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			p := Pkg{Name: m[1], Old: m[2], New: m[3], Arch: m[5]}
			for o := range strings.SplitSeq(m[4], ", ") {
				if o = strings.TrimSpace(o); o != "" {
					p.Origins = append(p.Origins, o)
					p.Security = p.Security || Security(o)
				}
			}
			s.Install = append(s.Install, p)
		case strings.HasPrefix(l, "Remv "), strings.HasPrefix(l, "Purg "):
			if m := remvRE.FindStringSubmatch(l); m != nil {
				s.Remove = append(s.Remove, Pkg{Name: m[1], Old: m[2]})
			}
		}
	}
	return s
}

// Names returns the sorted names of ps.
func Names(ps []Pkg) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,99}(:[a-z0-9-]{1,20})?$`)

// ValidName reports whether s is a package name (optionally with :arch).
func ValidName(s string) bool { return nameRE.MatchString(s) }

// critical are packages whose removal can cut off access to the host or
// break it; removing them needs an explicit acknowledgement.
var critical = []string{
	"openssh-server", "openssh-client", "systemd", "systemd-sysv", "init", "sudo", "sudo-rs", "apt", "dpkg",
	"libc6", "login", "passwd", "bash", "coreutils", "dbus", "netplan.io", "ifupdown", "network-manager",
	"systemd-resolved", "ufw", "nftables", "iptables", "grub-pc", "grub-efi-amd64", "grub-efi-arm64", "shim-signed",
	"linux-image-generic", "linux-generic", "linux-image-amd64", "linux-image-arm64", "ca-certificates",
}

// Protected is the package that may never be removed through Daemonica.
const Protected = "daemonica"

// Critical returns the critical packages among the removals; running is the
// running kernel release (uname -r), whose image is critical as well.
func Critical(remove []Pkg, running string) []string {
	var out []string
	for _, p := range remove {
		n, _, _ := strings.Cut(p.Name, ":")
		if slices.Contains(critical, n) || (running != "" && strings.HasSuffix(n, "-"+running) &&
			(strings.HasPrefix(n, "linux-image-") || strings.HasPrefix(n, "linux-modules-"))) {
			out = append(out, p.Name)
		}
	}
	return out
}
