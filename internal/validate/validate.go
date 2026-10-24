// Package validate holds allowlist validators for every string that may reach
// an external program, a file path or a configuration file (SPEC §3.2 rule 7).
// Validators are deliberately strict; anything not matching is rejected.
package validate

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	linuxUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	ifaceRE     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	unitRE      = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]{1,240}\.(service|timer|socket|target|mount|path|slice|scope)$`)
	jobNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	accountRE   = regexp.MustCompile(`^[\p{L}\p{N} ._@-]{1,64}$`)
	hostnameRE  = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

// ErrInvalid is returned for any rejected input.
var ErrInvalid = errors.New("invalid input")

// LinuxUser validates a Linux user or group name.
func LinuxUser(s string) error { return match(linuxUserRE, s) }

// Interface validates a network interface name.
func Interface(s string) error {
	if strings.HasPrefix(s, "-") {
		return ErrInvalid
	}
	return match(ifaceRE, s)
}

// Unit validates a systemd unit name (no path separators, newlines or spaces).
func Unit(s string) error {
	if strings.HasPrefix(s, "-") {
		return ErrInvalid
	}
	return match(unitRE, s)
}

// JobName validates the user-chosen part of a managed job unit (daemonia-job-<name>).
func JobName(s string) error { return match(jobNameRE, s) }

// AccountName validates a dashboard account display name.
func AccountName(s string) error {
	if strings.TrimSpace(s) != s {
		return ErrInvalid
	}
	return match(accountRE, s)
}

// Hostname validates an RFC 1123 hostname / FQDN (max 253 chars).
func Hostname(s string) error {
	if len(s) > 253 {
		return ErrInvalid
	}
	return match(hostnameRE, s)
}

// Domain validates a dashboard domain: an FQDN with at least one dot, lower-case.
func Domain(s string) error {
	if s != strings.ToLower(s) || !strings.Contains(s, ".") || strings.HasSuffix(s, ".") {
		return ErrInvalid
	}
	return Hostname(s)
}

// NoControl rejects strings with control characters, NUL or invalid UTF-8.
// Used for free-text fields such as comments and descriptions.
func NoControl(s string, maxLen int) error {
	if len(s) > maxLen || !utf8.ValidString(s) {
		return ErrInvalid
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ErrInvalid
		}
	}
	return nil
}

func match(re *regexp.Regexp, s string) error {
	if !re.MatchString(s) {
		return ErrInvalid
	}
	return nil
}
