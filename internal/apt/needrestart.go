package apt

import (
	"bufio"
	"regexp"
	"slices"
	"strings"
)

// NeedRestart is `needrestart -b` (batch mode) output.
type NeedRestart struct {
	Available bool `json:"available"`
	// Kernel: 0 unknown, 1 current, 2 ABI-compatible upgrade, 3 newer version pending.
	Kernel        int      `json:"kernel"`
	KernelCurrent string   `json:"kernel_current,omitempty"`
	KernelExpect  string   `json:"kernel_expected,omitempty"`
	Microcode     int      `json:"microcode"`
	Services      []string `json:"services"`
	Containers    []string `json:"containers"`
	Sessions      []string `json:"sessions"`
}

// NeedRestartBin is the needrestart program.
var NeedRestartBin = "/usr/sbin/needrestart"

var unitRE = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]{1,200}$`)

// ParseNeedRestart parses needrestart -b output.
func ParseNeedRestart(out string) NeedRestart {
	n := NeedRestart{Available: true, Services: []string{}, Containers: []string{}, Sessions: []string{}}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "NEEDRESTART-KSTA":
			n.Kernel = digit(v)
		case "NEEDRESTART-UCSTA":
			n.Microcode = digit(v)
		case "NEEDRESTART-KCUR":
			n.KernelCurrent = clip(v, 100)
		case "NEEDRESTART-KEXP":
			n.KernelExpect = clip(v, 100)
		case "NEEDRESTART-SVC":
			if unitRE.MatchString(v) {
				n.Services = append(n.Services, v)
			}
		case "NEEDRESTART-CONT":
			n.Containers = append(n.Containers, clip(v, 200))
		case "NEEDRESTART-SESS":
			n.Sessions = append(n.Sessions, clip(v, 200))
		}
	}
	slices.Sort(n.Services)
	n.Services = slices.Compact(n.Services)
	return n
}

func digit(s string) int {
	if len(s) == 1 && s[0] >= '0' && s[0] <= '9' {
		return int(s[0] - '0')
	}
	return 0
}

// clip removes control characters and limits s to max bytes.
func clip(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

func sortStrings(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
