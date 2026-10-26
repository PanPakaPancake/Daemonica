package apt

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// Found is a search result.
type Found struct {
	Name      string `json:"name"`
	Summary   string `json:"summary"`
	Installed string `json:"installed,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

var termRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{1,63}$`)

// ValidTerm reports whether s is a search term (a plain word: apt-cache
// treats it as a regular expression, so only literal characters are allowed
// besides '.' and '+').
func ValidTerm(s string) bool { return termRE.MatchString(s) }

// MaxFound limits the search results.
const MaxFound = 200

// ParseSearch parses apt-cache search output ("name - summary").
func ParseSearch(out string) (list []Found, more bool) {
	list = []Found{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		n, s, ok := strings.Cut(sc.Text(), " - ")
		if !ok || !ValidName(n) {
			continue
		}
		if len(list) == MaxFound {
			return list, true
		}
		list = append(list, Found{Name: n, Summary: clip(s, 160)})
	}
	return list, false
}

// Policy is the version information of apt-cache policy.
type Policy struct {
	Installed string `json:"installed,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

// ParsePolicy parses apt-cache policy output for several packages.
func ParsePolicy(out string) map[string]Policy {
	m := map[string]Policy{}
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if l != "" && l[0] != ' ' && strings.HasSuffix(l, ":") {
			cur = strings.TrimSuffix(l, ":")
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(l), ": ")
		if !ok || cur == "" {
			continue
		}
		if v == "(none)" {
			v = ""
		}
		p := m[cur]
		switch k {
		case "Installed":
			p.Installed = clip(v, 100)
		case "Candidate":
			p.Candidate = clip(v, 100)
		default:
			continue
		}
		m[cur] = p
	}
	return m
}

func itoa(n int) string { return strconv.Itoa(n) }
