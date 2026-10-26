package apt

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Source is one package source entry (shown only; SPEC §7.8).
type Source struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Format string `json:"format"` // "one-line" or "deb822"
	// Enabled is false for "Enabled: no" stanzas and commented-out lines are skipped.
	Enabled    bool     `json:"enabled"`
	Types      []string `json:"types"`
	URIs       []string `json:"uris"`
	Suites     []string `json:"suites"`
	Components []string `json:"components"`
	SignedBy   string   `json:"signed_by,omitempty"`
	// HTTPS: every URI uses https (or a local scheme).
	HTTPS bool `json:"https"`
	// Official: every URI is a known distribution host (D-19).
	Official bool `json:"official"`
}

// SourceFile is a file in the source configuration with its problems.
type SourceFile struct {
	Path    string   `json:"path"`
	Entries int      `json:"entries"`
	Errors  []string `json:"errors,omitempty"`
}

// Sources is the parsed source configuration.
type Sources struct {
	Entries []Source     `json:"entries"`
	Files   []SourceFile `json:"files"`
}

// officialHosts are distribution archive hosts (and their subdomains).
var officialHosts = []string{
	"deb.debian.org", "security.debian.org", "ftp.debian.org", "debian.org",
	"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "esm.ubuntu.com", "ubuntu.com",
}

func official(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := strings.ToLower(p.Hostname())
	return slices.ContainsFunc(officialHosts, func(o string) bool { return h == o || strings.HasSuffix(h, "."+o) })
}

func secure(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "file:") || strings.HasPrefix(u, "cdrom:")
}

func finish(s *Source) {
	s.HTTPS, s.Official = len(s.URIs) > 0, len(s.URIs) > 0
	for _, u := range s.URIs {
		s.HTTPS = s.HTTPS && secure(u)
		s.Official = s.Official && official(u)
	}
}

// ReadSources reads /etc/apt/sources.list and sources.list.d below root.
func ReadSources(root string) Sources {
	res := Sources{Entries: []Source{}, Files: []SourceFile{}}
	files := []string{filepath.Join(root, "etc/apt/sources.list")}
	d, _ := filepath.Glob(filepath.Join(root, "etc/apt/sources.list.d/*"))
	slices.Sort(d)
	files = append(files, d...)
	for _, f := range files {
		var ents []Source
		var errs []string
		switch {
		case strings.HasSuffix(f, ".list"):
			b, err := os.ReadFile(f) //nolint:gosec // fixed directory
			if err != nil {
				continue
			}
			ents, errs = ParseList(string(b))
		case strings.HasSuffix(f, ".sources"):
			b, err := os.ReadFile(f) //nolint:gosec // fixed directory
			if err != nil {
				continue
			}
			ents, errs = ParseDeb822(string(b))
		default:
			continue
		}
		rel := strings.TrimPrefix(f, strings.TrimSuffix(root, "/"))
		for i := range ents {
			ents[i].File = rel
		}
		res.Entries = append(res.Entries, ents...)
		res.Files = append(res.Files, SourceFile{Path: rel, Entries: len(ents), Errors: errs})
	}
	return res
}

// ParseList parses a one-line style file ("deb [opts] uri suite comp…").
func ParseList(text string) ([]Source, []string) {
	var out []Source
	var errs []string
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		typ, rest, _ := strings.Cut(l, " ")
		if typ != "deb" && typ != "deb-src" {
			errs = append(errs, clip("line "+itoa(n)+": "+l, 200))
			continue
		}
		s := Source{Line: n, Format: "one-line", Enabled: true, Types: []string{typ}}
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				errs = append(errs, clip("line "+itoa(n)+": "+l, 200))
				continue
			}
			for o := range strings.FieldsSeq(rest[1:end]) {
				if v, ok := strings.CutPrefix(o, "signed-by="); ok {
					s.SignedBy = v
				}
			}
			rest = rest[end+1:]
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			errs = append(errs, clip("line "+itoa(n)+": "+l, 200))
			continue
		}
		s.URIs, s.Suites, s.Components = f[:1], f[1:2], f[2:]
		finish(&s)
		out = append(out, s)
	}
	return out, errs
}

// ParseDeb822 parses a deb822 .sources file (stanzas separated by blank lines).
func ParseDeb822(text string) ([]Source, []string) {
	var out []Source
	var errs []string
	fields := map[string]string{}
	start, last := 0, ""
	flush := func() {
		if len(fields) == 0 {
			return
		}
		s := Source{Line: start, Format: "deb822", Enabled: !strings.EqualFold(fields["enabled"], "no"),
			Types: strings.Fields(fields["types"]), URIs: strings.Fields(fields["uris"]),
			Suites: strings.Fields(fields["suites"]), Components: strings.Fields(fields["components"])}
		if sb := strings.TrimSpace(fields["signed-by"]); sb != "" {
			if strings.Contains(sb, "\n") || strings.HasPrefix(sb, "-----BEGIN") {
				sb = "(embedded key)"
			}
			s.SignedBy = sb
		}
		if len(s.Types) == 0 || len(s.URIs) == 0 || len(s.Suites) == 0 {
			errs = append(errs, "stanza at line "+itoa(start)+": Types, URIs and Suites are required")
		} else {
			finish(&s)
			out = append(out, s)
		}
		fields = map[string]string{}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		raw := sc.Text()
		if strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.TrimSpace(raw) == "" {
			flush()
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			if last != "" {
				fields[last] += "\n" + strings.TrimSpace(raw)
			}
			continue
		}
		k, v, ok := strings.Cut(raw, ":")
		if !ok {
			errs = append(errs, clip("line "+itoa(n)+": "+raw, 200))
			continue
		}
		if len(fields) == 0 {
			start = n
		}
		last = strings.ToLower(strings.TrimSpace(k))
		fields[last] = strings.TrimSpace(v)
	}
	flush()
	return out, errs
}
