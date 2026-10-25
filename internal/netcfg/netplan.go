package netcfg

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Netplan edits netplan YAML (Ubuntu's default). The file that defines the
// interface is changed in place (comments and other keys are kept); an
// interface defined nowhere gets /etc/netplan/90-daemonica.yaml.
type Netplan struct {
	Root string
	Run  Runner
}

// NetplanOwnFile receives interfaces that no file defines yet.
const NetplanOwnFile = "/etc/netplan/90-daemonica.yaml"

var netplanDirs = []string{"/lib/netplan", "/etc/netplan", "/run/netplan"}

// deviceKeys are netplan's device sections whose addressing Daemonica edits.
var deviceKeys = []string{"ethernets", "vlans", "bridges", "bonds", "wifis"}

type npFile struct {
	path string // without Root
	doc  *yaml.Node
	raw  string
}

func (n *Netplan) files() ([]npFile, error) {
	// netplan merges files ordered by name; same names in later dirs win.
	byName := map[string]string{}
	for _, dir := range netplanDirs {
		m, _ := filepath.Glob(filepath.Join(n.Root, dir, "*.yaml"))
		for _, f := range m {
			byName[filepath.Base(f)] = strings.TrimPrefix(f, n.Root)
		}
	}
	names := make([]string, 0, len(byName))
	for k := range byName {
		names = append(names, k)
	}
	slices.Sort(names)
	var out []npFile
	for _, k := range names {
		p := byName[k]
		b, err := os.ReadFile(filepath.Join(n.Root, p)) //nolint:gosec // netplan directories
		if err != nil {
			return nil, err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, invalid("%s is not valid YAML", p)
		}
		out = append(out, npFile{path: p, doc: &doc, raw: string(b)})
	}
	return out, nil
}

func (n *Netplan) renderer() string {
	fs, err := n.files()
	if err != nil {
		return ""
	}
	r := "networkd"
	for _, f := range fs {
		if v := scalar(get(get(root(f.doc), "network"), "renderer")); v != "" {
			r = v
		}
	}
	return r
}

func root(doc *yaml.Node) *yaml.Node {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	return doc.Content[0]
}

// get returns the value of key in a mapping node.
func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func boolean(n *yaml.Node) bool {
	switch strings.ToLower(scalar(n)) {
	case "true", "yes", "on", "y":
		return true
	}
	return false
}

func strList(n *yaml.Node) ([]string, bool) {
	out := []string{}
	if n == nil {
		return out, true
	}
	if n.Kind != yaml.SequenceNode {
		return nil, false
	}
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode {
			return nil, false
		}
		out = append(out, c.Value)
	}
	return out, true
}

// match finds the device entry for an interface: by id, set-name, match.name or match.macaddress.
func matchEntry(dev *yaml.Node, id, name, mac string) bool {
	m := get(dev, "match")
	if m == nil {
		return id == name
	}
	if s := scalar(get(dev, "set-name")); s != "" {
		return s == name
	}
	if v := scalar(get(m, "name")); v != "" {
		return v == name
	}
	if v := scalar(get(m, "macaddress")); v != "" && mac != "" {
		return strings.EqualFold(v, mac)
	}
	return false
}

type npEntry struct {
	file    int
	section string
	id      string
	node    *yaml.Node
}

func (n *Netplan) find(fs []npFile, name, mac string) []npEntry {
	var out []npEntry
	for i, f := range fs {
		nw := get(root(f.doc), "network")
		for _, sec := range deviceKeys {
			s := get(nw, sec)
			if s == nil || s.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(s.Content); j += 2 {
				if matchEntry(s.Content[j+1], s.Content[j].Value, name, mac) {
					out = append(out, npEntry{file: i, section: sec, id: s.Content[j].Value, node: s.Content[j+1]})
				}
			}
		}
	}
	return out
}

var npRouteKeys = []string{"to", "via", "metric"}

// readEntry extracts the editable settings; ok=false when the entry uses
// settings Daemonica does not edit (they would be lost or misread).
func readEntry(name string, dev *yaml.Node) (IfaceConfig, bool) {
	c := IfaceConfig{Name: name, DHCP4: boolean(get(dev, "dhcp4")), DHCP6: boolean(get(dev, "dhcp6")), Routes: []StaticRoute{}}
	ok := true
	var good bool
	if c.Addresses, good = strList(get(dev, "addresses")); !good {
		c.Addresses, ok = []string{}, false
	}
	c.Gateway4, c.Gateway6 = scalar(get(dev, "gateway4")), scalar(get(dev, "gateway6"))
	ns := get(dev, "nameservers")
	if c.DNS, good = strList(get(ns, "addresses")); !good {
		c.DNS, ok = []string{}, false
	}
	if c.Search, good = strList(get(ns, "search")); !good {
		c.Search, ok = []string{}, false
	}
	if v := scalar(get(dev, "mtu")); v != "" {
		c.MTU, _ = strconv.Atoi(v)
	}
	if rs := get(dev, "routes"); rs != nil {
		if rs.Kind != yaml.SequenceNode {
			return c, false
		}
		for _, r := range rs.Content {
			if r.Kind != yaml.MappingNode {
				return c, false
			}
			for i := 0; i < len(r.Content); i += 2 {
				if !slices.Contains(npRouteKeys, r.Content[i].Value) {
					ok = false
				}
			}
			sr := StaticRoute{To: scalar(get(r, "to")), Via: scalar(get(r, "via"))}
			sr.Metric, _ = strconv.Atoi(scalar(get(r, "metric")))
			if sr.To == "0.0.0.0/0" || sr.To == "::/0" {
				sr.To = "default"
			}
			if sr.To == "default" && sr.Metric == 0 && sr.Via != "" {
				if strings.Contains(sr.Via, ":") && c.Gateway6 == "" {
					c.Gateway6 = sr.Via
					continue
				}
				if !strings.Contains(sr.Via, ":") && c.Gateway4 == "" {
					c.Gateway4 = sr.Via
					continue
				}
			}
			c.Routes = append(c.Routes, sr)
		}
	}
	return c, ok
}

// Config implements Backend.
func (n *Netplan) Config(name, mac string) (IfaceConfig, error) {
	fs, err := n.files()
	if err != nil {
		return IfaceConfig{}, err
	}
	es := n.find(fs, name, mac)
	switch len(es) {
	case 0:
		return IfaceConfig{Name: name, Addresses: []string{}, DNS: []string{}, Search: []string{}, Routes: []StaticRoute{},
			Editable: true, Reason: "not_configured", Source: NetplanOwnFile}, nil
	case 1:
	default:
		c, _ := readEntry(name, es[len(es)-1].node)
		c.Source, c.Reason = fs[es[len(es)-1].file].path, "several_files"
		return c, nil
	}
	c, ok := readEntry(name, es[0].node)
	c.Source, c.Editable = fs[es[0].file].path, ok
	if !ok {
		c.Reason = "advanced"
	}
	return c, nil
}

func setKey(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			if v == nil {
				m.Content = append(m.Content[:i], m.Content[i+2:]...)
			} else {
				old := m.Content[i+1]
				v.HeadComment, v.LineComment = old.HeadComment, old.LineComment
				if old.Kind == v.Kind && v.Kind == yaml.SequenceNode {
					v.Style = old.Style // keep block or flow as the file had it
				}
				m.Content[i+1] = v
			}
			return
		}
	}
	if v != nil {
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	}
}

func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
func intN(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)}
}
func boolN(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(v)}
}
func mapN() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }
func seqN(style yaml.Style) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: style}
}

func strSeq(items []string) *yaml.Node {
	if len(items) == 0 {
		return nil
	}
	s := seqN(0)
	for _, it := range items {
		s.Content = append(s.Content, str(it))
	}
	return s
}

// writeEntry stores cfg in the device mapping.
func writeEntry(dev *yaml.Node, cfg IfaceConfig) {
	opt := func(b bool) *yaml.Node {
		if b {
			return boolN(true)
		}
		return nil
	}
	setKey(dev, "dhcp4", opt(cfg.DHCP4))
	setKey(dev, "dhcp6", opt(cfg.DHCP6))
	setKey(dev, "addresses", strSeq(cfg.Addresses))
	setKey(dev, "gateway4", nil) // deprecated: written as default routes
	setKey(dev, "gateway6", nil)
	routes := slices.Clone(cfg.Routes)
	if cfg.Gateway6 != "" {
		routes = append([]StaticRoute{{To: "default", Via: cfg.Gateway6}}, routes...)
	}
	if cfg.Gateway4 != "" {
		routes = append([]StaticRoute{{To: "default", Via: cfg.Gateway4}}, routes...)
	}
	if len(routes) == 0 {
		setKey(dev, "routes", nil)
	} else {
		rs := seqN(0)
		for _, r := range routes {
			m := mapN()
			setKey(m, "to", str(r.To))
			setKey(m, "via", str(r.Via))
			if r.Metric > 0 {
				setKey(m, "metric", intN(r.Metric))
			}
			rs.Content = append(rs.Content, m)
		}
		setKey(dev, "routes", rs)
	}
	ns := get(dev, "nameservers")
	if ns == nil {
		ns = mapN()
	}
	setKey(ns, "addresses", strSeq(cfg.DNS))
	setKey(ns, "search", strSeq(cfg.Search))
	if len(ns.Content) == 0 {
		setKey(dev, "nameservers", nil)
	} else {
		setKey(dev, "nameservers", ns)
	}
	if cfg.MTU > 0 {
		setKey(dev, "mtu", intN(cfg.MTU))
	} else {
		setKey(dev, "mtu", nil)
	}
}

// indentOf guesses the indentation of a YAML text (spaces before the first nested key).
func indentOf(raw string) int {
	for _, l := range strings.Split(raw, "\n") {
		t := strings.TrimLeft(l, " ")
		if n := len(l) - len(t); n > 0 && t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "-") {
			if n >= 2 && n <= 8 {
				return n
			}
			break
		}
	}
	return 2
}

func encode(doc *yaml.Node, raw string) (string, error) {
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(indentOf(raw))
	if err := e.Encode(doc); err != nil {
		return "", err
	}
	_ = e.Close()
	return b.String(), nil
}

// Plan implements Backend.
func (n *Netplan) Plan(ctx context.Context, cfg IfaceConfig, mac string) (Plan, error) {
	cur, err := n.Config(cfg.Name, mac)
	if err != nil {
		return Plan{}, err
	}
	if !cur.Editable {
		return Plan{}, invalid("this interface cannot be edited here (%s)", cur.Reason)
	}
	fs, err := n.files()
	if err != nil {
		return Plan{}, err
	}
	var fc FileChange
	if es := n.find(fs, cfg.Name, mac); len(es) == 1 {
		f := fs[es[0].file]
		writeEntry(es[0].node, cfg)
		out, err := encode(f.doc, f.raw)
		if err != nil {
			return Plan{}, err
		}
		fc = FileChange{Path: f.path, Old: ptr(f.raw), New: ptr(out)}
	} else {
		var doc yaml.Node
		var old *string
		if b, err := os.ReadFile(filepath.Join(n.Root, NetplanOwnFile)); err == nil {
			old = ptr(string(b))
			if yaml.Unmarshal(b, &doc) != nil {
				return Plan{}, invalid("%s is not valid YAML", NetplanOwnFile)
			}
		}
		if root(&doc) == nil {
			doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{mapN()}}
		}
		r := root(&doc)
		nw := get(r, "network")
		if nw == nil {
			nw = mapN()
			setKey(nw, "version", intN(2))
			setKey(r, "network", nw)
		}
		eth := get(nw, "ethernets")
		if eth == nil {
			eth = mapN()
			setKey(nw, "ethernets", eth)
		}
		dev := get(eth, cfg.Name)
		if dev == nil {
			dev = mapN()
			setKey(eth, cfg.Name, dev)
		}
		writeEntry(dev, cfg)
		raw := ""
		if old != nil {
			raw = *old
		}
		out, err := encode(&doc, raw)
		if err != nil {
			return Plan{}, err
		}
		fc = FileChange{Path: NetplanOwnFile, Old: old, New: ptr(out)}
	}
	if fc.Old != nil && *fc.Old == *fc.New {
		return Plan{}, invalid("no change")
	}
	p := Plan{Manager: "netplan", Iface: cfg.Name, Files: []FileChange{fc}, Diff: UnifiedDiff(fc.Path, fc.Old, fc.New), Old: &cur, New: &cfg}
	return p, n.validate(ctx, p)
}

// validate runs `netplan generate` on a copy of the configuration with the change.
func (n *Netplan) validate(ctx context.Context, p Plan) error {
	tmp, err := os.MkdirTemp("", "daemonica-netplan-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for _, dir := range netplanDirs {
		m, _ := filepath.Glob(filepath.Join(n.Root, dir, "*.yaml"))
		for _, f := range m {
			b, err := os.ReadFile(f) //nolint:gosec // netplan directories
			if err != nil {
				return err
			}
			if err := writeTo(tmp, strings.TrimPrefix(f, n.Root), b); err != nil {
				return err
			}
		}
	}
	for _, f := range p.Files {
		if f.New == nil {
			_ = os.Remove(filepath.Join(tmp, f.Path))
			continue
		}
		if err := writeTo(tmp, f.Path, []byte(*f.New)); err != nil {
			return err
		}
	}
	res, err := n.Run(ctx, 30*time.Second, "/usr/sbin/netplan", "generate", "--root-dir", tmp)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return invalid("netplan rejects the configuration: %s", firstLine(res.Stderr))
	}
	return nil
}

func writeTo(root, p string, b []byte) error {
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	return os.WriteFile(full, b, 0o600)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	for _, l := range strings.Split(s, "\n") {
		// skip netplan's permission warnings
		if l = strings.TrimSpace(l); l != "" && !strings.Contains(l, "Permissions for") {
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return "unknown error"
}

// Activate implements Backend: write the files and run `netplan apply`.
func (n *Netplan) Activate(ctx context.Context, p Plan, rollback bool) error {
	if err := WriteFiles(n.Root, p.Files, rollback); err != nil {
		return err
	}
	res, err := n.Run(ctx, 2*time.Minute, "/usr/sbin/netplan", "apply")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return invalid("netplan apply failed: %s", firstLine(res.Stderr))
	}
	return nil
}
