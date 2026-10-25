package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

// Manager describes the network configuration system in use.
type Manager struct {
	// Name is netplan, ifupdown, networkmanager, networkd or none.
	Name string `json:"name"`
	// Renderer is netplan's backend (networkd or NetworkManager).
	Renderer string `json:"renderer,omitempty"`
	Writable bool   `json:"writable"`
	// Reason explains a read-only manager: mixed, unsupported, not_implemented, none.
	Reason string   `json:"reason,omitempty"`
	Files  []string `json:"files"`
}

// StaticRoute is a route configured for an interface.
type StaticRoute struct {
	To     string `json:"to"` // CIDR or "default"
	Via    string `json:"via"`
	Metric int    `json:"metric,omitempty"`
}

// IfaceConfig is the editable configuration of one interface.
type IfaceConfig struct {
	Name      string        `json:"name"`
	DHCP4     bool          `json:"dhcp4"`
	DHCP6     bool          `json:"dhcp6"`
	Addresses []string      `json:"addresses"`
	Gateway4  string        `json:"gateway4,omitempty"`
	Gateway6  string        `json:"gateway6,omitempty"`
	DNS       []string      `json:"dns"`
	Search    []string      `json:"search"`
	MTU       int           `json:"mtu,omitempty"`
	Routes    []StaticRoute `json:"routes"`
	// Read-only fields of a loaded configuration.
	Source   string `json:"source,omitempty"`
	Editable bool   `json:"editable"`
	// Reason explains a non-editable interface: several_files, advanced, not_configured, manager.
	Reason string `json:"reason,omitempty"`
}

// FileChange is one file written by a plan. Old/New nil mean "absent".
type FileChange struct {
	Path string  `json:"path"`
	Old  *string `json:"old"`
	New  *string `json:"new"`
}

// Plan is a validated configuration change.
type Plan struct {
	Manager string       `json:"manager"`
	Iface   string       `json:"iface"`
	Files   []FileChange `json:"files"`
	Diff    string       `json:"diff"`
}

// Runner runs a program (execx.Run in production).
type Runner func(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error)

// ExecRunner runs programs with execx.
func ExecRunner(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error) {
	return execx.Run(ctx, timeout, 256<<10, nil, path, args...)
}

// Backend reads and changes the configuration of one manager.
type Backend interface {
	Config(name, mac string) (IfaceConfig, error)
	// Plan builds and validates the file changes for cfg.
	Plan(ctx context.Context, cfg IfaceConfig, mac string) (Plan, error)
	// Activate makes the files of p (side new or old) take effect.
	Activate(ctx context.Context, p Plan, rollback bool) error
}

// ErrValidation reports an invalid configuration; the message is safe to show.
type ErrValidation struct{ Msg string }

func (e *ErrValidation) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ErrValidation{Msg: fmt.Sprintf(format, a...)} }

var (
	domainRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
	ifaceRE  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

const maxListItems = 16

// ValidIface checks an interface name against the kernel's rules.
func ValidIface(n string) bool { return ifaceRE.MatchString(n) && n != "." && n != ".." }

// Normalize validates cfg and returns it in canonical form.
func Normalize(cfg IfaceConfig) (IfaceConfig, error) {
	if !ValidIface(cfg.Name) {
		return cfg, invalid("invalid interface name")
	}
	out := IfaceConfig{Name: cfg.Name, DHCP4: cfg.DHCP4, DHCP6: cfg.DHCP6, MTU: cfg.MTU,
		Addresses: []string{}, DNS: []string{}, Search: []string{}, Routes: []StaticRoute{}}
	if len(cfg.Addresses) > maxListItems || len(cfg.DNS) > maxListItems || len(cfg.Search) > 6 || len(cfg.Routes) > maxListItems {
		return cfg, invalid("too many entries")
	}
	var has4, has6 bool
	for _, a := range cfg.Addresses {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() {
			return cfg, invalid("invalid address %q (CIDR expected, e.g. 192.0.2.10/24)", a)
		}
		has4, has6 = has4 || p.Addr().Is4(), has6 || p.Addr().Is6()
		if !slices.Contains(out.Addresses, p.String()) {
			out.Addresses = append(out.Addresses, p.String())
		}
	}
	gw := func(s string, v4 bool) (string, error) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "", nil
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.Is4() != v4 || ip.IsUnspecified() || ip.IsMulticast() {
			return "", invalid("invalid gateway %q", s)
		}
		return ip.String(), nil
	}
	var err error
	if out.Gateway4, err = gw(cfg.Gateway4, true); err != nil {
		return cfg, err
	}
	if out.Gateway6, err = gw(cfg.Gateway6, false); err != nil {
		return cfg, err
	}
	if out.Gateway4 != "" && !has4 && !cfg.DHCP4 {
		return cfg, invalid("an IPv4 gateway needs an IPv4 address or DHCP")
	}
	if out.Gateway6 != "" && !has6 && !cfg.DHCP6 {
		return cfg, invalid("an IPv6 gateway needs an IPv6 address or DHCPv6")
	}
	for _, d := range cfg.DNS {
		ip, err := netip.ParseAddr(strings.TrimSpace(d))
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
			return cfg, invalid("invalid DNS server %q", d)
		}
		if !slices.Contains(out.DNS, ip.String()) {
			out.DNS = append(out.DNS, ip.String())
		}
	}
	for _, s := range cfg.Search {
		s = strings.TrimSpace(s)
		if len(s) > 253 || !domainRE.MatchString(s) {
			return cfg, invalid("invalid search domain %q", s)
		}
		if !slices.Contains(out.Search, s) {
			out.Search = append(out.Search, s)
		}
	}
	if cfg.MTU != 0 && (cfg.MTU < 576 || cfg.MTU > 9216 || (has6 && cfg.MTU < 1280)) {
		return cfg, invalid("MTU must be 576–9216 (IPv6: at least 1280)")
	}
	for _, r := range cfg.Routes {
		var nr StaticRoute
		if t := strings.TrimSpace(r.To); t == "default" {
			nr.To = t
		} else {
			p, err := netip.ParsePrefix(t)
			if err != nil {
				return cfg, invalid("invalid route destination %q", r.To)
			}
			nr.To = p.Masked().String()
		}
		via, err := netip.ParseAddr(strings.TrimSpace(r.Via))
		if err != nil || via.IsUnspecified() {
			return cfg, invalid("invalid route gateway %q", r.Via)
		}
		nr.Via = via.String()
		if nr.To != "default" && netip.MustParsePrefix(nr.To).Addr().Is4() != via.Is4() {
			return cfg, invalid("route %s: gateway of the other address family", nr.To)
		}
		if r.Metric < 0 || r.Metric > 65535 {
			return cfg, invalid("route metric must be 0–65535")
		}
		nr.Metric = r.Metric
		// A default route here is the gateway of its family.
		if nr.To == "default" {
			if via.Is4() && out.Gateway4 == "" && nr.Metric == 0 {
				out.Gateway4 = nr.Via
				continue
			}
			if via.Is6() && out.Gateway6 == "" && nr.Metric == 0 {
				out.Gateway6 = nr.Via
				continue
			}
		}
		out.Routes = append(out.Routes, nr)
	}
	return out, nil
}

// Detector finds the active network manager.
type Detector struct {
	Root string
	// Active reports whether a systemd unit is active (replaceable in tests).
	Active func(unit string) bool
}

func (d *Detector) path(p string) string { return filepath.Join(d.Root, p) }

// Detect returns the manager and the backend for writing (nil when read-only).
func (d *Detector) Detect(run Runner) (Manager, Backend) {
	netplanFiles := d.globYAML("/etc/netplan", "/lib/netplan", "/run/netplan")
	ifupFiles := d.ifupdownFiles()
	active := func(u string) bool { return d.Active != nil && d.Active(u) }
	switch {
	case len(netplanFiles) > 0 && exists(d.path("/usr/sbin/netplan")):
		np := &Netplan{Root: d.Root, Run: run}
		m := Manager{Name: "netplan", Renderer: np.renderer(), Writable: true, Files: netplanFiles}
		if len(ifupFiles) > 0 {
			m.Writable, m.Reason, m.Files = false, "mixed", append(m.Files, ifupFiles...)
			return m, nil
		}
		return m, np
	case len(ifupFiles) > 0 && exists(d.path("/usr/sbin/ifup")):
		m := Manager{Name: "ifupdown", Writable: true, Files: ifupFiles}
		if active("NetworkManager.service") || (active("systemd-networkd.service") && len(d.networkdFiles()) > 0) {
			m.Writable, m.Reason = false, "mixed"
			return m, nil
		}
		return m, &Ifupdown{Root: d.Root, Run: run}
	case active("NetworkManager.service"):
		return Manager{Name: "networkmanager", Reason: "not_implemented", Files: []string{}}, nil
	case active("systemd-networkd.service") && len(d.networkdFiles()) > 0:
		return Manager{Name: "networkd", Reason: "not_implemented", Files: d.networkdFiles()}, nil
	}
	return Manager{Name: "none", Reason: "unsupported", Files: []string{}}, nil
}

func (d *Detector) globYAML(dirs ...string) []string {
	var out []string
	for _, dir := range dirs {
		m, _ := filepath.Glob(d.path(dir + "/*.yaml"))
		for _, f := range m {
			out = append(out, strings.TrimPrefix(f, d.Root))
		}
	}
	return out
}

func (d *Detector) networkdFiles() []string {
	m, _ := filepath.Glob(d.path("/etc/systemd/network/*.network"))
	out := make([]string, 0, len(m))
	for _, f := range m {
		out = append(out, strings.TrimPrefix(f, d.Root))
	}
	return out
}

// ifupdownFiles lists interfaces files that configure more than loopback.
func (d *Detector) ifupdownFiles() []string {
	b, err := os.ReadFile(d.path("/etc/network/interfaces"))
	if err != nil {
		return nil
	}
	st, err := parseInterfaces(string(b))
	if err != nil || st.hasSource {
		// sourced files: treat as configured (read-only handled by the backend)
		if err == nil && st.hasSource {
			return []string{"/etc/network/interfaces"}
		}
		return nil
	}
	for _, s := range st.stanzas {
		if s.iface != "lo" && s.iface != "" {
			return []string{"/etc/network/interfaces"}
		}
	}
	return nil
}

// WriteFiles writes the new (or, for rollback, old) side of the changes.
// Files are written atomically with mode 0600 (netplan warns about wider modes).
func WriteFiles(root string, files []FileChange, rollback bool) error {
	var errs []error
	for _, f := range files {
		content := f.New
		if rollback {
			content = f.Old
		}
		p := filepath.Join(root, f.Path)
		if content == nil {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
			continue
		}
		mode := os.FileMode(0o600)
		if strings.HasPrefix(f.Path, "/etc/network/") {
			mode = 0o644
		}
		if err := writeAtomic(p, []byte(*content), mode); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".daemonica-"+filepath.Base(p)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, p)
}

func ptr(s string) *string { return &s }
