package helper

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// DefaultPort is the dashboard port (A-03).
const DefaultPort = 8443

// Config is the security-relevant dashboard configuration. It is owned by the
// helper (trust anchor) and handed to the web process read-only via config.get.
type Config struct {
	Version     int      `json:"version"`
	SetupDone   bool     `json:"setup_done"`
	Domain      string   `json:"domain,omitempty"`
	Port        int      `json:"port"`
	Allowlist   []string `json:"allowlist"`
	IdleMinutes int      `json:"idle_minutes"`
	AbsHours    int      `json:"absolute_hours"`
	Language    string   `json:"language"`
	UploadMiB   int      `json:"upload_limit_mib"`
	TLSSource   string   `json:"tls_source,omitempty"` // own | acme-staging | acme-production
	// TerminalIdleMinutes ends web terminals without input (SPEC §7.5; 0 = default 15).
	TerminalIdleMinutes int `json:"terminal_idle_minutes,omitempty"`
}

// DefaultConfig is the configuration of a fresh install: setup mode, loopback only.
func DefaultConfig() Config {
	return Config{Version: 1, Port: DefaultPort, Allowlist: []string{"127.0.0.0/8", "::1/128"},
		IdleMinutes: 30, AbsHours: 12, Language: "de", UploadMiB: 1024, TerminalIdleMinutes: DefaultTerminalIdle}
}

// Validate checks all fields against their allowed ranges.
func (c Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("port out of range")
	}
	if c.Domain != "" {
		if err := validate.Domain(c.Domain); err != nil {
			return errors.New("invalid domain")
		}
	}
	if c.SetupDone && c.Domain == "" {
		return errors.New("domain required after setup")
	}
	if _, err := netallow.ParseList(c.Allowlist); err != nil || len(c.Allowlist) == 0 {
		return errors.New("invalid allowlist")
	}
	if c.IdleMinutes < 5 || c.IdleMinutes > 60 || c.AbsHours < 1 || c.AbsHours > 24 {
		return errors.New("session lifetimes out of bounds")
	}
	if c.Language != "de" && c.Language != "en" {
		return errors.New("unsupported language")
	}
	if c.UploadMiB < 1 || c.UploadMiB > 16*1024 {
		return errors.New("upload limit out of range")
	}
	if c.TerminalIdleMinutes < 0 || c.TerminalIdleMinutes > 24*60 {
		return errors.New("terminal idle timeout out of range")
	}
	return nil
}

// ConfigStore persists Config atomically (temp + fsync + rename, mode 0600).
type ConfigStore struct {
	mu   sync.Mutex
	path string
	cur  Config
}

// OpenConfig loads the config or creates the default one.
func OpenConfig(path string) (*ConfigStore, error) {
	s := &ConfigStore{path: path}
	data, err := os.ReadFile(path) //nolint:gosec // fixed helper path
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.cur = DefaultConfig()
		return s, s.writeLocked(s.cur)
	case err != nil:
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s.cur = c
	return s, nil
}

// Get returns a copy of the current config.
func (s *ConfigStore) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cur
	c.Allowlist = append([]string(nil), s.cur.Allowlist...)
	return c
}

// Update validates and atomically persists a modified config.
func (s *ConfigStore) Update(fn func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cur
	next.Allowlist = append([]string(nil), s.cur.Allowlist...)
	if err := fn(&next); err != nil {
		return s.cur, err
	}
	if err := next.Validate(); err != nil {
		return s.cur, err
	}
	if err := s.writeLocked(next); err != nil {
		return s.cur, err
	}
	s.cur = next
	return next, nil
}

func (s *ConfigStore) writeLocked(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, data, 0o600)
}

// WriteFileAtomic writes data to path via a temp file in the same directory,
// fsyncs file and directory, then renames (SPEC §3.2 rule 8).
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // directory of a fixed path
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
