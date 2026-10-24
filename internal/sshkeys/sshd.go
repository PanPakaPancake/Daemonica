package sshkeys

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

// Sshd is the sshd binary used for "sshd -T".
var Sshd = "/usr/sbin/sshd"

// Setting is one effective sshd setting.
type Setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// EffectiveConfig runs "sshd -T" (read-only view, SPEC §7.3).
func EffectiveConfig(ctx context.Context) ([]Setting, error) {
	res, err := execx.Run(ctx, 10*time.Second, 1<<20, nil, Sshd, "-T")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, errors.New("sshd -T failed")
	}
	var out []Setting
	sc := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		if k == "" {
			continue
		}
		out = append(out, Setting{Key: sysinfo.SanitizeText(k, 64), Value: sysinfo.SanitizeText(v, 2048)})
	}
	return out, nil
}

// AuthorizedKeysPatterns extracts AuthorizedKeysFile from settings (default if absent).
func AuthorizedKeysPatterns(cfg []Setting) []string {
	for _, s := range cfg {
		if s.Key == "authorizedkeysfile" {
			return strings.Fields(s.Value)
		}
	}
	return []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
}

// Resolve expands %h, %u and %% and returns the path relative to home. ok is
// false when the file lies outside the home directory (managed read-only).
func Resolve(pattern, home, user string) (rel string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '%' && i+1 < len(pattern) {
			switch pattern[i+1] {
			case 'h':
				b.WriteString(home)
			case 'u':
				b.WriteString(user)
			case '%':
				b.WriteByte('%')
			default:
				return "", false
			}
			i++
			continue
		}
		b.WriteByte(pattern[i])
	}
	p := b.String()
	if !path.IsAbs(p) {
		r, err := CleanRel(p)
		return r, err == nil
	}
	h := path.Clean(home) + "/"
	c := path.Clean(p)
	if !strings.HasPrefix(c, h) {
		return "", false
	}
	r, err := CleanRel(strings.TrimPrefix(c, h))
	return r, err == nil
}

// HostKey is a server host key.
type HostKey struct {
	File        string `json:"file"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// HostKeys reads /etc/ssh/ssh_host_*_key.pub (public parts only).
func HostKeys(dir string) []HostKey {
	matches, _ := filepath.Glob(filepath.Join(dir, "ssh_host_*_key.pub"))
	sort.Strings(matches)
	var out []HostKey
	for _, m := range matches {
		b, err := os.ReadFile(m) //nolint:gosec // fixed glob in /etc/ssh
		if err != nil {
			continue
		}
		f := strings.Fields(string(b))
		if len(f) < 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		out = append(out, HostKey{File: filepath.Base(m), Type: sysinfo.SanitizeText(f[0], 64),
			Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])})
	}
	return out
}
