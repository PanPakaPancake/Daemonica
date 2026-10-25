package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/files"
)

// Previous versions of files below /etc (SPEC §7.4 SOLL): before the editor
// overwrites a file, the helper keeps its old content for 30 days, at most 20
// versions per file. Restoring loads a version into the editor; saving it
// goes through the normal write path (concurrency check, validation, audit).
const (
	VersionsKeep   = 20
	VersionsMaxAge = 30 * 24 * time.Hour
)

// Version describes one stored previous version.
type Version struct {
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Size    int64     `json:"size"`
	Hash    string    `json:"hash"`
	Account string    `json:"account,omitempty"` // account whose save replaced this content
}

var versionIDRE = regexp.MustCompile(`^[0-9]{19}-[0-9a-f]{16}$`)

// VersionStore keeps versions in Dir (root 0700), one subdirectory per file
// (named by the SHA-256 of the canonical path).
type VersionStore struct {
	Dir    string
	Prefix string // tests only
	Now    func() time.Time

	mu sync.Mutex
}

// Covers reports whether saves of p keep a previous version: files below
// Prefix (default /etc/), never secrets such as /etc/shadow.
func (s *VersionStore) Covers(p string) bool {
	if s == nil {
		return false
	}
	prefix := s.Prefix
	if prefix == "" {
		prefix = "/etc/"
	}
	return strings.HasPrefix(p, prefix) && !files.Sensitive(p)
}

func (s *VersionStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *VersionStore) fileDir(p string) string {
	sum := sha256.Sum256([]byte(p))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:]))
}

type versionIndex struct {
	Path string `json:"path"`
}

// Save stores data as the newest version of p and prunes old versions.
func (s *VersionStore) Save(p string, data []byte, account string) (Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.fileDir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Version{}, err
	}
	idx, _ := json.Marshal(versionIndex{Path: p})
	if err := WriteFileAtomic(filepath.Join(dir, "index.json"), idx, 0o600); err != nil {
		return Version{}, err
	}
	sum := sha256.Sum256(data)
	now := s.now().UTC()
	v := Version{
		ID:      fmt.Sprintf("%019d-%s", now.UnixNano(), hex.EncodeToString(sum[:8])),
		Time:    now,
		Size:    int64(len(data)),
		Hash:    hex.EncodeToString(sum[:]),
		Account: account,
	}
	meta, _ := json.Marshal(v)
	if err := WriteFileAtomic(filepath.Join(dir, v.ID+".data"), data, 0o600); err != nil {
		return Version{}, err
	}
	if err := WriteFileAtomic(filepath.Join(dir, v.ID+".json"), meta, 0o600); err != nil {
		_ = os.Remove(filepath.Join(dir, v.ID+".data"))
		return Version{}, err
	}
	s.pruneLocked(dir)
	return v, nil
}

// List returns the versions of p, newest first.
func (s *VersionStore) List(p string) ([]Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.fileDir(p)
	s.pruneLocked(dir)
	return s.listLocked(dir)
}

func (s *VersionStore) listLocked(dir string) ([]Version, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Version{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Version{}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !versionIDRE.MatchString(id) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // name from our own directory, validated
		if err != nil {
			continue
		}
		var v Version
		if json.Unmarshal(raw, &v) != nil || v.ID != id {
			continue
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Version) int { return strings.Compare(b.ID, a.ID) })
	return out, nil
}

// Read returns the content of version id of p.
func (s *VersionStore) Read(p, id string) (Version, []byte, error) {
	if !versionIDRE.MatchString(id) {
		return Version{}, nil, os.ErrNotExist
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.fileDir(p)
	raw, err := os.ReadFile(filepath.Join(dir, id+".json")) //nolint:gosec // validated id
	if err != nil {
		return Version{}, nil, err
	}
	var v Version
	if err := json.Unmarshal(raw, &v); err != nil {
		return Version{}, nil, err
	}
	if s.now().Sub(v.Time) > VersionsMaxAge {
		return Version{}, nil, os.ErrNotExist
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".data")) //nolint:gosec // validated id
	if err != nil {
		return Version{}, nil, err
	}
	return v, data, nil
}

// pruneLocked drops versions beyond VersionsKeep or older than VersionsMaxAge.
func (s *VersionStore) pruneLocked(dir string) {
	vs, err := s.listLocked(dir)
	if err != nil {
		return
	}
	now := s.now()
	for i, v := range vs {
		if i >= VersionsKeep || now.Sub(v.Time) > VersionsMaxAge {
			_ = os.Remove(filepath.Join(dir, v.ID+".data"))
			_ = os.Remove(filepath.Join(dir, v.ID+".json"))
		}
	}
}

// Remove deletes one version (used when the save it belonged to failed).
func (s *VersionStore) Remove(p, id string) {
	if !versionIDRE.MatchString(id) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.fileDir(p)
	_ = os.Remove(filepath.Join(dir, id+".data"))
	_ = os.Remove(filepath.Join(dir, id+".json"))
}
