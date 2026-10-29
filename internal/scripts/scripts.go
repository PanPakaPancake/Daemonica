// Package scripts is the script library (DEC-030): scripts written in the
// dashboard ("local") and script collections from GitHub, pinned to a
// commit. Updating a collection shows the diff to the installed commit and
// needs a step-up; jobs and terminals use the files by their path.
//
// Files live in a root-owned, world-readable tree (Root) so that jobs of any
// user can run them and jobs.Trusted accepts them for root jobs. Source
// metadata, including access tokens, lives in the helper state (0600).
package scripts

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// DefaultRoot is the library tree on the host.
const DefaultRoot = "/var/lib/daemonica-scripts"

// LocalID is the source of scripts written in the dashboard.
const LocalID = "local"

// Limits keep collections small enough for the helper RPC (1 MiB frames)
// and for review.
const (
	MaxFileSize = 1 << 20
	// MaxLocalSize bounds scripts written in (and shown by) the dashboard:
	// JSON escaping of "<" or ">" may grow the text sixfold.
	MaxLocalSize = 128 << 10
	MaxFiles     = 2000
	MaxTreeSize  = 32 << 20
	// MaxDiffBytes bounds the JSON-encoded diff text of one candidate.
	MaxDiffBytes = 600 << 10
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("exists")
	ErrStale    = errors.New("stale")
	ErrTooLarge = errors.New("too large")
	ErrInvalid  = errors.New("invalid")
)

var (
	idRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,127}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	refRE    = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
)

// ValidID reports whether id can name a source directory.
func ValidID(id string) bool { return idRE.MatchString(id) && id != LocalID }

// ValidCommit reports whether s is a full commit SHA.
func ValidCommit(s string) bool { return commitRE.MatchString(s) }

// ValidPath reports whether p is a relative library path whose components
// are all usable in unit files (jobs.CleanPath) and not hidden.
func ValidPath(p string) bool {
	if p == "" || len(p) > 512 {
		return false
	}
	for c := range strings.SplitSeq(p, "/") {
		if !nameRE.MatchString(c) || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// NormalizeRepo accepts "owner/name", "github.com/owner/name" and https
// URLs (with or without .git) and returns "owner/name".
func NormalizeRepo(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	return s, repoRE.MatchString(s)
}

// NormalizeSubdir cleans a subdirectory filter ("" for the whole repo).
func NormalizeSubdir(s string) (string, bool) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return "", true
	}
	return s, ValidPath(s)
}

// ValidRef reports whether ref is an acceptable branch, tag or SHA ("" is
// the default branch).
func ValidRef(ref string) bool {
	return refRE.MatchString(ref) && !strings.Contains(ref, "..") && !strings.HasPrefix(ref, "/") && !strings.HasSuffix(ref, "/")
}

// Source is a GitHub collection pinned to a commit.
type Source struct {
	ID      string    `json:"id"`
	Repo    string    `json:"repo"`
	Ref     string    `json:"ref,omitempty"`
	Subdir  string    `json:"subdir,omitempty"`
	Commit  Commit    `json:"commit"`
	Added   time.Time `json:"added"`
	Updated time.Time `json:"updated"`
	By      string    `json:"by,omitempty"`
	// Token is a GitHub access token for private repositories. It never
	// leaves the helper (see View).
	Token string `json:"token,omitempty"`
}

// SourceView is a source as the dashboard sees it.
type SourceView struct {
	Source
	HasToken bool `json:"has_token"`
}

// View strips the token.
func (s Source) View() SourceView {
	v := SourceView{Source: s, HasToken: s.Token != ""}
	v.Token = ""
	return v
}

// Commit identifies a pinned commit.
type Commit struct {
	SHA     string    `json:"sha"`
	Message string    `json:"message,omitempty"`
	Author  string    `json:"author,omitempty"`
	Date    time.Time `json:"date"`
}

// Entry is one file of a tree.
type Entry struct {
	Data []byte
	Exec bool
}

// Tree maps library paths (relative, "/"-separated) to files.
type Tree map[string]Entry

// Size is the sum of all file sizes.
func (t Tree) Size() int {
	n := 0
	for _, e := range t {
		n += len(e.Data)
	}
	return n
}

// File is a library file.
type File struct {
	Source   string    `json:"source"`
	Path     string    `json:"path"`
	Abs      string    `json:"abs"`
	Size     int64     `json:"size"`
	Exec     bool      `json:"exec"`
	SHA256   string    `json:"sha256"`
	Modified time.Time `json:"modified"`
	// Shebang is the interpreter line ("#!/bin/bash"), if any.
	Shebang string   `json:"shebang,omitempty"`
	UsedBy  []string `json:"used_by,omitempty"`
}

// Library manages the tree and the source metadata.
type Library struct {
	Root      string
	StateFile string
	GitHub    *GitHub
	Now       func() time.Time

	mu sync.Mutex
}

func (l *Library) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Init creates the tree root (root 0755) and the local source.
func (l *Library) Init() error {
	for _, d := range []string{l.Root, filepath.Join(l.Root, LocalID)} {
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // script tree must be readable by jobs of every user
			return err
		}
		// The helper runs with UMask=0077; jobs of other users must read the tree.
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // script tree must be readable by jobs of every user
			return err
		}
	}
	return nil
}

// Abs returns the host path of a library file.
func (l *Library) Abs(source, path string) string {
	return filepath.Join(l.Root, source, filepath.FromSlash(path))
}

// SourceDir returns the directory of a source.
func (l *Library) SourceDir(id string) string { return filepath.Join(l.Root, id) }

type state struct {
	Sources []Source `json:"sources"`
}

func (l *Library) load() (state, error) {
	var st state
	b, err := os.ReadFile(l.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func (l *Library) save(st state) error {
	slices.SortFunc(st.Sources, func(a, b Source) int { return strings.Compare(a.ID, b.ID) })
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(l.StateFile, b, 0o600)
}

// Sources lists the GitHub sources.
func (l *Library) Sources() ([]Source, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := l.load()
	if st.Sources == nil {
		st.Sources = []Source{}
	}
	return st.Sources, err
}

// Source returns one GitHub source.
func (l *Library) Source(id string) (Source, error) {
	list, err := l.Sources()
	if err != nil {
		return Source{}, err
	}
	for _, s := range list {
		if s.ID == id {
			return s, nil
		}
	}
	return Source{}, ErrNotFound
}

// Files lists all library files (local first, then the sources).
func (l *Library) Files() ([]File, error) {
	srcs, err := l.Sources()
	if err != nil {
		return nil, err
	}
	ids := []string{LocalID}
	for _, s := range srcs {
		ids = append(ids, s.ID)
	}
	out := []File{}
	for _, id := range ids {
		base := l.SourceDir(id)
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == base && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipDir
				}
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, _ := filepath.Rel(base, p)
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			f := File{Source: id, Path: filepath.ToSlash(rel), Abs: p, Size: fi.Size(), Exec: fi.Mode()&0o111 != 0, Modified: fi.ModTime().UTC()}
			if b, err := os.ReadFile(p); err == nil { //nolint:gosec // inside the root-owned script tree, regular files only
				sum := sha256.Sum256(b)
				f.SHA256 = hex.EncodeToString(sum[:])
				f.Shebang = shebang(b)
			}
			out = append(out, f)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func shebang(b []byte) string {
	if !strings.HasPrefix(string(b[:min(len(b), 2)]), "#!") {
		return ""
	}
	line, _, _ := strings.Cut(string(b[:min(len(b), 200)]), "\n")
	line = strings.TrimSpace(line)
	if !utf8.ValidString(line) {
		return ""
	}
	return line
}

// Read returns a file's content and hash.
func (l *Library) Read(source, path string) ([]byte, string, error) {
	if (source != LocalID && !ValidID(source)) || !ValidPath(path) {
		return nil, "", ErrInvalid
	}
	p := l.Abs(source, path)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, "", ErrNotFound
	}
	if fi.Size() > MaxLocalSize {
		return nil, "", ErrTooLarge
	}
	b, err := os.ReadFile(p) //nolint:gosec // inside the root-owned script tree, validated name
	if err != nil {
		return nil, "", err
	}
	return b, hashOf(b), nil
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IsText reports whether b looks like a text file (UTF-8, no NUL).
func IsText(b []byte) bool {
	return utf8.Valid(b) && !slices.Contains(b, 0)
}

// SaveLocal creates or replaces a local script. hash is the SHA-256 of the
// content the editor started from ("" to create a new file).
func (l *Library) SaveLocal(name string, content []byte, exec bool, hash string) (string, error) {
	if !ValidPath(name) || strings.Contains(name, "/") {
		return "", ErrInvalid
	}
	if len(content) > MaxLocalSize {
		return "", ErrTooLarge
	}
	if !IsText(content) {
		return "", ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.Abs(LocalID, name)
	cur, err := os.ReadFile(p) //nolint:gosec // inside the root-owned script tree, validated name
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if hash != "" {
			return "", ErrStale
		}
	case err != nil:
		return "", err
	case hash == "":
		return "", ErrExists
	case hashOf(cur) != hash:
		return "", ErrStale
	}
	mode := os.FileMode(0o644)
	if exec {
		mode = 0o755
	}
	if err := writeAtomic(p, content, mode); err != nil {
		return "", err
	}
	return hashOf(content), nil
}

// DeleteLocal removes a local script.
func (l *Library) DeleteLocal(name string) error {
	if !ValidPath(name) || strings.Contains(name, "/") {
		return ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := os.Remove(l.Abs(LocalID, name))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// ReadTree reads an installed source (for the diff of an update).
func (l *Library) ReadTree(id string) (Tree, error) {
	base := l.SourceDir(id)
	t := Tree{}
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == base && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipDir
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Size() > MaxFileSize {
			return ErrTooLarge
		}
		b, err := os.ReadFile(p) //nolint:gosec // inside the root-owned script tree, regular files only
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(base, p)
		t[filepath.ToSlash(rel)] = Entry{Data: b, Exec: fi.Mode()&0o111 != 0}
		return nil
	})
	return t, err
}

// Install replaces the files of source id with t: the new tree is written
// next to the old one and swapped in by rename.
func (l *Library) install(id string, t Tree) error {
	tmp, err := os.MkdirTemp(l.Root, ".new-"+id+"-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for p, e := range t {
		if !ValidPath(p) {
			return fmt.Errorf("%w: %s", ErrInvalid, p)
		}
		full := filepath.Join(tmp, filepath.FromSlash(p))
		if err := mkdirs(tmp, filepath.Dir(full)); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if e.Exec {
			mode = 0o755
		}
		if err := os.WriteFile(full, e.Data, mode); err != nil {
			return err
		}
		if err := os.Chmod(full, mode); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // scripts are executed by jobs of other users
		return err
	}
	dst := l.SourceDir(id)
	old := ""
	if _, err := os.Lstat(dst); err == nil {
		old = filepath.Join(l.Root, ".old-"+id+"-"+randHex())
		if err := os.Rename(dst, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		if old != "" {
			_ = os.Rename(old, dst)
		}
		return err
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return nil
}

// mkdirs creates dir (below base) with mode 0755 regardless of the umask.
func mkdirs(base, dir string) error {
	if dir == base {
		return nil
	}
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := mkdirs(base, filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { //nolint:gosec // script tree must be readable by jobs of every user
		return err
	}
	return os.Chmod(dir, 0o755) //nolint:gosec // script tree must be readable by jobs of every user
}

func randHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".daemonica-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
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
	return os.Rename(tmp.Name(), p)
}

// RemoveSource deletes a source and its files.
func (l *Library) RemoveSource(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := l.load()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(st.Sources, func(s Source) bool { return s.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	st.Sources = slices.Delete(st.Sources, i, i+1)
	if err := os.RemoveAll(l.SourceDir(id)); err != nil {
		return err
	}
	return l.save(st)
}

// Spec describes a GitHub source to add.
type Spec struct {
	ID     string `json:"id"`
	Repo   string `json:"repo"`
	Ref    string `json:"ref,omitempty"`
	Subdir string `json:"subdir,omitempty"`
	Token  string `json:"token,omitempty"`
}

// Normalize validates a spec. The returned field names the bad input.
func (s Spec) Normalize() (Spec, string) {
	var ok bool
	if s.Repo, ok = NormalizeRepo(s.Repo); !ok {
		return s, "repo"
	}
	s.Ref = strings.TrimSpace(s.Ref)
	if !ValidRef(s.Ref) {
		return s, "ref"
	}
	if s.Subdir, ok = NormalizeSubdir(s.Subdir); !ok {
		return s, "subdir"
	}
	if s.ID != "" && !ValidID(s.ID) {
		return s, "id"
	}
	s.Token = strings.TrimSpace(s.Token)
	if len(s.Token) > 255 || strings.ContainsAny(s.Token, " \t\r\n") {
		return s, "token"
	}
	return s, ""
}

// Candidate is a commit offered for adding or updating a source, with the
// changes against what is installed.
type Candidate struct {
	Commit  Commit    `json:"commit"`
	Files   int       `json:"files"`
	Size    int       `json:"size"`
	Changes []Change  `json:"changes"`
	Skipped []Skipped `json:"skipped"`
	// Current is true when the commit is already installed.
	Current bool `json:"current,omitempty"`
}

// Add installs a new source at commit (which the admin reviewed).
func (l *Library) Add(s Spec, c Commit, t Tree, by string) (Source, error) {
	if !ValidID(s.ID) {
		return Source{}, ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := l.load()
	if err != nil {
		return Source{}, err
	}
	if slices.ContainsFunc(st.Sources, func(x Source) bool { return x.ID == s.ID }) {
		return Source{}, ErrExists
	}
	if _, err := os.Lstat(l.SourceDir(s.ID)); err == nil {
		return Source{}, ErrExists
	}
	if err := l.install(s.ID, t); err != nil {
		return Source{}, err
	}
	now := l.now().UTC()
	src := Source{ID: s.ID, Repo: s.Repo, Ref: s.Ref, Subdir: s.Subdir, Commit: c, Added: now, Updated: now, By: by, Token: s.Token}
	st.Sources = append(st.Sources, src)
	return src, l.save(st)
}

// Update installs commit c of an existing source.
func (l *Library) Update(id string, c Commit, t Tree, by string) (Source, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := l.load()
	if err != nil {
		return Source{}, err
	}
	i := slices.IndexFunc(st.Sources, func(x Source) bool { return x.ID == id })
	if i < 0 {
		return Source{}, ErrNotFound
	}
	if err := l.install(id, t); err != nil {
		return Source{}, err
	}
	st.Sources[i].Commit = c
	st.Sources[i].Updated = l.now().UTC()
	st.Sources[i].By = by
	return st.Sources[i], l.save(st)
}
