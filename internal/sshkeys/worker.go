package sshkeys

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// MaxFileSize bounds authorized_keys files handled by the dashboard.
const MaxFileSize = 1 << 20

// ReadArgs / ReadResult are the worker protocol for "ak.read".
type ReadArgs struct {
	Home string   `json:"home"`
	Rel  []string `json:"rel"` // paths relative to home (from AuthorizedKeysFile)
}

// FileState describes one authorized_keys file as seen by its owner.
type FileState struct {
	Rel     string `json:"rel"`
	Exists  bool   `json:"exists"`
	Content string `json:"content,omitempty"`
	Hash    string `json:"hash"`
	Mode    uint32 `json:"mode"`
	UID     uint32 `json:"uid"`
	Symlink bool   `json:"symlink"`
}

// ReadResult also reports the ~/.ssh directory.
type ReadResult struct {
	Files      []FileState `json:"files"`
	SSHDir     bool        `json:"ssh_dir"`
	SSHDirMode uint32      `json:"ssh_dir_mode"`
	SSHDirUID  uint32      `json:"ssh_dir_uid"`
}

// WriteArgs is the worker protocol for "ak.write".
type WriteArgs struct {
	Home     string `json:"home"`
	Rel      string `json:"rel"`
	Content  string `json:"content"`
	Expected string `json:"expected"` // hash of the content the change was based on ("" = file absent)
}

// Hash returns the SHA-256 (hex) of content.
func Hash(content string) string {
	s := sha256.Sum256([]byte(content))
	return hex.EncodeToString(s[:])
}

// CleanRel validates a home-relative path (no "..", not absolute).
func CleanRel(rel string) (string, error) {
	c := path.Clean(rel)
	if rel == "" || path.IsAbs(c) || c == "." || c == ".." || strings.HasPrefix(c, "../") || strings.ContainsAny(c, "\x00\n") {
		return "", errors.New("invalid path")
	}
	return c, nil
}

func ownerMode(fi fs.FileInfo) (uint32, uint32) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, uint32(fi.Mode().Perm())
	}
	return 0, uint32(fi.Mode().Perm())
}

// WorkerHandlers are executed in the worker process (as the key owner).
func WorkerHandlers() map[string]worker.Handler {
	return map[string]worker.Handler{
		"ak.read": func(raw json.RawMessage) (any, error) {
			var a ReadArgs
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, &worker.OpError{Code: "bad_request"}
			}
			root, err := os.OpenRoot(a.Home)
			if err != nil {
				return nil, &worker.OpError{Code: "not_found", Msg: "home directory not accessible"}
			}
			defer func() { _ = root.Close() }()
			var res ReadResult
			if fi, err := root.Lstat(".ssh"); err == nil && fi.IsDir() {
				res.SSHDir = true
				res.SSHDirUID, res.SSHDirMode = ownerMode(fi)
			}
			for _, r := range a.Rel {
				rel, err := CleanRel(r)
				if err != nil {
					continue
				}
				st := FileState{Rel: rel, Hash: Hash("")}
				fi, err := root.Lstat(rel)
				if err == nil {
					st.Exists = true
					st.Symlink = fi.Mode()&fs.ModeSymlink != 0
					st.UID, st.Mode = ownerMode(fi)
					if !st.Symlink && fi.Mode().IsRegular() {
						f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
						if err == nil {
							b, _ := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
							_ = f.Close()
							if len(b) > MaxFileSize {
								return nil, &worker.OpError{Code: "validation_failed", Msg: "authorized_keys too large"}
							}
							st.Content, st.Hash = string(b), Hash(string(b))
						}
					}
				}
				res.Files = append(res.Files, st)
			}
			return res, nil
		},
		"ak.write": func(raw json.RawMessage) (any, error) {
			var a WriteArgs
			if err := json.Unmarshal(raw, &a); err != nil || len(a.Content) > MaxFileSize {
				return nil, &worker.OpError{Code: "bad_request"}
			}
			rel, err := CleanRel(a.Rel)
			if err != nil {
				return nil, &worker.OpError{Code: "validation_failed", Msg: "invalid path"}
			}
			root, err := os.OpenRoot(a.Home)
			if err != nil {
				return nil, &worker.OpError{Code: "not_found", Msg: "home directory not accessible"}
			}
			defer func() { _ = root.Close() }()
			// Optimistic concurrency: refuse if the file changed since it was read.
			cur := ""
			if f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0); err == nil {
				b, _ := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
				_ = f.Close()
				cur = string(b)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, &worker.OpError{Code: "conflict", Msg: "file not readable (symlink?)"}
			}
			if Hash(cur) != a.Expected {
				return nil, &worker.OpError{Code: "conflict", Msg: "file changed meanwhile"}
			}
			dir := path.Dir(rel)
			if dir != "." {
				if err := root.MkdirAll(dir, 0o700); err != nil {
					return nil, &worker.OpError{Code: "conflict", Msg: "cannot create directory"}
				}
			}
			tmp := path.Join(dir, ".authorized_keys.daemonica-tmp")
			_ = root.Remove(tmp)
			f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			if err != nil {
				return nil, &worker.OpError{Code: "conflict", Msg: "cannot write"}
			}
			if _, err := f.WriteString(a.Content); err != nil {
				_ = f.Close()
				_ = root.Remove(tmp)
				return nil, err
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				_ = root.Remove(tmp)
				return nil, err
			}
			_ = f.Close()
			if err := root.Rename(tmp, rel); err != nil {
				_ = root.Remove(tmp)
				return nil, &worker.OpError{Code: "conflict", Msg: "cannot replace file"}
			}
			return map[string]string{"hash": Hash(a.Content)}, nil
		},
	}
}
