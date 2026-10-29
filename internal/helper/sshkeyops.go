package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/sshkeys"
	"github.com/PanPakaPancake/daemonica/internal/validate"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// Worker runs file operations under a Linux user's credentials.
type Worker interface {
	Run(ctx context.Context, id worker.Identity, elevated bool, op string, args, out any) error
}

// SSHKeyOps manages authorized_keys (SPEC §7.3).
type SSHKeyOps struct {
	Worker Worker
	Lookup func(name string) (worker.Identity, error)
	// Config returns the effective sshd settings (cached briefly).
	Config     func(ctx context.Context) ([]sshkeys.Setting, error)
	HostKeyDir string

	mu       sync.Mutex
	cfgCache []sshkeys.Setting
	cfgAt    time.Time
}

func (s *SSHKeyOps) settings(ctx context.Context) []sshkeys.Setting {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfgCache != nil && time.Since(s.cfgAt) < 30*time.Second {
		return s.cfgCache
	}
	cfg, err := s.Config(ctx)
	if err == nil {
		s.cfgCache, s.cfgAt = cfg, time.Now()
	}
	return s.cfgCache
}

// KeyListing is the result of sshkeys.list.
type KeyListing struct {
	User      string              `json:"user"`
	Keys      []sshkeys.Key       `json:"keys"`
	Invalid   []int               `json:"invalid_lines,omitempty"`
	Files     []sshkeys.FileState `json:"files"`
	WritePath string              `json:"write_path,omitempty"` // home-relative file new keys go to
	ReadOnly  bool                `json:"read_only"`
	Problems  []string            `json:"problems,omitempty"` // permission findings (stable codes)
	Hash      string              `json:"hash"`               // of the writable file (optimistic concurrency)
}

type keyParams struct {
	User        string   `json:"user"`
	Key         string   `json:"key,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// target resolves the user and authorizes the action (own vs. others).
func (s *SSHKeyOps) target(c Call, name string, write bool) (worker.Identity, error) {
	if validate.LinuxUser(name) != nil {
		return worker.Identity{}, Errf(rpc.CodeValidation, "invalid user")
	}
	id, err := s.Lookup(name)
	if err != nil {
		return worker.Identity{}, Errf(rpc.CodeNotFound, "user not found")
	}
	own := id.UID == c.Subject.LinuxUID
	act := policy.ActSSHKeysOwn
	if !own {
		act = policy.ActSSHKeysOthers
	}
	d := policy.Decide(*c.Subject, act, id.UID, true)
	if !write && !own && c.Subject.Role == policy.RoleAdmin {
		d = policy.Allow // viewing other users' public keys: admin without step-up
	}
	switch d {
	case policy.Deny:
		return id, Errf(rpc.CodeForbidden, "")
	case policy.NeedStepUp:
		return id, Errf(rpc.CodeStepUpNeeded, "")
	}
	return id, nil
}

func (s *SSHKeyOps) list(ctx context.Context, id worker.Identity) (KeyListing, error) {
	out := KeyListing{User: id.Name}
	var rels []string
	for i, p := range sshkeys.AuthorizedKeysPatterns(s.settings(ctx)) {
		rel, ok := sshkeys.Resolve(p, id.Home, id.Name)
		if !ok {
			if i == 0 {
				out.ReadOnly = true
			}
			continue
		}
		rels = append(rels, rel)
		if i == 0 {
			out.WritePath = rel
		}
	}
	if len(rels) == 0 {
		out.ReadOnly = true
		return out, nil
	}
	var rr sshkeys.ReadResult
	if err := s.Worker.Run(ctx, id, id.UID == 0, "ak.read", sshkeys.ReadArgs{Home: id.Home, Rel: rels}, &rr); err != nil {
		return out, Errf(rpc.CodeUnavailable, "cannot read keys")
	}
	out.Files = rr.Files
	out.Hash = sshkeys.Hash("")
	for _, f := range rr.Files {
		if f.Rel == out.WritePath {
			out.Hash = f.Hash
		}
		if f.Symlink {
			out.Problems = append(out.Problems, "symlink:"+f.Rel)
			if f.Rel == out.WritePath {
				out.ReadOnly = true
			}
		}
		if f.Exists && !f.Symlink {
			if f.UID != id.UID {
				out.Problems = append(out.Problems, "owner:"+f.Rel)
			}
			if f.Mode&0o077 != 0 {
				out.Problems = append(out.Problems, "mode:"+f.Rel)
			}
		}
		pf, invalid := sshkeys.ParseFile(f.Content)
		out.Keys = append(out.Keys, pf.Keys...)
		out.Invalid = append(out.Invalid, invalid...)
	}
	if rr.SSHDir && (rr.SSHDirUID != id.UID || rr.SSHDirMode&0o077 != 0) {
		out.Problems = append(out.Problems, "dir:.ssh")
	}
	if out.Keys == nil {
		out.Keys = []sshkeys.Key{}
	}
	return out, nil
}

// modify reads the writable file, applies fn and writes it back (as the user).
func (s *SSHKeyOps) modify(ctx context.Context, id worker.Identity, fn func(f *sshkeys.File) error) (KeyListing, error) {
	l, err := s.list(ctx, id)
	if err != nil {
		return l, err
	}
	if l.ReadOnly || l.WritePath == "" {
		return l, Errf(rpc.CodeNotSupported, "authorized_keys location is not managed by the dashboard")
	}
	content := ""
	for _, f := range l.Files {
		if f.Rel == l.WritePath {
			content = f.Content
		}
	}
	pf, _ := sshkeys.ParseFile(content)
	if err := fn(pf); err != nil {
		return l, err
	}
	err = s.Worker.Run(ctx, id, id.UID == 0, "ak.write", sshkeys.WriteArgs{Home: id.Home, Rel: l.WritePath, Content: pf.String(), Expected: l.Hash}, nil)
	if err != nil {
		var oe *worker.OpError
		if errors.As(err, &oe) && oe.Code == rpc.CodeConflict {
			return l, Errf(rpc.CodeConflict, "%s", oe.Msg)
		}
		return l, Errf(rpc.CodeUnavailable, "cannot write keys")
	}
	return s.list(ctx, id)
}

// Count returns the number of valid keys of a user (-1 if unknown); used by users.list.
func (s *SSHKeyOps) Count(ctx context.Context, name string) int {
	id, err := s.Lookup(name)
	if err != nil || id.UID == 0 {
		return -1
	}
	l, err := s.list(ctx, id)
	if err != nil {
		return -1
	}
	return len(l.Keys)
}

// Register installs sshkeys.* operations.
func (s *SSHKeyOps) Register(ops map[string]*Op) {
	target := func(c Call) string {
		var p keyParams
		_ = json.Unmarshal(c.Params, &p)
		t := "linux_user:" + p.User
		if p.Fingerprint != "" {
			t += " key:" + p.Fingerprint
		}
		return t
	}

	Register(ops, &Op{Name: "sshkeys.list", Action: policy.ActSSHKeysOwn, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p keyParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			id, err := s.target(c, p.User, false)
			if err != nil {
				return nil, err
			}
			if id.UID == 0 && c.Subject.Role != policy.RoleAdmin {
				return nil, Errf(rpc.CodeForbidden, "")
			}
			return s.list(ctx, id)
		}})

	Register(ops, &Op{Name: "sshkeys.add", Action: policy.ActSSHKeysOwn, AuditTarget: target,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p keyParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			id, err := s.target(c, p.User, true)
			if err != nil {
				return nil, err
			}
			k, perr := sshkeys.Parse(p.Key)
			if perr != nil {
				return nil, Errf(rpc.CodeValidation, "%s", perr.Error())
			}
			if len(p.Options) > 0 {
				if k, perr = k.WithOptions(p.Options); perr != nil {
					return nil, Errf(rpc.CodeValidation, "%s", perr.Error())
				}
			}
			return s.modify(ctx, id, func(f *sshkeys.File) error {
				if f.Has(k) {
					return Errf(rpc.CodeConflict, "key already present")
				}
				f.Add(k)
				return nil
			})
		}})

	Register(ops, &Op{Name: "sshkeys.remove", Action: policy.ActSSHKeysOwn, AuditTarget: target,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p keyParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			id, err := s.target(c, p.User, true)
			if err != nil {
				return nil, err
			}
			return s.modify(ctx, id, func(f *sshkeys.File) error {
				if !f.Remove(p.Fingerprint) {
					return Errf(rpc.CodeNotFound, "key not found")
				}
				return nil
			})
		}})

	Register(ops, &Op{Name: "sshkeys.set_options", Action: policy.ActSSHKeysOwn, AuditTarget: target,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p keyParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			id, err := s.target(c, p.User, true)
			if err != nil {
				return nil, err
			}
			return s.modify(ctx, id, func(f *sshkeys.File) error {
				k, ok := f.Find(p.Fingerprint)
				if !ok {
					return Errf(rpc.CodeNotFound, "key not found")
				}
				nk, err := k.WithOptions(p.Options)
				if err != nil {
					return Errf(rpc.CodeValidation, "%s", err.Error())
				}
				f.Replace(p.Fingerprint, nk)
				return nil
			})
		}})

	Register(ops, &Op{Name: "sshkeys.fix_permissions", Action: policy.ActSSHKeysOwn, AuditTarget: target,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p keyParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			id, err := s.target(c, p.User, true)
			if err != nil {
				return nil, err
			}
			l, err := s.list(ctx, id)
			if err != nil {
				return nil, err
			}
			if err := fixPermissions(id, l.Files); err != nil {
				return nil, Errf(rpc.CodeConflict, "%s", err.Error())
			}
			return s.list(ctx, id)
		}})

	Register(ops, &Op{Name: "sshkeys.server", Action: policy.ActUsersRead, NoAudit: true,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			return map[string]any{"host_keys": sshkeys.HostKeys(s.HostKeyDir), "sshd": s.settings(ctx)}, nil
		}})
}

// fixPermissions sets ~/.ssh to 0700 and key files to 0600, owned by the user.
// It runs as root but only through file descriptors opened with O_NOFOLLOW
// inside an os.Root at the home directory, so symlinks cannot redirect it.
func fixPermissions(id worker.Identity, files []sshkeys.FileState) error {
	hfi, err := os.Lstat(id.Home)
	if err != nil || !hfi.IsDir() {
		return errors.New("home directory missing or not a directory")
	}
	if st, ok := hfi.Sys().(*syscall.Stat_t); !ok || st.Uid != id.UID {
		return errors.New("home directory is not owned by the user")
	}
	root, err := os.OpenRoot(id.Home)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	fix := func(rel string, mode os.FileMode, dir bool) error {
		flags := os.O_RDONLY | syscall.O_NOFOLLOW
		if dir {
			flags |= syscall.O_DIRECTORY
		}
		f, err := root.OpenFile(rel, flags, 0)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return errors.New("cannot open " + rel + " (symlink?)")
		}
		defer func() { _ = f.Close() }()
		if err := f.Chown(int(id.UID), int(id.GID)); err != nil {
			return err
		}
		return f.Chmod(mode)
	}
	if err := fix(".ssh", 0o700, true); err != nil {
		return err
	}
	for _, f := range files {
		if !f.Exists || f.Symlink {
			continue
		}
		if d := path.Dir(f.Rel); d != "." && d != ".ssh" && !strings.HasPrefix(d, ".ssh/") {
			continue // only touch files inside ~/.ssh
		}
		if err := fix(f.Rel, 0o600, false); err != nil {
			return err
		}
	}
	return nil
}
