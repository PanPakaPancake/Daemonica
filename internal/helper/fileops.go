package helper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/files"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// StreamWorker runs workers, including ones with a data stream.
type StreamWorker interface {
	Worker
	RunStream(ctx context.Context, id worker.Identity, elevated bool, op string, args, out any, data *os.File) error
}

// File manager limits (SPEC §7.4).
const (
	RootModeTTL      = 10 * time.Minute
	DownloadTokenTTL = 60 * time.Second
	CodeRootRequired = "root_mode_required"
)

// FileOps implements the fs.* operations (SPEC §7.4). Every file access runs
// in a worker under the mapped Linux user; only the admin "as root" mode
// (step-up, 10 minutes, per session) runs workers as root.
type FileOps struct {
	Worker    StreamWorker
	Lookup    func(name string) (worker.Identity, error)
	UploadMiB func() int
	Now       func() time.Time

	mu     sync.Mutex
	root   map[string]time.Time // session key → end of root mode
	tokens map[string]dlToken   // sha256(token) → pending download
}

type dlToken struct {
	grant     string
	asRoot    bool
	target    files.Target
	sensitive bool
	expires   time.Time
}

func (f *FileOps) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// fsFlags are accepted by every file operation.
type fsFlags struct {
	AsRoot           bool `json:"as_root,omitempty"`
	ConfirmSensitive bool `json:"confirm_sensitive,omitempty"`
}

// rootUntil returns the end of the session's root mode (zero if inactive).
func (f *FileOps) rootUntil(grantID string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	until := f.root[grantID]
	if !until.IsZero() && !f.now().Before(until) {
		delete(f.root, grantID)
		return time.Time{}
	}
	return until
}

// identity returns the worker identity for the call.
func (f *FileOps) identity(c Call, flags fsFlags) (worker.Identity, bool, error) {
	if flags.AsRoot {
		c.AuditKV["as_root"] = "true"
		if c.Subject.Role != policy.RoleAdmin {
			return worker.Identity{}, false, Errf(rpc.CodeForbidden, "")
		}
		if f.rootUntil(c.SessionKey).IsZero() {
			return worker.Identity{}, false, Errf(CodeRootRequired, "")
		}
		id, err := f.Lookup("root")
		if err != nil {
			return worker.Identity{}, false, err
		}
		return id, true, nil
	}
	id, err := f.Lookup(c.Subject.LinuxUser)
	if err != nil {
		return worker.Identity{}, false, Errf(rpc.CodeNotFound, "linux user not found")
	}
	if id.UID == 0 {
		return worker.Identity{}, false, Errf(rpc.CodeForbidden, "")
	}
	return id, false, nil
}

// guard turns the user's confirmation into the worker's sensitive-path permit:
// both the explicit confirmation and a fresh step-up are required (Annex B).
func guard(c Call, flags fsFlags) files.Guard {
	if flags.ConfirmSensitive {
		c.AuditKV["sensitive"] = "true"
	}
	return files.Guard{SensitiveOK: flags.ConfirmSensitive && c.Subject.StepUp}
}

// workerErr maps worker failures to stable helper errors.
func workerErr(c Call, flags fsFlags, err error) error {
	if err == nil {
		return nil
	}
	var oe *worker.OpError
	if errors.As(err, &oe) {
		if oe.Code == files.CodeSensitive && flags.ConfirmSensitive && !c.Subject.StepUp {
			return Errf(rpc.CodeStepUpNeeded, "")
		}
		if slices.Contains(files.Codes, oe.Code) {
			return &OpError{Code: oe.Code}
		}
		return Errf(rpc.CodeInternal, "")
	}
	var he *OpError
	if errors.As(err, &he) {
		return he
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return Errf(rpc.CodeTimeout, "")
	}
	return err
}

func decodeFS(c Call, v any) error {
	if err := rpc.DecodeStrict(c.Params, v); err != nil {
		return Errf(rpc.CodeBadRequest, "invalid parameters")
	}
	return nil
}

func auditTarget(c Call) string {
	if p := c.AuditKV["path"]; p != "" {
		return "path:" + p
	}
	return ""
}

// relayOut runs a worker that writes a chunked stream (metadata chunk first)
// and relays it to the client.
func (f *FileOps) relayOut(ctx context.Context, st *Stream, id worker.Identity, elevated bool, op string, args any) (files.ReadResult, error) {
	var res files.ReadResult
	pr, pw, err := os.Pipe()
	if err != nil {
		return res, err
	}
	defer func() { _ = pr.Close() }()
	errc := make(chan error, 1)
	go func() { errc <- f.Worker.RunStream(ctx, id, elevated, op, args, &res, pw) }()
	fail := func(e error) (files.ReadResult, error) {
		_ = pr.Close()
		if werr := <-errc; werr != nil {
			return res, werr
		}
		return res, e
	}
	meta, err := rpc.ReadChunk(pr)
	if err != nil {
		return fail(Errf(rpc.CodeInternal, ""))
	}
	if err := st.Ready(json.RawMessage(meta)); err != nil {
		return fail(err)
	}
	w := st.Writer()
	if _, err := io.Copy(w, &rpc.ChunkReader{R: pr}); err != nil {
		return fail(Errf(files.CodeAborted, ""))
	}
	if err := w.Close(); err != nil {
		return fail(err)
	}
	return res, <-errc
}

// relayIn feeds the client's chunked upload (at most max bytes) into a worker.
func (f *FileOps) relayIn(ctx context.Context, st *Stream, id worker.Identity, elevated bool, op string, args any, max int64, out any) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- f.Worker.RunStream(ctx, id, elevated, op, args, out, pr) }()
	cw := rpc.ChunkWriter{W: pw}
	n, cerr := io.Copy(cw, io.LimitReader(st.Reader(), max+1))
	if cerr == nil && n > max {
		cerr = Errf(files.CodeTooLarge, "")
	}
	if cerr == nil {
		cerr = cw.Close() // end marker: the worker commits
	}
	_ = pw.Close() // without end marker the worker discards the data
	werr := <-errc
	if cerr != nil {
		var oe *OpError
		if errors.As(cerr, &oe) {
			return oe
		}
		if werr != nil {
			return werr
		}
		return Errf(files.CodeAborted, "")
	}
	return werr
}

func (f *FileOps) uploadMax() int64 {
	mib := 1024
	if f.UploadMiB != nil {
		if v := f.UploadMiB(); v > 0 {
			mib = v
		}
	}
	return int64(mib) << 20
}

// Register installs the fs.* operations.
func (f *FileOps) Register(ops map[string]*Op) {
	f.root = map[string]time.Time{}
	f.tokens = map[string]dlToken{}

	type listParams struct {
		files.ListArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.list", Action: policy.ActFiles, NoAudit: true, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p listParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			var res files.ListResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.list", p.ListArgs, &res))
		}})

	type statParams struct {
		files.Target
		fsFlags
	}
	Register(ops, &Op{Name: "fs.stat", Action: policy.ActFiles, NoAudit: true, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p statParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			var res files.StatResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.stat", files.StatArgs{Target: p.Target}, &res))
		}})

	type createParams struct {
		files.CreateArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.create", Action: policy.ActFiles, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p createParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = files.Join(p.Dir, files.Display(p.Name))
			c.AuditKV["kind"] = p.Kind
			c.AuditKV["mode"] = fmt.Sprintf("%04o", p.Mode)
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			var res files.PathResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.create", p.CreateArgs, &res))
		}})

	type renameParams struct {
		files.RenameArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.rename", Action: policy.ActFiles, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p renameParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			c.AuditKV["new_name"] = files.Display(p.NewName)
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			var res files.PathResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.rename", p.RenameArgs, &res))
		}})

	type transferParams struct {
		files.TransferArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.transfer", Action: policy.ActFiles, AuditTarget: auditTarget, Timeout: 15 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p transferParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			c.AuditKV["dest"] = p.DestDir
			if p.NewName != "" {
				c.AuditKV["dest"] = files.Join(p.DestDir, files.Display(p.NewName))
			}
			c.AuditKV["copy"] = strconv.FormatBool(p.Copy)
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			var res files.TransferResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.transfer", p.TransferArgs, &res))
		}})

	type deleteParams struct {
		files.DeleteArgs
		fsFlags
		// Confirm must repeat the entry name for recursive deletion ("type the name").
		Confirm string `json:"confirm,omitempty"`
	}
	Register(ops, &Op{Name: "fs.delete", Action: policy.ActFiles, AuditTarget: auditTarget, Timeout: 15 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p deleteParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			c.AuditKV["recursive"] = strconv.FormatBool(p.Recursive)
			if p.Recursive {
				_, name, err := p.Resolve()
				if err != nil || p.Confirm != files.Display(name) {
					return nil, Errf(rpc.CodeValidation, "confirmation does not match")
				}
			}
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			var res files.DeleteResult
			err = f.Worker.Run(ctx, id, el, "fs.delete", p.DeleteArgs, &res)
			c.AuditKV["entries"] = strconv.Itoa(res.Entries)
			return res, workerErr(c, p.fsFlags, err)
		}})

	type chmodParams struct {
		files.ChmodArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.chmod", Action: policy.ActFiles, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p chmodParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			c.AuditKV["mode"] = fmt.Sprintf("%04o", p.Mode)
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			var res files.PathResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.chmod", p.ChmodArgs, &res))
		}})

	type chownParams struct {
		files.ChownArgs
		fsFlags
	}
	// chown is root-only in Linux; Daemonica allows it only in the admin root
	// mode (admin + step-up, SPEC §7.4).
	Register(ops, &Op{Name: "fs.chown", Action: policy.ActFiles, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p chownParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			c.AuditKV["owner"] = p.User + ":" + p.Group
			if !p.AsRoot {
				return nil, Errf(CodeRootRequired, "")
			}
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			var res files.PathResult
			return res, workerErr(c, p.fsFlags, f.Worker.Run(ctx, id, el, "fs.chown", p.ChownArgs, &res))
		}})

	// --- root mode ---
	type rootStatus struct {
		Active bool       `json:"active"`
		Until  *time.Time `json:"until,omitempty"`
	}
	status := func(grant string) rootStatus {
		if u := f.rootUntil(grant); !u.IsZero() {
			u = u.UTC()
			return rootStatus{Active: true, Until: &u}
		}
		return rootStatus{}
	}
	Register(ops, &Op{Name: "fs.root_enable", Action: policy.ActFilesRoot,
		Handle: func(_ context.Context, c Call) (any, error) {
			f.mu.Lock()
			f.root[c.SessionKey] = f.now().Add(RootModeTTL)
			f.mu.Unlock()
			return status(c.SessionKey), nil
		}})
	Register(ops, &Op{Name: "fs.root_disable", Action: policy.ActFiles,
		Handle: func(_ context.Context, c Call) (any, error) {
			f.mu.Lock()
			delete(f.root, c.SessionKey)
			f.mu.Unlock()
			return status(c.SessionKey), nil
		}})
	// fs.info tells the UI where to start and what applies to this session.
	Register(ops, &Op{Name: "fs.info", Action: policy.ActFiles, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			home := "/"
			if id, err := f.Lookup(c.Subject.LinuxUser); err == nil && files.ValidPath(id.Home) {
				home = id.Home
			}
			return map[string]any{"home": home, "root": status(c.SessionKey), "upload_limit_mib": f.uploadMax() >> 20,
				"edit_limit": files.MaxEditBytes}, nil
		}})

	// --- editor ---
	type readParams struct {
		files.Target
		fsFlags
	}
	Register(ops, &Op{Name: "fs.read", Action: policy.ActFiles, NoAudit: true, AuditTarget: auditTarget, Timeout: 2 * time.Minute,
		Stream: func(ctx context.Context, c Call, st *Stream) (any, error) {
			var p readParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			args := files.ReadArgs{Target: p.Target, Edit: true, Guard: guard(c, p.fsFlags)}
			res, err := f.relayOut(ctx, st, id, el, "fs.read", args)
			return res, workerErr(c, p.fsFlags, err)
		}})

	type writeParams struct {
		files.WriteArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.write", Action: policy.ActFiles, AuditTarget: auditTarget, Timeout: 2 * time.Minute,
		Stream: func(ctx context.Context, c Call, st *Stream) (any, error) {
			var p writeParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			if err := st.Ready(nil); err != nil {
				return nil, err
			}
			var res files.WriteResult
			err = f.relayIn(ctx, st, id, el, "fs.write", p.WriteArgs, files.MaxEditBytes, &res)
			if err == nil {
				c.AuditKV["size"] = strconv.FormatInt(res.Size, 10)
				c.AuditKV["sha256"] = res.Hash
			}
			return res, workerErr(c, p.fsFlags, err)
		}})

	// --- upload ---
	type uploadParams struct {
		files.UploadArgs
		fsFlags
	}
	Register(ops, &Op{Name: "fs.upload", Action: policy.ActFiles, AuditTarget: auditTarget, Timeout: 12 * time.Hour,
		Stream: func(ctx context.Context, c Call, st *Stream) (any, error) {
			var p uploadParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = files.Join(p.Dir, files.Display(p.Name))
			c.AuditKV["overwrite"] = strconv.FormatBool(p.Overwrite)
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			p.Guard = guard(c, p.fsFlags)
			p.Max = f.uploadMax()
			var chk files.UploadCheck
			pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err = f.Worker.Run(pctx, id, el, "fs.upload_check", p.UploadArgs, &chk)
			cancel()
			if err != nil {
				return nil, workerErr(c, p.fsFlags, err)
			}
			if err := st.Ready(map[string]any{"path": chk.Path, "max": p.Max}); err != nil {
				return nil, err
			}
			var res files.UploadResult
			err = f.relayIn(ctx, st, id, el, "fs.upload", p.UploadArgs, p.Max, &res)
			if err == nil {
				c.AuditKV["size"] = strconv.FormatInt(res.Size, 10)
				c.AuditKV["sha256"] = res.SHA256
			}
			return res, workerErr(c, p.fsFlags, err)
		}})

	// --- download (one-time, session-bound token, 60 s; SPEC §3.5) ---
	type tokenParams struct {
		files.Target
		fsFlags
	}
	Register(ops, &Op{Name: "fs.download_token", Action: policy.ActFiles, AuditTarget: auditTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p tokenParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			c.AuditKV["path"] = p.Path()
			id, el, err := f.identity(c, p.fsFlags)
			if err != nil {
				return nil, err
			}
			g := guard(c, p.fsFlags)
			var res files.StatResult
			if err := f.Worker.Run(ctx, id, el, "fs.stat", files.StatArgs{Target: p.Target, Regular: true, Guard: g}, &res); err != nil {
				return nil, workerErr(c, p.fsFlags, err)
			}
			var raw [32]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return nil, err
			}
			tok := base64.RawURLEncoding.EncodeToString(raw[:])
			sum := sha256.Sum256([]byte(tok))
			exp := f.now().Add(DownloadTokenTTL)
			f.mu.Lock()
			for k, t := range f.tokens {
				if !f.now().Before(t.expires) {
					delete(f.tokens, k)
				}
			}
			if len(f.tokens) > 1000 {
				f.mu.Unlock()
				return nil, Errf(rpc.CodeRateLimited, "")
			}
			f.tokens[hex.EncodeToString(sum[:])] = dlToken{grant: c.SessionKey, asRoot: p.AsRoot, target: p.Target,
				sensitive: g.SensitiveOK, expires: exp}
			f.mu.Unlock()
			return map[string]any{"token": tok, "expires_at": exp.UTC(), "size": res.Size}, nil
		}})

	type downloadParams struct {
		Token  string `json:"token"`
		Offset int64  `json:"offset,omitempty"`
		Length int64  `json:"length,omitempty"`
	}
	Register(ops, &Op{Name: "fs.download", Action: policy.ActFiles, AuditTarget: auditTarget, Timeout: 12 * time.Hour,
		Stream: func(ctx context.Context, c Call, st *Stream) (any, error) {
			var p downloadParams
			if err := decodeFS(c, &p); err != nil {
				return nil, err
			}
			sum := sha256.Sum256([]byte(p.Token))
			key := hex.EncodeToString(sum[:])
			f.mu.Lock()
			t, ok := f.tokens[key]
			delete(f.tokens, key) // one-time
			f.mu.Unlock()
			if !ok || t.grant != c.SessionKey || !f.now().Before(t.expires) {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			flags := fsFlags{AsRoot: t.asRoot}
			c.AuditKV["path"] = t.target.Path()
			if p.Offset > 0 || p.Length > 0 {
				c.AuditKV["range"] = fmt.Sprintf("%d+%d", p.Offset, p.Length)
			}
			id, el, err := f.identity(c, flags)
			if err != nil {
				return nil, err
			}
			args := files.ReadArgs{Target: t.target, Offset: p.Offset, Length: p.Length, Guard: files.Guard{SensitiveOK: t.sensitive}}
			res, err := f.relayOut(ctx, st, id, el, "fs.read", args)
			c.AuditKV["bytes"] = strconv.FormatInt(res.Bytes, 10)
			return res, workerErr(c, flags, err)
		}})
}
