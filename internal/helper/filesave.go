package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strconv"

	"github.com/PanPakaPancake/daemonica/internal/files"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// SaveResult is the answer to fs.write. Saved is false when validation
// blocked the save or rolled it back; the file then has its previous content.
type SaveResult struct {
	files.WriteResult
	Saved      bool        `json:"saved"`
	Validation *Validation `json:"validation,omitempty"`
	Version    string      `json:"version,omitempty"` // stored previous version
}

func (f *FileOps) validator(p string) *Validator {
	if f.Validate != nil {
		return f.Validate(p)
	}
	return ValidatorFor(p)
}

// readText reads a file in editor mode through a worker and returns its
// metadata and content (empty for binary or oversized files).
func (f *FileOps) readText(ctx context.Context, id worker.Identity, elevated bool, a files.ReadArgs) (files.ReadMeta, []byte, error) {
	var meta files.ReadMeta
	var res files.ReadResult
	pr, pw, err := os.Pipe()
	if err != nil {
		return meta, nil, err
	}
	defer func() { _ = pr.Close() }()
	errc := make(chan error, 1)
	go func() { errc <- f.Worker.RunStream(ctx, id, elevated, "fs.read", a, &res, pw) }()
	raw, rerr := rpc.ReadChunk(pr)
	var data []byte
	if rerr == nil {
		rerr = json.Unmarshal(raw, &meta)
	}
	if rerr == nil {
		data, rerr = io.ReadAll(io.LimitReader(&rpc.ChunkReader{R: pr}, files.MaxEditBytes+1))
	}
	_ = pr.Close()
	if werr := <-errc; werr != nil {
		return meta, nil, werr
	}
	if rerr != nil {
		return meta, nil, Errf(rpc.CodeInternal, "")
	}
	return meta, data, nil
}

func hasCode(err error, code string) bool {
	var oe *worker.OpError
	return errors.As(err, &oe) && oe.Code == code
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// save writes editor content with previous-version backup (/etc) and
// validation of known configuration files.
func (f *FileOps) save(ctx context.Context, c Call, id worker.Identity, el bool, a files.WriteArgs, force bool, data []byte) (SaveResult, error) {
	want := a.Path()
	var v *Validator
	versioned := false
	if a.Raw == "" {
		v = f.validator(want)
		versioned = f.Versions.Covers(want)
	}

	// The current content is kept as previous version and for a rollback.
	var old []byte
	exists := false
	if versioned || (v != nil && !v.Pre) {
		meta, content, err := f.readText(ctx, id, el, files.ReadArgs{Target: a.Target, Edit: true, Guard: a.Guard})
		switch {
		case err == nil:
			// Only a regular text file with the expected content is a usable
			// baseline; otherwise the write below refuses (conflict, symlink).
			exists = meta.Path == want && !meta.Binary && !meta.TooLarge && meta.Hash == a.ExpectedHash
			old = content
		case hasCode(err, files.CodeNotFound):
		default:
			return SaveResult{}, err
		}
	}

	if v != nil && v.Pre {
		tmp, cleanup, err := preCopy(f.StateDir, path.Base(want), data)
		if err != nil {
			return SaveResult{}, Errf(rpc.CodeInternal, "")
		}
		val := v.Run(ctx, tmp, want)
		cleanup()
		if !val.OK {
			c.AuditKV["validation"] = "failed"
			c.AuditKV["saved"] = "false"
			return SaveResult{Validation: &val}, nil
		}
		if !val.Skipped {
			c.AuditKV["validation"] = "ok"
		}
		v = nil // done
	}

	// Baseline of a post-save check: if the live configuration already fails,
	// a failure after the save is not this edit's fault and is not rolled back.
	baselineOK := true
	if v != nil {
		baselineOK = v.Run(ctx, want, want).OK
	}

	var stored Version
	if versioned && exists && sha256Hex(old) != sha256Hex(data) {
		var err error
		if stored, err = f.Versions.Save(want, old, c.Subject.AccountID); err != nil {
			return SaveResult{}, Errf(rpc.CodeInternal, "")
		}
	}
	dropStored := func() {
		if stored.ID != "" {
			f.Versions.Remove(want, stored.ID)
			stored = Version{}
		}
	}

	var res files.WriteResult
	if err := f.relayIn(ctx, bytes.NewReader(data), id, el, "fs.write", a, files.MaxEditBytes, &res); err != nil {
		dropStored()
		return SaveResult{}, err
	}
	c.AuditKV["size"] = strconv.FormatInt(res.Size, 10)
	c.AuditKV["sha256"] = res.Hash
	out := SaveResult{WriteResult: res, Saved: true, Version: stored.ID}
	if stored.ID != "" {
		c.AuditKV["previous_version"] = stored.ID
	}
	if v == nil {
		return out, nil
	}

	val := v.Run(ctx, res.Path, res.Path)
	out.Validation = &val
	switch {
	case val.Skipped:
		out.Validation = nil
	case val.OK:
		c.AuditKV["validation"] = "ok"
	case force:
		c.AuditKV["validation"] = "failed_kept"
	case !baselineOK:
		val.Preexisting = true
		c.AuditKV["validation"] = "failed_preexisting"
	default:
		c.AuditKV["validation"] = "failed"
		// Restore the previous state.
		var rerr error
		if exists {
			back := a
			back.ExpectedHash = res.Hash
			var rres files.WriteResult
			rerr = f.relayIn(ctx, bytes.NewReader(old), id, el, "fs.write", back, files.MaxEditBytes, &rres)
			if rerr == nil {
				out.WriteResult = rres
			}
		} else if a.Create {
			var dres files.DeleteResult
			rerr = f.Worker.Run(ctx, id, el, "fs.delete", files.DeleteArgs{Target: a.Target, Guard: a.Guard}, &dres)
		} else {
			rerr = errors.New("no baseline")
		}
		if rerr == nil {
			val.RolledBack = true
			out.Saved = false
			out.Version = ""
			dropStored()
			c.AuditKV["rolled_back"] = "true"
		} else {
			c.AuditKV["rolled_back"] = "false"
		}
	}
	c.AuditKV["saved"] = strconv.FormatBool(out.Saved)
	return out, nil
}

// versionAccess checks that the caller can read the current file (under its
// own identity, like the editor) and returns its canonical path.
func (f *FileOps) versionAccess(ctx context.Context, c Call, t files.Target, flags fsFlags) (string, error) {
	id, el, err := f.identity(c, flags)
	if err != nil {
		return "", err
	}
	meta, _, err := f.readText(ctx, id, el, files.ReadArgs{Target: t, Edit: true, Guard: guard(c, flags)})
	if err != nil {
		return "", workerErr(c, flags, err)
	}
	return meta.Path, nil
}
