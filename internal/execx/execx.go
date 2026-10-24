// Package execx runs external programs the way SPEC §3.2 rule 7 requires:
// absolute path, argv array (never a shell), fixed minimal environment,
// timeout, output limit and context cancellation.
package execx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// Env is the fixed environment for child processes.
var Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=", "PAGER=cat"}

// ErrTruncated is returned (with the partial output) when the limit was hit.
var ErrTruncated = errors.New("execx: output truncated")

// Result of a run.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type limitWriter struct {
	buf   bytes.Buffer
	limit int
	hit   bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	room := w.limit - w.buf.Len()
	if room <= 0 {
		w.hit = true
		return len(p), nil
	}
	if len(p) > room {
		w.buf.Write(p[:room])
		w.hit = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

// Run executes path with args. path must be absolute. stdin may be nil.
func Run(ctx context.Context, timeout time.Duration, limit int, stdin io.Reader, path string, args ...string) (Result, error) {
	if !filepath.IsAbs(path) {
		return Result{}, errors.New("execx: path must be absolute")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // fixed absolute path, argv only
	cmd.Env = Env
	cmd.Dir = "/"
	cmd.Stdin = stdin
	cmd.WaitDelay = 2 * time.Second
	out := &limitWriter{limit: limit}
	errw := &limitWriter{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errw
	err := cmd.Run()
	res := Result{Stdout: out.buf.Bytes(), Stderr: errw.buf.Bytes(), ExitCode: cmd.ProcessState.ExitCode()}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return res, err
	}
	if out.hit {
		return res, ErrTruncated
	}
	return res, nil
}
