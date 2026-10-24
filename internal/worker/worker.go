// Package worker runs file operations in a short-lived child process that has
// assumed the credentials of the mapped Linux user (SPEC §3.2 rule 6): the
// helper re-executes its own binary with SysProcAttr.Credential, the child sets
// no_new_privs and then performs exactly one typed operation. Linux file
// permissions are therefore the boundary, not helper code.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// Arg is the argv[1] that switches the helper binary into worker mode.
const Arg = "__worker"

// MaxIO bounds worker request/response sizes.
const MaxIO = 8 << 20

// Request is sent to the worker on stdin.
type Request struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

// Response is written by the worker to stdout.
type Response struct {
	OK     bool            `json:"ok"`
	Code   string          `json:"code,omitempty"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Identity is the Linux user a worker runs as.
type Identity struct {
	Name   string
	UID    uint32
	GID    uint32
	Groups []uint32
	Home   string
}

// Lookup resolves a user name to an Identity (including supplementary groups).
func Lookup(name string) (Identity, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return Identity{}, err
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return Identity{}, errors.New("worker: bad uid/gid")
	}
	id := Identity{Name: u.Username, UID: uint32(uid), GID: uint32(gid), Home: u.HomeDir}
	gids, _ := u.GroupIds()
	for _, g := range gids {
		if v, err := strconv.ParseUint(g, 10, 32); err == nil {
			id.Groups = append(id.Groups, uint32(v))
		}
	}
	return id, nil
}

// Runner starts workers.
type Runner struct {
	// Binary is the helper executable (default: /proc/self/exe resolved at start-up).
	Binary  string
	Timeout time.Duration
}

// OpError is a typed error returned by a worker operation.
type OpError struct{ Code, Msg string }

func (e *OpError) Error() string { return e.Code + ": " + e.Msg }

// Run executes op as id. Root (UID 0) is only allowed when elevated is true
// (admin "as root" mode after step-up, SPEC §7.4).
func (r *Runner) Run(ctx context.Context, id Identity, elevated bool, op string, args, out any) error {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.run(ctx, id, elevated, op, args, out, nil)
}

// RunStream is Run with a data pipe end passed to the worker as fd 3 (see
// Data). The caller keeps the other end and feeds or drains it concurrently;
// RunStream closes data in the parent once the worker has started. Its
// lifetime is bounded by ctx only.
func (r *Runner) RunStream(ctx context.Context, id Identity, elevated bool, op string, args, out any, data *os.File) error {
	return r.run(ctx, id, elevated, op, args, out, data)
}

func (r *Runner) run(ctx context.Context, id Identity, elevated bool, op string, args, out any, data *os.File) error {
	if data != nil {
		defer func() { _ = data.Close() }()
	}
	if id.UID == 0 && !elevated {
		return errors.New("worker: refusing to run as root without elevation")
	}
	bin := r.Binary
	if bin == "" {
		bin = "/proc/self/exe"
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	req, _ := json.Marshal(Request{Op: op, Args: raw})
	cmd := exec.CommandContext(ctx, bin, Arg) //nolint:gosec // own binary, fixed argument
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=" + id.Home, "USER=" + id.Name}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: id.UID, Gid: id.GID, Groups: id.Groups},
		Setsid:     true,
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Stdin = bytes.NewReader(req)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limited{&stdout, MaxIO}, &limited{&stderr, 64 << 10}
	cmd.WaitDelay = 2 * time.Second
	if data != nil {
		cmd.ExtraFiles = []*os.File{data}
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	if data != nil {
		// The worker holds its own copy; closing ours lets EOF/EPIPE propagate.
		_ = data.Close()
	}
	if err := cmd.Wait(); err != nil && stdout.Len() == 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("worker: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return errors.New("worker: invalid response")
	}
	if !resp.OK {
		return &OpError{Code: resp.Code, Msg: resp.Error}
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	if len(p) > l.n {
		_, _ = l.w.Write(p[:l.n])
		l.n = 0
		return len(p), nil
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// Data returns the stream passed by RunStream as fd 3, or nil.
func Data() *os.File {
	f := os.NewFile(3, "data")
	if f == nil {
		return nil
	}
	if _, err := f.Stat(); err != nil {
		return nil
	}
	return f
}

// Handler implements one worker operation.
type Handler func(args json.RawMessage) (any, error)

// Main is called by the helper binary when argv[1] == Arg. It never returns.
func Main(handlers map[string]Handler) {
	// Irrevocably drop the ability to gain privileges (setuid, file caps).
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0); errno != 0 {
		emit(Response{Code: "internal_error", Error: "no_new_privs failed"})
	}
	syscall.Umask(0o077)
	in, err := io.ReadAll(io.LimitReader(os.Stdin, MaxIO))
	if err != nil {
		emit(Response{Code: "bad_request", Error: "read"})
	}
	var req Request
	if err := json.Unmarshal(in, &req); err != nil {
		emit(Response{Code: "bad_request", Error: "decode"})
	}
	h, ok := handlers[req.Op]
	if !ok {
		emit(Response{Code: "unknown_operation"})
	}
	res, err := h(req.Args)
	if err != nil {
		var oe *OpError
		if errors.As(err, &oe) {
			emit(Response{Code: oe.Code, Error: oe.Msg})
		}
		emit(Response{Code: "internal_error", Error: err.Error()})
	}
	raw, _ := json.Marshal(res)
	emit(Response{OK: true, Result: raw})
}

func emit(r Response) {
	b, _ := json.Marshal(r)
	_, _ = os.Stdout.Write(b)
	os.Exit(0)
}
