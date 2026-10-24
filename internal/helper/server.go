// Package helper implements daemonia-helper: the small privileged process that
// executes typed, allowlisted operations on behalf of the web process and the
// root-only admin CLI (SPEC §3.2). It never listens on TCP.
package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// Channel identifies which socket a request arrived on.
type Channel int

const (
	// ChannelWeb is /run/daemonia/helper.sock (peer must be the daemonia-web UID).
	ChannelWeb Channel = iota
	// ChannelAdmin is /run/daemonia/admin.sock (peer must be UID 0).
	ChannelAdmin
)

// Call is the input to an operation handler.
type Call struct {
	Channel  Channel
	Subject  *policy.Subject // nil for pre-auth and admin-channel operations
	GrantID  string          // hashed grant identifier (for audit "session")
	SourceIP string
	Params   []byte
}

// Op is one allowlisted, typed operation (Annex D).
type Op struct {
	Name string
	// Action is the policy action checked for authenticated operations.
	Action policy.Action
	// PreAuth marks operations callable without a grant (login/enrollment
	// ceremonies only). They are only reachable on the web channel.
	PreAuth bool
	// AdminChannel marks operations reachable exclusively over admin.sock.
	AdminChannel bool
	Timeout      time.Duration
	// Handle decodes Params strictly, validates them and performs the operation.
	Handle func(ctx context.Context, c Call) (any, error)
	// AuditTarget optionally extracts a target string for the audit log.
	AuditTarget func(c Call) string
	// NoAudit suppresses success audit records for high-frequency read operations.
	NoAudit bool
}

// OpError carries a stable error code back to the caller.
type OpError struct {
	Code string
	Msg  string
}

func (e *OpError) Error() string { return e.Code + ": " + e.Msg }

// Errf builds an OpError.
func Errf(code, format string, a ...any) error {
	return &OpError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Server dispatches requests on one channel.
type Server struct {
	Channel    Channel
	AllowedUID uint32
	Ops        map[string]*Op
	Grants     *GrantStore
	Audit      *audit.Logger
	Log        *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Register adds an operation. It panics on duplicates or on operations whose
// policy action is unknown, so mis-registrations fail at start-up.
func Register(ops map[string]*Op, op *Op) {
	if !rpc.ValidOpName(op.Name) {
		panic("helper: invalid op name " + op.Name)
	}
	if _, dup := ops[op.Name]; dup {
		panic("helper: duplicate op " + op.Name)
	}
	if !op.PreAuth && !op.AdminChannel {
		policy.MustKnow(op.Action)
	}
	if op.Timeout == 0 {
		op.Timeout = 30 * time.Second
	}
	ops[op.Name] = op
}

// ListenUnix creates a Unix socket with the given mode and group.
func ListenUnix(path string, mode os.FileMode, gid int) (net.Listener, error) {
	_ = os.Remove(path)
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			_ = l.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// PeerUID returns the UID of the process on the other end of a Unix socket (SO_PEERCRED).
func PeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) //nolint:gosec // fd fits int
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		uid, err := PeerUID(c)
		if err != nil || uid != s.AllowedUID {
			s.Log.Warn("rejected helper connection", "peer_uid", uid, "channel", s.Channel)
			_ = c.Close()
			continue
		}
		s.track(c, true)
		go func() {
			defer s.track(c, false)
			s.handleConn(ctx, c)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
		_ = c.Close()
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		req, err := rpc.ReadRequest(c)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_ = rpc.WriteFrame(c, rpc.Fail(0, rpc.CodeBadRequest, "malformed request"))
			}
			return
		}
		resp := s.Dispatch(ctx, req)
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := rpc.WriteFrame(c, resp); err != nil {
			return
		}
	}
}

// Dispatch authenticates, authorizes, executes and audits one request.
func (s *Server) Dispatch(ctx context.Context, req *rpc.Request) *rpc.Response {
	op, ok := s.Ops[req.Op]
	if !ok {
		return rpc.Fail(req.ID, rpc.CodeUnknownOp, "")
	}
	call := Call{Channel: s.Channel, SourceIP: req.SourceIP, Params: req.Params}

	switch {
	case op.AdminChannel:
		if s.Channel != ChannelAdmin {
			return rpc.Fail(req.ID, rpc.CodeUnknownOp, "")
		}
	case s.Channel == ChannelAdmin:
		// Web operations are not exposed on the admin socket.
		return rpc.Fail(req.ID, rpc.CodeUnknownOp, "")
	case op.PreAuth:
		// No subject.
	default:
		subj, gid, err := s.Grants.Resolve(req.Grant, time.Now())
		if err != nil {
			s.audit(op, call, nil, audit.ResultDenied, "invalid or expired grant")
			return rpc.Fail(req.ID, rpc.CodeUnauthorized, "")
		}
		call.Subject, call.GrantID = &subj, gid
		switch policy.Decide(subj, op.Action, 0, false) {
		case policy.Deny:
			s.audit(op, call, nil, audit.ResultDenied, "policy")
			return rpc.Fail(req.ID, rpc.CodeForbidden, "")
		case policy.NeedStepUp:
			s.audit(op, call, nil, audit.ResultDenied, "step-up required")
			return rpc.Fail(req.ID, rpc.CodeStepUpNeeded, "")
		case policy.Allow:
		}
	}

	opCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	result, err := op.Handle(opCtx, call)
	if err != nil {
		var oe *OpError
		if errors.As(err, &oe) {
			res := audit.ResultError
			if oe.Code == rpc.CodeForbidden || oe.Code == rpc.CodeStepUpNeeded || oe.Code == rpc.CodeLockout || oe.Code == rpc.CodeTokenInvalid {
				res = audit.ResultDenied
			}
			s.audit(op, call, nil, res, oe.Code)
			return rpc.Fail(req.ID, oe.Code, oe.Msg)
		}
		if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
			s.audit(op, call, nil, audit.ResultError, "timeout")
			return rpc.Fail(req.ID, rpc.CodeTimeout, "")
		}
		s.Log.Error("operation failed", "op", op.Name, "err", err)
		s.audit(op, call, nil, audit.ResultError, "internal")
		return rpc.Fail(req.ID, rpc.CodeInternal, "")
	}
	if !op.NoAudit {
		s.audit(op, call, nil, audit.ResultOK, "")
	}
	resp, err := rpc.Succeed(req.ID, result)
	if err != nil {
		return rpc.Fail(req.ID, rpc.CodeInternal, "")
	}
	return resp
}

func (s *Server) audit(op *Op, c Call, params map[string]string, result, reason string) {
	if s.Audit == nil {
		return
	}
	ev := audit.Event{Action: op.Name, Result: result, Reason: reason, SourceIP: c.SourceIP, Params: params,
		Session: c.GrantID}
	if c.Subject != nil {
		ev.Actor = audit.Actor{AccountID: c.Subject.AccountID, Role: string(c.Subject.Role), LinuxUser: c.Subject.LinuxUser}
		ev.StepUp = c.Subject.StepUp
	} else if c.Channel == ChannelAdmin {
		ev.Actor = audit.Actor{Name: "root (daemonia-admin)", LinuxUser: "root"}
	}
	if op.AuditTarget != nil {
		ev.Target = op.AuditTarget(c)
	}
	if _, err := s.Audit.Append(ev); err != nil {
		s.Log.Error("audit append failed", "err", err)
	}
}
