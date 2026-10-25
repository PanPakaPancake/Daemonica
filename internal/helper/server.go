// Package helper implements daemonica-helper: the small privileged process that
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
	// ChannelWeb is /run/daemonica/helper.sock (peer must be the daemonica-web UID).
	ChannelWeb Channel = iota
	// ChannelAdmin is /run/daemonica/admin.sock (peer must be UID 0).
	ChannelAdmin
)

// Call is the input to an operation handler.
type Call struct {
	Channel Channel
	Subject *policy.Subject // nil for pre-auth and admin-channel operations
	GrantID string          // hashed grant identifier (for audit "session")
	// SessionKey identifies the login session across step-up token rotation.
	SessionKey string
	Grant      string // opaque grant token (only for session operations such as step-up/logout)
	SourceIP   string
	Params     []byte
	// AuditKV collects audit parameters set by the handler (never secrets or contents).
	AuditKV map[string]string
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
	// Stream replaces Handle for streaming operations (uploads/downloads, see
	// rpc/stream.go). The handler calls st.Ready before any data flows.
	Stream func(ctx context.Context, c Call, st *Stream) (any, error)
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
		if op, ok := s.Ops[req.Op]; ok && op.Stream != nil {
			s.serveStream(ctx, c, req, op)
			return
		}
		resp := s.Dispatch(ctx, req)
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := rpc.WriteFrame(c, resp); err != nil {
			return
		}
	}
}

// authorize resolves the caller and checks the static policy of op. A non-nil
// response means the request is refused.
func (s *Server) authorize(op *Op, req *rpc.Request) (Call, *rpc.Response) {
	call := Call{Channel: s.Channel, SourceIP: req.SourceIP, Params: req.Params, AuditKV: map[string]string{}}
	switch {
	case op.AdminChannel:
		if s.Channel != ChannelAdmin {
			return call, rpc.Fail(req.ID, rpc.CodeUnknownOp, "")
		}
	case s.Channel == ChannelAdmin:
		// Web operations are not exposed on the admin socket.
		return call, rpc.Fail(req.ID, rpc.CodeUnknownOp, "")
	case op.PreAuth:
		// No subject.
	default:
		subj, gid, err := s.Grants.Resolve(req.Grant, time.Now())
		if err != nil {
			s.audit(op, call, audit.ResultDenied, "invalid or expired grant")
			return call, rpc.Fail(req.ID, rpc.CodeUnauthorized, "")
		}
		call.Subject, call.GrantID, call.Grant = &subj, gid, req.Grant
		call.SessionKey = s.Grants.SessionKey(req.Grant)
		switch policy.Decide(subj, op.Action, 0, false) {
		case policy.Deny:
			s.audit(op, call, audit.ResultDenied, "policy")
			return call, rpc.Fail(req.ID, rpc.CodeForbidden, "")
		case policy.NeedStepUp:
			s.audit(op, call, audit.ResultDenied, "step-up required")
			return call, rpc.Fail(req.ID, rpc.CodeStepUpNeeded, "")
		case policy.Allow:
		}
	}
	return call, nil
}

// deniedCodes are audited as "denied" rather than "error".
var deniedCodes = map[string]bool{rpc.CodeForbidden: true, rpc.CodeStepUpNeeded: true, rpc.CodeLockout: true,
	rpc.CodeTokenInvalid: true, "path_blocked": true, "protected_path": true, "sensitive_path": true,
	"permission_denied": true, "root_mode_required": true}

// finish audits the outcome and builds the response.
func (s *Server) finish(ctx context.Context, op *Op, call Call, id uint64, result any, err error) *rpc.Response {
	if err != nil {
		var oe *OpError
		if errors.As(err, &oe) {
			res := audit.ResultError
			if deniedCodes[oe.Code] {
				res = audit.ResultDenied
			}
			s.audit(op, call, res, oe.Code)
			return rpc.Fail(id, oe.Code, oe.Msg)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			s.audit(op, call, audit.ResultError, "timeout")
			return rpc.Fail(id, rpc.CodeTimeout, "")
		}
		s.Log.Error("operation failed", "op", op.Name, "err", err)
		s.audit(op, call, audit.ResultError, "internal")
		return rpc.Fail(id, rpc.CodeInternal, "")
	}
	if !op.NoAudit || call.AuditKV["sensitive"] != "" || call.AuditKV["as_root"] != "" {
		s.audit(op, call, audit.ResultOK, "")
	}
	resp, rerr := rpc.Succeed(id, result)
	if rerr != nil {
		return rpc.Fail(id, rpc.CodeInternal, "")
	}
	return resp
}

// Dispatch authenticates, authorizes, executes and audits one request.
func (s *Server) Dispatch(ctx context.Context, req *rpc.Request) *rpc.Response {
	op, ok := s.Ops[req.Op]
	if !ok {
		return rpc.Fail(req.ID, rpc.CodeUnknownOp, "")
	}
	if op.Handle == nil {
		return rpc.Fail(req.ID, rpc.CodeBadRequest, "streaming operation")
	}
	call, fail := s.authorize(op, req)
	if fail != nil {
		return fail
	}
	opCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	result, err := op.Handle(opCtx, call)
	return s.finish(opCtx, op, call, req.ID, result, err)
}

// Stream is the data channel of a streaming operation.
type Stream struct {
	rw   io.ReadWriter
	conn net.Conn
	id   uint64
}

// Duplex returns the raw connection for operations where both sides send
// chunks at the same time and pauses may be long (terminal). Unlike the
// Reader/Writer path it has no per-read idle deadline; the operation's
// context still ends it.
func (st *Stream) Duplex() io.ReadWriter { return st.conn }

// Ready sends the ready frame with metadata; data may flow afterwards.
func (st *Stream) Ready(meta any) error {
	resp, err := rpc.Succeed(st.id, meta)
	if err != nil {
		return err
	}
	return rpc.WriteFrame(st.rw, resp)
}

// Reader returns the client's data (uploads): io.EOF after the end marker,
// io.ErrUnexpectedEOF if the client broke off.
func (st *Stream) Reader() *rpc.ChunkReader { return &rpc.ChunkReader{R: st.rw} }

// Writer returns a chunk writer towards the client (downloads); Close it to
// send the end marker.
func (st *Stream) Writer() rpc.ChunkWriter { return rpc.ChunkWriter{W: st.rw} }

func (s *Server) serveStream(ctx context.Context, c net.Conn, req *rpc.Request, op *Op) {
	call, fail := s.authorize(op, req)
	if fail != nil {
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_ = rpc.WriteFrame(c, fail)
		return
	}
	opCtx, cancel := context.WithTimeout(ctx, op.Timeout)
	defer cancel()
	context.AfterFunc(opCtx, func() { _ = c.SetDeadline(time.Now()) })
	st := &Stream{rw: rpc.NewStreamConn(c), conn: c, id: req.ID}
	result, err := op.Stream(opCtx, call, st)
	resp := s.finish(opCtx, op, call, req.ID, result, err)
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_ = rpc.WriteFrame(c, resp)
}

func (s *Server) audit(op *Op, c Call, result, reason string) {
	if s.Audit == nil {
		return
	}
	var params map[string]string
	if len(c.AuditKV) > 0 {
		params = c.AuditKV
	}
	ev := audit.Event{Action: op.Name, Result: result, Reason: reason, SourceIP: c.SourceIP, Params: params,
		Session: c.GrantID}
	if c.Subject != nil {
		ev.Actor = audit.Actor{AccountID: c.Subject.AccountID, Role: string(c.Subject.Role), LinuxUser: c.Subject.LinuxUser}
		ev.StepUp = c.Subject.StepUp
	} else if c.Channel == ChannelAdmin {
		ev.Actor = audit.Actor{Name: "root (daemonica-admin)", LinuxUser: "root"}
	}
	if op.AuditTarget != nil {
		ev.Target = op.AuditTarget(c)
	}
	if _, err := s.Audit.Append(ev); err != nil {
		s.Log.Error("audit append failed", "err", err)
	}
}
