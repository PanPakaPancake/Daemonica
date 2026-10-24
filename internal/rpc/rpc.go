// Package rpc defines the versioned, length-prefixed wire protocol spoken
// between daemonica-web / daemonica-admin and daemonica-helper over Unix sockets
// (SPEC §3.2 rule 1).
//
// Frame layout: a 4-byte big-endian payload length followed by a JSON payload.
// Payloads larger than MaxFrameSize are rejected before any allocation of the
// payload buffer. Large data is transferred via dedicated streams, never via
// a single frame.
package rpc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Version is the protocol version. Peers MUST reject frames with a different version.
const Version = 1

// MaxFrameSize is the hard upper bound for a single frame payload (1 MiB).
const MaxFrameSize = 1 << 20

// Errors returned by the framing layer.
var (
	ErrFrameTooLarge   = errors.New("rpc: frame exceeds maximum size")
	ErrEmptyFrame      = errors.New("rpc: empty frame")
	ErrVersionMismatch = errors.New("rpc: protocol version mismatch")
	ErrInvalidOpName   = errors.New("rpc: invalid operation name")
)

// opNameRE restricts operation names to the documented namespace form, e.g.
// "systemd.restart" or "firewall.logs.query".
var opNameRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}(\.[a-z][a-z0-9_]{0,31}){1,3}$`)

// ValidOpName reports whether name is syntactically a valid operation name.
func ValidOpName(name string) bool { return opNameRE.MatchString(name) }

// Request is sent by a client to the helper.
type Request struct {
	V  int    `json:"v"`
	ID uint64 `json:"id"`
	// Op is the name of an allowlisted, typed helper operation.
	Op string `json:"op"`
	// Grant is the opaque grant token previously issued by the helper. The
	// helper resolves it to account, role, Linux user and step-up state
	// itself; the client never asserts identity or role.
	Grant string `json:"grant,omitempty"`
	// SourceIP is informational (for audit) and never used for authorization.
	SourceIP string          `json:"source_ip,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
}

// Error is a stable, machine-readable error. Message never contains internal details.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Response is sent by the helper.
type Response struct {
	V      int             `json:"v"`
	ID     uint64          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Stable error codes.
const (
	CodeBadRequest    = "bad_request"
	CodeUnknownOp     = "unknown_operation"
	CodeUnauthorized  = "unauthorized"
	CodeForbidden     = "forbidden"
	CodeStepUpNeeded  = "step_up_required"
	CodeConflict      = "conflict"
	CodeNotFound      = "not_found"
	CodeInternal      = "internal_error"
	CodeTimeout       = "timeout"
	CodeLockout       = "lockout_protection"
	CodeRateLimited   = "rate_limited"
	CodeUnavailable   = "unavailable"
	CodeNotSupported  = "not_supported"
	CodeValidation    = "validation_failed"
	CodeTokenInvalid  = "token_invalid"
	CodeSetupComplete = "setup_complete"
)

// WriteFrame marshals v and writes it as one frame.
func WriteFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("rpc: marshal: %w", err)
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload))) //nolint:gosec // bounded by MaxFrameSize
	copy(buf[4:], payload)
	_, err = w.Write(buf)
	return err
}

// ReadFrame reads one raw frame payload. It never allocates more than MaxFrameSize.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeStrict decodes JSON into v, rejecting unknown fields and trailing data.
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("rpc: trailing data")
	}
	// Ensure nothing but whitespace follows.
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("rpc: trailing data")
	}
	return nil
}

// ReadRequest reads and validates one request frame.
func ReadRequest(r io.Reader) (*Request, error) {
	payload, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	var req Request
	if err := DecodeStrict(payload, &req); err != nil {
		return nil, fmt.Errorf("rpc: decode request: %w", err)
	}
	if req.V != Version {
		return nil, ErrVersionMismatch
	}
	if !ValidOpName(req.Op) {
		return nil, ErrInvalidOpName
	}
	return &req, nil
}

// ReadResponse reads and validates one response frame.
func ReadResponse(r io.Reader) (*Response, error) {
	payload, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := DecodeStrict(payload, &resp); err != nil {
		return nil, fmt.Errorf("rpc: decode response: %w", err)
	}
	if resp.V != Version {
		return nil, ErrVersionMismatch
	}
	return &resp, nil
}

// Fail builds an error response.
func Fail(id uint64, code, msg string) *Response {
	return &Response{V: Version, ID: id, OK: false, Error: &Error{Code: code, Message: msg}}
}

// Succeed builds a success response with result marshalled from v.
func Succeed(id uint64, v any) (*Response, error) {
	var raw json.RawMessage
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return &Response{V: Version, ID: id, OK: true, Result: raw}, nil
}
