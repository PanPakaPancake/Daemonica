package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// Client calls the helper over a Unix socket. Each call uses its own short-lived
// connection, which keeps the client simple and isolates failures.
type Client struct {
	Socket  string
	Timeout time.Duration
	nextID  atomic.Uint64
}

// Call performs op with params and decodes the result into out (if non-nil).
// A helper-side failure is returned as *Error.
func (c *Client) Call(ctx context.Context, op, grant, sourceIP string, params, out any) error {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return &Error{Code: CodeUnavailable}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	var raw json.RawMessage
	if params != nil {
		if raw, err = json.Marshal(params); err != nil {
			return err
		}
	}
	id := c.nextID.Add(1)
	if err := WriteFrame(conn, Request{V: Version, ID: id, Op: op, Grant: grant, SourceIP: sourceIP, Params: raw}); err != nil {
		return &Error{Code: CodeUnavailable}
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		return &Error{Code: CodeUnavailable}
	}
	if resp.ID != id {
		return errors.New("rpc: response id mismatch")
	}
	if !resp.OK {
		if resp.Error == nil {
			return &Error{Code: CodeInternal}
		}
		return resp.Error
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

// ErrorCode extracts the stable code from err ("" if none).
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
