package rpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Streams (SPEC §3.2 rule 1: "large data via streams").
//
// A streaming operation starts like a normal call with one Request frame. The
// helper then answers with a first Response frame: an error ends the exchange,
// success ("ready") carries operation metadata. Data follows as chunks — a
// 4-byte big-endian length plus that many bytes, at most MaxChunk each — and
// a zero-length chunk marks the regular end. A stream that breaks off without
// the end marker is an abort. After the data the helper sends a final
// Response frame with the result. Data flows client→helper for uploads and
// helper→client for downloads; the connection is closed afterwards.

// MaxChunk is the largest data chunk on a stream.
const MaxChunk = 256 << 10

// ErrChunkTooLarge is returned for chunks above MaxChunk.
var ErrChunkTooLarge = errors.New("rpc: chunk exceeds maximum size")

// WriteChunk writes one data chunk. An empty p writes the end marker.
func WriteChunk(w io.Writer, p []byte) error {
	if len(p) > MaxChunk {
		return ErrChunkTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p))) //nolint:gosec // bounded by MaxChunk
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(p) == 0 {
		return nil
	}
	_, err := w.Write(p)
	return err
}

// ReadChunk reads one whole chunk. It returns (nil, io.EOF) at the end marker
// and io.ErrUnexpectedEOF if the stream breaks off.
func ReadChunk(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, io.EOF
	}
	if n > MaxChunk {
		return nil, ErrChunkTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}

// ChunkReader turns a chunked stream into a plain reader. It returns io.EOF
// only after the end marker; a stream that ends early yields io.ErrUnexpectedEOF.
type ChunkReader struct {
	R    io.Reader
	left uint32
	done bool
}

func (c *ChunkReader) Read(p []byte) (int, error) {
	for c.left == 0 {
		if c.done {
			return 0, io.EOF
		}
		var hdr [4]byte
		if _, err := io.ReadFull(c.R, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 {
			c.done = true
			return 0, io.EOF
		}
		if n > MaxChunk {
			return 0, ErrChunkTooLarge
		}
		c.left = n
	}
	if len(p) == 0 {
		return 0, nil
	}
	if uint32(len(p)) > c.left { //nolint:gosec // len is non-negative
		p = p[:c.left]
	}
	n, err := c.R.Read(p)
	c.left -= uint32(n) //nolint:gosec // n <= len(p) <= left
	if errors.Is(err, io.EOF) {
		if c.left > 0 {
			return n, io.ErrUnexpectedEOF
		}
		err = nil
	}
	return n, err
}

// Done reports whether the end marker has been read.
func (c *ChunkReader) Done() bool { return c.done }

// ChunkWriter splits writes into chunks; Close writes the end marker.
type ChunkWriter struct{ W io.Writer }

func (c ChunkWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), MaxChunk)
		if err := WriteChunk(c.W, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close writes the end marker (it does not close the underlying writer).
func (c ChunkWriter) Close() error { return WriteChunk(c.W, nil) }

// deadlineConn refreshes the connection deadline before every read or write,
// so a stream may run long as long as data keeps flowing.
type deadlineConn struct {
	c    net.Conn
	idle time.Duration
}

func (d deadlineConn) Read(p []byte) (int, error) {
	_ = d.c.SetReadDeadline(time.Now().Add(d.idle))
	return d.c.Read(p)
}

func (d deadlineConn) Write(p []byte) (int, error) {
	_ = d.c.SetWriteDeadline(time.Now().Add(d.idle))
	return d.c.Write(p)
}

// StreamIdle is the longest pause tolerated inside a stream.
const StreamIdle = 2 * time.Minute

// NewStreamConn wraps c with per-operation idle deadlines.
func NewStreamConn(c net.Conn) io.ReadWriter { return deadlineConn{c: c, idle: StreamIdle} }

func (c *Client) openStream(ctx context.Context, op, grant, sourceIP string, params any) (net.Conn, io.ReadWriter, uint64, *Response, error) {
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(dctx, "unix", c.Socket)
	if err != nil {
		return nil, nil, 0, nil, &Error{Code: CodeUnavailable}
	}
	// Cancel the request (client gone) by closing the connection.
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	var raw json.RawMessage
	if params != nil {
		if raw, err = json.Marshal(params); err != nil {
			_ = conn.Close()
			return nil, nil, 0, nil, err
		}
	}
	rw := NewStreamConn(conn)
	id := c.nextID.Add(1)
	if err := WriteFrame(rw, Request{V: Version, ID: id, Op: op, Grant: grant, SourceIP: sourceIP, Params: raw}); err != nil {
		_ = conn.Close()
		return nil, nil, 0, nil, &Error{Code: CodeUnavailable}
	}
	// The first answer may take a while (preflight, worker start-up).
	_ = conn.SetReadDeadline(time.Now().Add(c.timeout()))
	resp, err := ReadResponse(conn)
	if err != nil || resp.ID != id {
		_ = conn.Close()
		return nil, nil, 0, nil, &Error{Code: CodeUnavailable}
	}
	if !resp.OK {
		_ = conn.Close()
		if resp.Error == nil {
			return nil, nil, 0, nil, &Error{Code: CodeInternal}
		}
		return nil, nil, 0, nil, resp.Error
	}
	return conn, rw, id, resp, nil
}

func (c *Client) timeout() time.Duration {
	if c.Timeout == 0 {
		return 60 * time.Second
	}
	return c.Timeout
}

func finalResponse(conn net.Conn, id uint64, wait time.Duration, out any) error {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	resp, err := ReadResponse(conn)
	if err != nil || resp.ID != id {
		return &Error{Code: CodeUnavailable}
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

// Upload runs a streaming upload operation: body is sent as chunks after the
// helper signalled readiness; the final result is decoded into out. If body
// fails (client aborted), the stream is broken off and the helper discards
// the partial data. ready (optional) receives the metadata of the ready frame.
func (c *Client) Upload(ctx context.Context, op, grant, sourceIP string, params any, body io.Reader, ready, out any) error {
	conn, rw, id, resp, err := c.openStream(ctx, op, grant, sourceIP, params)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if ready != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, ready); err != nil {
			return err
		}
	}
	buf := make([]byte, MaxChunk)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if werr := WriteChunk(rw, buf[:n]); werr != nil {
				// The helper stopped reading (limit, disk full, …): fetch its verdict.
				if ferr := finalResponse(conn, id, 5*time.Second, nil); ferr != nil {
					return ferr
				}
				return &Error{Code: CodeUnavailable}
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr // connection closes without end marker → helper aborts
		}
	}
	if err := WriteChunk(rw, nil); err != nil {
		return &Error{Code: CodeUnavailable}
	}
	return finalResponse(conn, id, c.timeout(), out)
}

// DownloadStream is the data part of a streaming download.
type DownloadStream struct {
	conn net.Conn
	id   uint64
	r    *ChunkReader
	wait time.Duration
}

// Read reads data; io.EOF after the end marker.
func (d *DownloadStream) Read(p []byte) (int, error) { return d.r.Read(p) }

// Finish must be called after Read returned io.EOF: it reads the final status.
func (d *DownloadStream) Finish(out any) error {
	if !d.r.Done() {
		return &Error{Code: CodeInternal}
	}
	return finalResponse(d.conn, d.id, d.wait, out)
}

// Close releases the connection (aborting the download if still running).
func (d *DownloadStream) Close() error { return d.conn.Close() }

// Download starts a streaming download. meta receives the ready metadata.
func (c *Client) Download(ctx context.Context, op, grant, sourceIP string, params, meta any) (*DownloadStream, error) {
	conn, rw, id, resp, err := c.openStream(ctx, op, grant, sourceIP, params)
	if err != nil {
		return nil, err
	}
	if meta != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, meta); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return &DownloadStream{conn: conn, id: id, r: &ChunkReader{R: rw}, wait: c.timeout()}, nil
}
