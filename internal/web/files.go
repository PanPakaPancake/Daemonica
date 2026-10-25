package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// maxEditBytes mirrors files.MaxEditBytes (the files package is helper-only).
const maxEditBytes = 5 << 20

// ParamsHeader carries the JSON parameters of streaming PUT requests, whose
// body is the raw data.
const ParamsHeader = "X-Daemonica-Params"

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// registerFileRoutes installs the file manager API (SPEC §7.4).
func (s *Server) registerFileRoutes(mux *http.ServeMux) {
	sess := func(op string) http.Handler { return s.forward(endpoint{op: op, session: true}) }
	for _, op := range []string{"list", "stat", "create", "rename", "transfer", "delete", "chmod", "chown", "download_token", "versions"} {
		mux.Handle("POST /api/v1/files/"+op, sess("fs."+op))
	}
	mux.Handle("GET /api/v1/files/info", sess("fs.info"))
	mux.Handle("POST /api/v1/files/root/enable", sess("fs.root_enable"))
	mux.Handle("POST /api/v1/files/root/disable", sess("fs.root_disable"))
	mux.Handle("POST /api/v1/files/content/read", LimitBody(16<<10, s.fileRead("fs.read")))
	mux.Handle("POST /api/v1/files/versions/read", LimitBody(16<<10, s.fileRead("fs.version_read")))
	mux.Handle("PUT /api/v1/files/content", http.HandlerFunc(s.fileWrite))
	mux.Handle("PUT /api/v1/files/upload", http.HandlerFunc(s.fileUpload))
	mux.Handle("GET /api/v1/files/download/{token}", http.HandlerFunc(s.fileDownload))
}

// rpcFail writes the problem response for a helper error.
func (s *Server) rpcFail(w http.ResponseWriter, r *http.Request, err error) {
	code := rpc.ErrorCode(err)
	if code == "" {
		code = rpc.CodeInternal
	}
	if code == rpc.CodeUnauthorized {
		s.Sessions.Destroy(w, r)
	}
	Problem(w, r, httpStatus(code), code)
}

// headerParams reads the JSON parameters of a streaming request.
func headerParams(r *http.Request) (json.RawMessage, bool) {
	v := r.Header.Get(ParamsHeader)
	if len(v) == 0 || len(v) > 8<<10 || !json.Valid([]byte(v)) {
		return nil, false
	}
	return json.RawMessage(v), true
}

// fileRead returns a text file (or a stored previous version) for the editor
// as JSON (metadata + content).
func (s *Server) fileRead(op string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.fileReadOp(w, r, op) })
}

func (s *Server) fileReadOp(w http.ResponseWriter, r *http.Request, op string) {
	grant := s.Sessions.Grant(r)
	if grant == "" {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	params, err := readParams(r)
	if err != nil || params == nil {
		Problem(w, r, http.StatusBadRequest, "bad_request")
		return
	}
	meta := map[string]any{}
	ds, err := s.Helper.Download(r.Context(), op, grant, clientIP(r).String(), params, &meta)
	if err != nil {
		s.rpcFail(w, r, err)
		return
	}
	defer func() { _ = ds.Close() }()
	data, err := io.ReadAll(io.LimitReader(ds, maxEditBytes+1))
	if err != nil || len(data) > maxEditBytes {
		Problem(w, r, http.StatusBadGateway, "internal_error")
		return
	}
	if err := ds.Finish(nil); err != nil {
		s.rpcFail(w, r, err)
		return
	}
	if b, _ := meta["binary"].(bool); !b {
		if t, _ := meta["too_large"].(bool); !t {
			meta["content"] = string(data)
		}
	}
	writeJSON(w, http.StatusOK, meta)
}

// deadlineBody extends the read deadline while an upload keeps flowing.
type deadlineBody struct {
	r  io.Reader
	rc *http.ResponseController
}

func (d deadlineBody) Read(p []byte) (int, error) {
	_ = d.rc.SetReadDeadline(time.Now().Add(rpc.StreamIdle))
	return d.r.Read(p)
}

func (s *Server) streamIn(w http.ResponseWriter, r *http.Request, op string, limit int64) {
	grant := s.Sessions.Grant(r)
	if grant == "" {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	params, ok := headerParams(r)
	if !ok {
		Problem(w, r, http.StatusBadRequest, "bad_request")
		return
	}
	rc := http.NewResponseController(w)
	var body io.Reader = r.Body
	if limit > 0 {
		body = http.MaxBytesReader(w, r.Body, limit)
	}
	var out json.RawMessage
	err := s.Helper.Upload(r.Context(), op, grant, clientIP(r).String(), params, deadlineBody{r: body, rc: rc}, nil, &out)
	_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			Problem(w, r, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		if rpc.ErrorCode(err) == "" {
			// The browser aborted the upload; the helper discarded the data.
			Problem(w, r, http.StatusBadRequest, "aborted")
			return
		}
		s.rpcFail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// fileWrite saves editor content (raw body, parameters in ParamsHeader).
func (s *Server) fileWrite(w http.ResponseWriter, r *http.Request) {
	s.streamIn(w, r, "fs.write", maxEditBytes+1)
}

// fileUpload streams an upload to the helper without buffering it here; the
// helper enforces the configured size limit.
func (s *Server) fileUpload(w http.ResponseWriter, r *http.Request) {
	s.streamIn(w, r, "fs.upload", 0)
}

// parseRange accepts a single "bytes=start-" or "bytes=start-end" range.
func parseRange(h string) (offset, length int64, ok bool) {
	spec, found := strings.CutPrefix(h, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false
	}
	a, b, found := strings.Cut(spec, "-")
	if !found || a == "" {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(a, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	if b == "" {
		return start, 0, true
	}
	end, err := strconv.ParseInt(b, 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	return start, end - start + 1, true
}

// contentDisposition always forces a download (SPEC §3.5) and encodes the
// name per RFC 6266/5987 with an ASCII fallback.
func contentDisposition(name string) string {
	var fb strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' || r == '/' || r == ';' {
			fb.WriteByte('_')
		} else {
			fb.WriteRune(r)
		}
	}
	enc := strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
	return `attachment; filename="` + fb.String() + `"; filename*=UTF-8''` + enc
}

type deadlineWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (d deadlineWriter) Write(p []byte) (int, error) {
	_ = d.rc.SetWriteDeadline(time.Now().Add(rpc.StreamIdle))
	return d.w.Write(p)
}

// captureDownload streams a packet capture for a one-time token (M1.5d).
func (s *Server) captureDownload(w http.ResponseWriter, r *http.Request) {
	grant := s.Sessions.Grant(r)
	if grant == "" {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	tok := r.PathValue("token")
	if !tokenRE.MatchString(tok) {
		Problem(w, r, http.StatusUnauthorized, "token_invalid")
		return
	}
	var meta struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	ds, err := s.Helper.Download(r.Context(), "capture.download", grant, clientIP(r).String(), map[string]string{"token": tok}, &meta)
	if err != nil {
		s.rpcFail(w, r, err)
		return
	}
	defer func() { _ = ds.Close() }()
	h := w.Header()
	h.Set("Content-Type", "application/vnd.tcpdump.pcap")
	h.Set("Content-Disposition", contentDisposition(meta.Name))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if _, err := io.Copy(deadlineWriter{w: w, rc: rc}, ds); err != nil {
		s.Log.Warn("capture download interrupted", "err", err)
		return
	}
	if err := ds.Finish(nil); err != nil {
		s.Log.Warn("capture download finished with error", "code", rpc.ErrorCode(err))
	}
}

// fileDownload streams a file for a one-time download token.
func (s *Server) fileDownload(w http.ResponseWriter, r *http.Request) {
	grant := s.Sessions.Grant(r)
	if grant == "" {
		Problem(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	tok := r.PathValue("token")
	if !tokenRE.MatchString(tok) {
		Problem(w, r, http.StatusUnauthorized, "token_invalid")
		return
	}
	params := map[string]any{"token": tok}
	off, length, partial := parseRange(r.Header.Get("Range"))
	if partial {
		params["offset"], params["length"] = off, length
	}
	var meta struct {
		Name   string    `json:"name"`
		Size   int64     `json:"size"`
		MTime  time.Time `json:"mtime"`
		Offset int64     `json:"offset"`
		Length int64     `json:"length"`
	}
	ds, err := s.Helper.Download(r.Context(), "fs.download", grant, clientIP(r).String(), params, &meta)
	if err != nil {
		if rpc.ErrorCode(err) == "range_not_satisfiable" {
			w.Header().Set("Content-Range", "bytes */*")
			Problem(w, r, http.StatusRequestedRangeNotSatisfiable, "range_not_satisfiable")
			return
		}
		s.rpcFail(w, r, err)
		return
	}
	defer func() { _ = ds.Close() }()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(meta.Name))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Accept-Ranges", "bytes")
	h.Set("Content-Length", strconv.FormatInt(meta.Length, 10))
	if !meta.MTime.IsZero() {
		h.Set("Last-Modified", meta.MTime.UTC().Format(http.TimeFormat))
	}
	status := http.StatusOK
	if partial && meta.Length > 0 {
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(meta.Offset, 10)+"-"+
			strconv.FormatInt(meta.Offset+meta.Length-1, 10)+"/"+strconv.FormatInt(meta.Size, 10))
	}
	w.WriteHeader(status)
	rc := http.NewResponseController(w)
	if _, err := io.Copy(deadlineWriter{w: w, rc: rc}, ds); err != nil {
		s.Log.Warn("download interrupted", "err", err)
		return
	}
	if err := ds.Finish(nil); err != nil {
		s.Log.Warn("download finished with error", "code", rpc.ErrorCode(err))
	}
}
