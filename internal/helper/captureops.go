package helper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/capture"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// CaptureOps exposes packet captures (SPEC §7.6 M1.5d). Admin only (policy);
// every start needs a fresh step-up, downloads use a one-time token.
type CaptureOps struct {
	M      *capture.Manager
	Config *ConfigStore
	Run    netcfg.Runner
	// Ifaces lists the kernel's interface names.
	Ifaces func() ([]string, error)
	Now    func() time.Time

	mu     sync.Mutex
	tokens map[string]capToken
}

type capToken struct {
	id      string
	session string
	expires time.Time
}

// CaptureTokenTTL is how long a download link is valid.
const CaptureTokenTTL = 60 * time.Second

func (o *CaptureOps) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *CaptureOps) available() bool { _, err := os.Stat(capture.Tcpdump); return err == nil }

// Retention is the configured capture retention.
func (o *CaptureOps) Retention() time.Duration {
	h := o.Config.Get().CaptureRetentionHours
	if h <= 0 {
		return capture.DefaultRetention
	}
	return time.Duration(h) * time.Hour
}

// Janitor prunes old captures every interval until ctx ends.
func (o *CaptureOps) Janitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		o.M.Prune(o.Retention(), capture.DefaultTotal)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// CaptureStatus is the capture.status result.
type CaptureStatus struct {
	Available      bool           `json:"available"`
	Installable    bool           `json:"installable"`
	Ifaces         []string       `json:"ifaces"`
	DashboardPort  int            `json:"dashboard_port"`
	Current        *capture.Live  `json:"current,omitempty"`
	Captures       []capture.Meta `json:"captures"`
	RetentionHours int            `json:"retention_hours"`
	TotalBytes     int64          `json:"total_bytes"`
	TotalLimit     int64          `json:"total_limit"`
}

type captureIDParams struct {
	ID string `json:"id"`
}

type captureLinesParams struct {
	ID    string `json:"id"`
	After string `json:"after,omitempty"`
	Lines int    `json:"lines,omitempty"`
}

func capErr(err error) error {
	var ve *capture.ErrValidation
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ve):
		return Errf(rpc.CodeValidation, "%s", ve.Msg)
	case errors.Is(err, capture.ErrBusy):
		return Errf(rpc.CodeConflict, "a capture is running")
	case errors.Is(err, capture.ErrNotFound):
		return Errf(rpc.CodeNotFound, "")
	case errors.Is(err, capture.ErrLowDisk):
		return Errf(rpc.CodeUnavailable, "less than 10 %% free disk space")
	}
	return err
}

func (o *CaptureOps) status() (CaptureStatus, error) {
	list, err := o.M.List()
	if err != nil {
		return CaptureStatus{}, err
	}
	ifaces, _ := o.Ifaces()
	_, aptErr := os.Stat("/usr/bin/apt-get")
	st := CaptureStatus{Available: o.available(), Ifaces: ifaces, DashboardPort: o.Config.Get().Port, Current: o.M.Current(), Captures: list,
		RetentionHours: int(o.Retention() / time.Hour), TotalLimit: capture.DefaultTotal}
	st.Installable = !st.Available && aptErr == nil
	if st.Ifaces == nil {
		st.Ifaces = []string{}
	}
	for _, c := range list {
		st.TotalBytes += c.Bytes
	}
	return st, nil
}

func (o *CaptureOps) start(ctx context.Context, c Call) (any, error) {
	var s capture.Spec
	if err := decode(c, &s); err != nil {
		return nil, err
	}
	s.DashboardPort = o.Config.Get().Port
	s, err := s.Normalize()
	if err != nil {
		return nil, capErr(err)
	}
	ifaces, err := o.Ifaces()
	if err != nil || !slices.Contains(ifaces, s.Iface) {
		return nil, Errf(rpc.CodeValidation, "unknown interface")
	}
	if !o.available() {
		return nil, Errf(rpc.CodeNotSupported, "tcpdump is not installed")
	}
	// Syntax check: compile the filter without capturing.
	res, err := o.Run(ctx, 15*time.Second, capture.Tcpdump, s.CompileArgs()...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, Errf(rpc.CodeValidation, "the filter expression does not compile")
	}
	c.AuditKV["iface"] = s.Iface
	c.AuditKV["filter"] = s.Filter()
	c.AuditKV["limits"] = strconv.Itoa(s.DurationSec) + "s/" + strconv.Itoa(s.Packets) + "p/" + strconv.FormatInt(s.SizeBytes>>20, 10) + "MiB"
	c.AuditKV["snaplen"] = strconv.Itoa(s.Snaplen())
	if s.Promisc {
		c.AuditKV["promisc"] = "yes"
	}
	meta, err := o.M.Start(ctx, s, c.Subject.AccountID)
	if err != nil {
		return nil, capErr(err)
	}
	return meta, nil
}

func (o *CaptureOps) issueToken(c Call, id string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(tok))
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.tokens == nil {
		o.tokens = map[string]capToken{}
	}
	for k, t := range o.tokens {
		if o.now().After(t.expires) {
			delete(o.tokens, k)
		}
	}
	o.tokens[hex.EncodeToString(sum[:])] = capToken{id: id, session: c.SessionKey, expires: o.now().Add(CaptureTokenTTL)}
	return tok
}

func (o *CaptureOps) takeToken(c Call, tok string) (string, bool) {
	sum := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(sum[:])
	o.mu.Lock()
	defer o.mu.Unlock()
	t, ok := o.tokens[key]
	delete(o.tokens, key) // one-time
	return t.id, ok && t.session == c.SessionKey && o.now().Before(t.expires)
}

func idTarget(c Call) string {
	var p captureIDParams
	_ = decode(c, &p)
	if capture.ValidID(p.ID) {
		return "capture:" + p.ID
	}
	return ""
}

// Register installs capture.* operations.
func (o *CaptureOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "capture.status", Action: policy.ActCaptureManage, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) { return o.status() }})

	Register(ops, &Op{Name: "capture.start", Action: policy.ActCaptureStart, Timeout: time.Minute, Handle: o.start})

	Register(ops, &Op{Name: "capture.stop", Action: policy.ActCaptureManage, Timeout: 30 * time.Second, AuditTarget: idTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p captureIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			return map[string]bool{"stopped": true}, capErr(o.M.Stop(p.ID))
		}})

	Register(ops, &Op{Name: "capture.lines", Action: policy.ActCaptureManage, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p captureLinesParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			l, err := o.M.Lines(p.ID, p.After, p.Lines)
			return l, capErr(err)
		}})

	Register(ops, &Op{Name: "capture.delete", Action: policy.ActCaptureManage, AuditTarget: idTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p captureIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			return map[string]bool{"deleted": true}, capErr(o.M.Delete(p.ID))
		}})

	Register(ops, &Op{Name: "capture.delete_all", Action: policy.ActCaptureManage,
		Handle: func(_ context.Context, c Call) (any, error) {
			n := o.M.DeleteAll()
			c.AuditKV["count"] = strconv.Itoa(n)
			return map[string]int{"deleted": n}, nil
		}})

	Register(ops, &Op{Name: "capture.settings", Action: policy.ActCaptureManage,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p struct {
				RetentionHours int `json:"retention_hours"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if p.RetentionHours < 1 || p.RetentionHours > 7*24 {
				return nil, Errf(rpc.CodeValidation, "retention must be 1 to 168 hours")
			}
			if _, err := o.Config.Update(func(cf *Config) error { cf.CaptureRetentionHours = p.RetentionHours; return nil }); err != nil {
				return nil, err
			}
			c.AuditKV["retention_hours"] = strconv.Itoa(p.RetentionHours)
			o.M.Prune(o.Retention(), capture.DefaultTotal)
			return map[string]int{"retention_hours": p.RetentionHours}, nil
		}})

	Register(ops, &Op{Name: "capture.download_token", Action: policy.ActCaptureDownload, AuditTarget: idTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p captureIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			m, err := o.M.Get(p.ID)
			if err != nil {
				return nil, capErr(err)
			}
			if m.State == "running" {
				return nil, Errf(rpc.CodeConflict, "the capture is still running")
			}
			return map[string]any{"token": o.issueToken(c, p.ID), "expires_in": int(CaptureTokenTTL / time.Second)}, nil
		}})

	Register(ops, &Op{Name: "capture.download", Action: policy.ActCaptureManage, Timeout: 2 * time.Hour,
		Stream: func(_ context.Context, c Call, st *Stream) (any, error) {
			var p struct {
				Token string `json:"token"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			id, ok := o.takeToken(c, p.Token)
			if !ok {
				return nil, Errf(rpc.CodeTokenInvalid, "")
			}
			f, meta, err := o.M.Open(id)
			if err != nil {
				return nil, capErr(err)
			}
			defer func() { _ = f.Close() }()
			fi, err := f.Stat()
			if err != nil {
				return nil, err
			}
			c.AuditKV["capture"] = id
			name := "capture-" + meta.Iface + "-" + meta.Started.UTC().Format("20060102-150405") + ".pcap"
			if err := st.Ready(map[string]any{"name": strings.ReplaceAll(name, "/", "_"), "size": fi.Size(), "mtime": fi.ModTime(), "length": fi.Size()}); err != nil {
				return nil, err
			}
			w := st.Writer()
			n, err := io.Copy(w, f)
			c.AuditKV["bytes"] = strconv.FormatInt(n, 10)
			if err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return map[string]int64{"bytes": n}, nil
		}})

	Register(ops, &Op{Name: "capture.install", Action: policy.ActCaptureStart, Timeout: 115 * time.Second,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			if o.available() {
				return nil, Errf(rpc.CodeConflict, "tcpdump is already installed")
			}
			res, err := o.Run(ctx, 110*time.Second, "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", "tcpdump")
			if err != nil {
				return nil, err
			}
			if res.ExitCode != 0 {
				msg := strings.TrimSpace(string(res.Stderr))
				if len(msg) > 400 {
					msg = msg[len(msg)-400:]
				}
				return nil, Errf(rpc.CodeInternal, "apt-get failed: %s", msg)
			}
			return map[string]bool{"installed": true}, nil
		}})
}
