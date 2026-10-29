// Command daemonica-web is the unprivileged HTTPS front end. It terminates TLS
// itself, enforces the network allowlist at accept time and talks to the
// helper exclusively over /run/daemonica/helper.sock (SPEC §3.2, §3.6).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/netallow"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/tlsconf"
	"github.com/PanPakaPancake/daemonica/internal/web"
	"github.com/PanPakaPancake/daemonica/internal/web/ui"
)

func main() {
	sock := flag.String("helper-socket", "/run/daemonica/helper.sock", "helper socket")
	tlsDir := flag.String("tls-dir", "/var/lib/daemonica/tls", "directory with fullchain.pem and privkey.pem")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Geteuid() == 0 {
		log.Error("daemonica-web must not run as root")
		os.Exit(1)
	}
	client := &rpc.Client{Socket: *sock, Timeout: 5 * time.Minute}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	cfg, err := fetchConfig(ctx, client, log)
	if err != nil {
		log.Error("helper not reachable", "err", err)
		os.Exit(1)
	}

	holder := &tlsconf.Holder{}
	var listenAddr string
	var origins []string
	var allow *netallow.Allowlist
	portStr := strconv.Itoa(cfg.Port)
	cert, certErr := tls.LoadX509KeyPair(filepath.Join(*tlsDir, "fullchain.pem"), filepath.Join(*tlsDir, "privkey.pem"))
	domainMode := cfg.Domain != "" && certErr == nil
	switch {
	case domainMode:
		// Final domain with a real certificate. During setup only the token-gated
		// setup endpoints work here (needed to register the first passkey on the
		// final RP ID, SPEC §3.3 Bootstrap 3).
		holder.Set(&cert)
		pfx, err := netallow.ParseList(cfg.Allowlist)
		if err != nil {
			log.Error("invalid allowlist in config")
			os.Exit(1)
		}
		allow = netallow.New(pfx)
		listenAddr = net.JoinHostPort("", portStr)
		origins = []string{"https://" + net.JoinHostPort(cfg.Domain, portStr)}
		if cfg.Port == 443 {
			origins = append(origins, "https://"+cfg.Domain)
		}
		log.Info("listening for domain", "domain", cfg.Domain, "addr", listenAddr, "setup_done", cfg.SetupDone)
	case cfg.SetupDone:
		log.Error("setup is complete but no usable TLS certificate exists; see 'daemonica-admin tls-status'", "err", certErr)
		os.Exit(1)
	default:
		// Setup mode: loopback only, ephemeral self-signed certificate (§3.3 Bootstrap 1).
		sc, err := tlsconf.SelfSignedSetup([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, 24*time.Hour)
		if err != nil {
			log.Error("cannot create setup certificate", "err", err)
			os.Exit(1)
		}
		holder.Set(sc)
		listenAddr = net.JoinHostPort("127.0.0.1", portStr)
		allow = netallow.New(netallow.Loopback)
		origins = []string{"https://localhost:" + portStr, "https://127.0.0.1:" + portStr}
		log.Info("setup mode: listening on loopback only", "addr", listenAddr)
	}

	// Watch the helper-owned configuration: allowlist changes apply live; a
	// changed domain, port or setup phase restarts the process; a new
	// certificate is swapped in (reloadCert)
	// (exit 75 → systemd Restart=on-failure) so listener and origins are rebuilt.
	kick := make(chan struct{}, 1)
	go watchConfig(ctx, client, log, cfg, allow, domainMode, kick, func() error { return reloadCert(holder, *tlsDir) })

	srv := &web.Server{
		Helper:   client,
		Log:      log,
		UI:       ui.FS(),
		Origins:  func() []string { return origins },
		Limiter:  web.NewRateLimiter(0.5, 10, 10, 100),
		Sessions: web.NewSessions(),
		Allow:    allow,
		// Settings changes reload the allowlist at once instead of at the next poll.
		ReloadConfig: func() {
			select {
			case kick <- struct{}{}:
			default:
			}
		},
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         tlsconf.Config(holder),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ConnContext:       web.ConnAccepted,
	}

	inner, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Error("cannot listen", "addr", listenAddr, "err", err)
		os.Exit(1)
	}
	ln := tls.NewListener(&netallow.Listener{Listener: inner, Allow: allow}, httpSrv.TLSConfig)

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()
	log.Info("daemonica-web started", "addr", listenAddr, "setup_mode", !cfg.SetupDone)
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func fetchConfig(ctx context.Context, c *rpc.Client, log *slog.Logger) (helper.WebConfig, error) {
	var cfg helper.WebConfig
	var err error
	for i := 0; i < 30; i++ {
		if err = c.Call(ctx, "config.web", "", "", nil, &cfg); err == nil {
			return cfg, nil
		}
		log.Warn("waiting for helper", "attempt", i+1)
		select {
		case <-ctx.Done():
			return cfg, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return cfg, fmt.Errorf("config.web: %w", err)
}

// ExitRestart asks systemd to restart the service (Restart=on-failure).
const ExitRestart = 75

// reloadCert swaps in a new certificate (ACME renewal, change in the
// settings) without restarting: sessions live in this process.
func reloadCert(h *tlsconf.Holder, dir string) error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return err
	}
	h.Set(&cert)
	return nil
}

func watchConfig(ctx context.Context, c *rpc.Client, log *slog.Logger, start helper.WebConfig, allow *netallow.Allowlist, domainMode bool,
	kick <-chan struct{}, reload func() error) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
		var cur helper.WebConfig
		if err := c.Call(ctx, "config.web", "", "", nil, &cur); err != nil {
			continue
		}
		wantDomainMode := cur.Domain != "" && cur.CertVersion != 0
		// In loopback setup mode only switching to domain mode matters; restarting
		// on every wizard step would abort in-flight requests (e.g. ACME issuance).
		changed := wantDomainMode != domainMode
		if domainMode && (cur.Domain != start.Domain || cur.Port != start.Port) {
			changed = true
		}
		if domainMode && !changed && cur.CertVersion != start.CertVersion {
			if err := reload(); err != nil {
				// Key and chain are written one after the other: retry at the next poll.
				log.Warn("cannot load the new certificate yet", "err", err)
			} else {
				start.CertVersion = cur.CertVersion
				log.Info("certificate reloaded")
			}
		}
		if changed {
			log.Info("listener configuration changed; restarting")
			os.Exit(ExitRestart)
		}
		if domainMode && strings.Join(cur.Allowlist, ",") != strings.Join(start.Allowlist, ",") {
			if pfx, err := netallow.ParseList(cur.Allowlist); err == nil {
				allow.Set(pfx)
				start.Allowlist = cur.Allowlist
				log.Info("allowlist updated", "entries", len(pfx))
			}
		}
	}
}
