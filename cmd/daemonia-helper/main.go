// Command daemonia-helper is the privileged helper (runs as root). It listens
// exclusively on Unix sockets: helper.sock for daemonia-web and admin.sock for
// the root-only daemonia-admin CLI (SPEC §3.2).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/planner"
)

var version = "0.1.0-dev"

func main() {
	stateDir := flag.String("state-dir", "/var/lib/daemonia-helper", "helper state directory (root 0700)")
	runDir := flag.String("run-dir", "/run/daemonia", "runtime directory for sockets")
	auditPath := flag.String("audit-log", "/var/log/daemonia/audit.log", "audit log path")
	webUser := flag.String("web-user", "daemonia-web", "system user of the web process")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Geteuid() != 0 {
		log.Error("daemonia-helper must run as root")
		os.Exit(1)
	}
	u, err := user.Lookup(*webUser)
	if err != nil {
		log.Error("web user not found", "user", *webUser)
		os.Exit(1)
	}
	webUID, _ := strconv.ParseUint(u.Uid, 10, 32)
	webGID, _ := strconv.Atoi(u.Gid)

	for _, d := range []string{*stateDir, filepath.Join(*stateDir, "backups"), filepath.Join(*stateDir, "journal")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			log.Error("cannot create state dir", "dir", d, "err", err)
			os.Exit(1)
		}
	}

	cfg, err := helper.OpenConfig(filepath.Join(*stateDir, "config.json"))
	if err != nil {
		log.Error("cannot load config", "err", err)
		os.Exit(1)
	}
	al, err := audit.Open(*auditPath, "")
	if err != nil {
		log.Error("cannot open audit log", "err", err)
		os.Exit(1)
	}
	defer func() { _ = al.Close() }()
	// Mirror audit records to the journal; the unit sets SyslogIdentifier so
	// records can be found with `journalctl -t daemonia-helper`.
	auditLog := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	al.Mirror = func(line []byte) { auditLog.Info("audit", "record", string(line)) }

	pm, err := planner.New(filepath.Join(*stateDir, "journal"), planner.DefaultConfirmWindow)
	if err != nil {
		log.Error("planner init failed", "err", err)
		os.Exit(1)
	}
	// Handlers for network/firewall/allowlist are registered here as modules land.
	for _, e := range pm.Recover(context.Background()) {
		log.Error("rollback recovery failed", "err", e)
	}

	grants := helper.NewGrantStore(0, 0)
	core := &helper.Core{Config: cfg, Tokens: auth.NewMemTokenStore(), Grants: grants, AuditPath: *auditPath, Version: version}
	ops := map[string]*helper.Op{}
	core.Register(ops, al)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// systemd creates RuntimeDirectory as root:root; the web user needs to
	// traverse it to reach helper.sock (admin.sock stays 0600 root).
	if err := os.MkdirAll(*runDir, 0o750); err == nil {
		_ = os.Chown(*runDir, 0, webGID)
		_ = os.Chmod(*runDir, 0o750)
	}
	webL, err := helper.ListenUnix(filepath.Join(*runDir, "helper.sock"), 0o660, webGID)
	if err != nil {
		log.Error("cannot listen on helper.sock", "err", err)
		os.Exit(1)
	}
	adminL, err := helper.ListenUnix(filepath.Join(*runDir, "admin.sock"), 0o600, 0)
	if err != nil {
		log.Error("cannot listen on admin.sock", "err", err)
		os.Exit(1)
	}

	webSrv := &helper.Server{Channel: helper.ChannelWeb, AllowedUID: uint32(webUID), Ops: ops, Grants: grants, Audit: al, Log: log}
	adminSrv := &helper.Server{Channel: helper.ChannelAdmin, AllowedUID: 0, Ops: ops, Grants: grants, Audit: al, Log: log}

	_, _ = al.Append(audit.Event{Action: "helper.start", Result: audit.ResultOK, Params: map[string]string{"version": version}})
	log.Info("daemonia-helper started", "version", version)

	errc := make(chan error, 2)
	go func() { errc <- webSrv.Serve(ctx, webL) }()
	go func() { errc <- adminSrv.Serve(ctx, adminL) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			log.Error("listener failed", "err", err)
		}
	}
	_, _ = al.Append(audit.Event{Action: "helper.stop", Result: audit.ResultOK})
}
