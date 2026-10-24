// Command daemonica-helper is the privileged helper (runs as root). It listens
// exclusively on Unix sockets: helper.sock for daemonica-web and admin.sock for
// the root-only daemonica-admin CLI (SPEC §3.2).
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
	"time"

	"github.com/PanPakaPancake/daemonica/internal/audit"
	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/services"
	"github.com/PanPakaPancake/daemonica/internal/sshkeys"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
	"github.com/PanPakaPancake/daemonica/internal/users"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

var version = "0.1.0-dev"

func main() {
	// Worker mode: re-executed by the helper with a Linux user's credentials
	// (SPEC §3.2 rule 6). Must run before any flag parsing or root checks.
	if len(os.Args) > 1 && os.Args[1] == worker.Arg {
		worker.Main(sshkeys.WorkerHandlers())
	}
	stateDir := flag.String("state-dir", "/var/lib/daemonica-helper", "helper state directory (root 0700)")
	runDir := flag.String("run-dir", "/run/daemonica", "runtime directory for sockets")
	auditPath := flag.String("audit-log", "/var/log/daemonica/audit.log", "audit log path")
	webUser := flag.String("web-user", "daemonica-web", "system user of the web process")
	tlsDir := flag.String("tls-dir", "/var/lib/daemonica/tls", "certificate directory of the web process")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Geteuid() != 0 {
		log.Error("daemonica-helper must run as root")
		os.Exit(1)
	}
	u, err := user.Lookup(*webUser)
	if err != nil {
		log.Error("web user not found", "user", *webUser)
		os.Exit(1)
	}
	webUID, _ := strconv.ParseUint(u.Uid, 10, 32)
	webGID, _ := strconv.Atoi(u.Gid)
	webUIDInt, _ := strconv.Atoi(u.Uid)

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
	// records can be found with `journalctl -t daemonica-helper`.
	auditLog := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	al.Mirror = func(line []byte) { auditLog.Info("audit", "record", string(line)) }

	pm, err := planner.New(filepath.Join(*stateDir, "journal"), planner.DefaultConfirmWindow)
	if err != nil {
		log.Error("planner init failed", "err", err)
		os.Exit(1)
	}
	// Plan→Apply→Confirm handlers (network/firewall follow with their modules).
	pm.Register(&helper.AllowlistHandler{Config: cfg})
	pm.OnEvent = func(ch planner.Change, event string, err error) {
		ev := audit.Event{Action: "change." + event, Target: "change:" + ch.ID, Result: audit.ResultOK,
			Actor: audit.Actor{AccountID: ch.Owner}, Params: map[string]string{"kind": ch.Kind, "risk": ch.Risk}}
		if err != nil {
			ev.Result, ev.Reason = audit.ResultError, "handler failed"
		}
		_, _ = al.Append(ev)
	}
	for _, e := range pm.Recover(context.Background()) {
		log.Error("rollback recovery failed", "err", e)
	}

	db, err := helper.OpenDB(context.Background(), filepath.Join(*stateDir, "accounts.db"))
	if err != nil {
		log.Error("cannot open accounts.db", "err", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	tokens := db.TokenStore()

	c := cfg.Get()
	grants := helper.NewGrantStore(time.Duration(c.IdleMinutes)*time.Minute, time.Duration(c.AbsHours)*time.Hour)
	if err := grants.WithPersistence(db, time.Now()); err != nil {
		log.Error("cannot load sessions", "err", err)
		os.Exit(1)
	}
	core := &helper.Core{Config: cfg, Tokens: tokens, Grants: grants, AuditPath: *auditPath, TLSDir: *tlsDir, Version: version}
	ops := map[string]*helper.Op{}
	core.Register(ops, al)
	authOps := &helper.AuthOps{DB: db, Config: cfg, Grants: grants, Tokens: tokens, Audit: al}
	authOps.Register(ops)
	certOps := &helper.CertOps{Config: cfg, Guard: authOps.SetupGuard, TLSDir: *tlsDir, StateDir: *stateDir, WebUID: webUIDInt, WebGID: webGID}
	certOps.Register(ops)
	(&helper.SettingsOps{Config: cfg, Planner: pm}).Register(ops)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// M1.1: system overview, processes, services (D-Bus), journal.
	sd, err := services.Connect()
	if err != nil {
		log.Error("cannot connect to systemd over D-Bus", "err", err)
		os.Exit(1)
	}
	defer func() { _ = sd.Close() }()
	collector := &sysinfo.Collector{FS: sysinfo.FS{Root: "/"}, Interval: 3 * time.Second, Extras: sysinfo.Extras{
		FailedUnits: sd.FailedCount,
		CertDays:    helper.CertDaysFrom(*tlsDir),
		Updates:     helper.UpdatesFromNotifier("/var/lib/update-notifier/updates-available"),
	}}
	go collector.Run(ctx)
	(&helper.SysOps{Collector: collector, SelfPID: os.Getpid()}).Register(ops)
	(&helper.ServiceOps{Systemd: sd}).Register(ops)
	(&helper.LogOps{}).Register(ops)

	// M1.2: SSH keys and Linux users/groups.
	keyOps := &helper.SSHKeyOps{Worker: &worker.Runner{Timeout: 30 * time.Second}, Lookup: worker.Lookup,
		Config: sshkeys.EffectiveConfig, HostKeyDir: "/etc/ssh"}
	keyOps.Register(ops)
	(&helper.UserOps{DB: users.DB{Root: "/"}, Accts: db, KeyCount: keyOps.Count}).Register(ops)

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
	log.Info("daemonica-helper started", "version", version)

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
