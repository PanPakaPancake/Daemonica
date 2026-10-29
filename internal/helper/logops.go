package helper

import (
	"context"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

// LogOps exposes journald queries (SPEC §7.2 "Logs"). Read-only accounts are
// denied by policy (Annex A: logs are Admin/Operator only).
type LogOps struct {
	// Run is replaceable in tests.
	Run func(ctx context.Context, q journal.Query) (journal.Result, error)
	// Root prefixes the allowlisted log files (tests).
	Root string
}

// Register installs journal.* operations.
func (l *LogOps) Register(ops map[string]*Op) {
	run := l.Run
	if run == nil {
		run = journal.Run
	}
	Register(ops, &Op{Name: "journal.query", Action: policy.ActLogsRead, NoAudit: true, Timeout: 30 * time.Second,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var q journal.Query
			if err := decode(c, &q); err != nil {
				return nil, err
			}
			if _, err := q.Args(); err != nil {
				return nil, Errf(rpc.CodeValidation, "%s", err.Error())
			}
			res, err := run(ctx, q)
			if err != nil {
				return nil, Errf(rpc.CodeUnavailable, "journal query failed")
			}
			if res.Entries == nil {
				res.Entries = []journal.Entry{}
			}
			return res, nil
		}})

	// Classic log files from a fixed allowlist (SPEC §7.2 SOLL).
	Register(ops, &Op{Name: "logs.files", Action: policy.ActLogsRead, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) { return journal.ListFiles(l.Root), nil }})
	Register(ops, &Op{Name: "logs.file", Action: policy.ActLogsRead, NoAudit: true, Timeout: 30 * time.Second,
		Handle: func(_ context.Context, c Call) (any, error) {
			var q journal.FileQuery
			if err := decode(c, &q); err != nil {
				return nil, err
			}
			res, err := journal.ReadFile(l.Root, q)
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "%s", err.Error())
			}
			return res, nil
		}})
}
