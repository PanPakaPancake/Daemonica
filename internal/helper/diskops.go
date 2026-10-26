package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/disks"
	"github.com/PanPakaPancake/daemonica/internal/journal"
	"github.com/PanPakaPancake/daemonica/internal/netcfg"
	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

// KindFstab is the planner kind for fstab changes.
const KindFstab = "fstab"

// Error codes of the disk operations.
const (
	CodeProtectedMount = "protected_mount"
)

// Mounter starts and stops mount units (disks.Systemd in production).
type Mounter interface {
	Reload(ctx context.Context) error
	Unit(ctx context.Context, unit string, start bool) error
}

type fstabPayload struct {
	Old    string `json:"old"`
	New    string `json:"new"`
	Backup string `json:"backup"`
}

// FstabHandler applies fstab changes: backup, atomic replace, daemon-reload;
// rollback restores the old text. Nothing is mounted or unmounted.
type FstabHandler struct {
	Path   string
	Reload func(ctx context.Context) error
}

// Kind implements planner.Handler.
func (h *FstabHandler) Kind() string { return KindFstab }

func writeFstab(path, text string) error {
	tmp := path + ".daemonica-tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil { //nolint:gosec // fstab is world-readable
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Apply implements planner.Handler.
func (h *FstabHandler) Apply(ctx context.Context, payload json.RawMessage) error {
	var p fstabPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	cur, err := os.ReadFile(h.Path)
	if err != nil {
		return err
	}
	if string(cur) != p.Old {
		return errors.New("fstab changed since the plan")
	}
	if err := os.WriteFile(p.Backup, cur, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(p.Backup, 0o644); err != nil { //nolint:gosec // copy of a world-readable file
		return err
	}
	if err := writeFstab(h.Path, p.New); err != nil {
		return err
	}
	return h.Reload(ctx)
}

// Rollback implements planner.Handler.
func (h *FstabHandler) Rollback(ctx context.Context, payload json.RawMessage) error {
	var p fstabPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	if err := writeFstab(h.Path, p.Old); err != nil {
		return err
	}
	return h.Reload(ctx)
}

// DiskOps exposes block devices, mounts and fstab (SPEC §7.8). Reading is
// open to all roles; mount, unmount and fstab changes need admin + step-up.
type DiskOps struct {
	Run       netcfg.Runner
	FstabPath string
	// ProcRoot is "/proc" in production; FS reads the mount usage.
	ProcRoot string
	FS       sysinfo.FS
	Statfs   func(string, *syscall.Statfs_t) error
	Mounter  Mounter
	Planner  *planner.Manager
	// Log returns the last journal lines of a unit (optional).
	Log func(ctx context.Context, unit string) []string
	Now func() time.Time
}

// DiskOverview is the disks.overview result.
type DiskOverview struct {
	Blocks []disks.Block   `json:"blocks"`
	Mounts []sysinfo.Mount `json:"mounts"`
	Fstab  disks.Fstab     `json:"fstab"`
	Swaps  []Swap          `json:"swaps"`
	Error  string          `json:"error,omitempty"`
}

// Swap is one line of /proc/swaps.
type Swap struct {
	Device string `json:"device"`
	Type   string `json:"type"`
	Size   uint64 `json:"size"`
	Used   uint64 `json:"used"`
}

// FstabCheck is the disks.fstab_check and disks.fstab_plan result.
type FstabCheck struct {
	Problems []disks.Problem `json:"problems"`
	Diff     string          `json:"diff"`
	Change   *planner.Change `json:"change,omitempty"`
	Entries  []disks.Entry   `json:"entries"`
	Blocking bool            `json:"blocking"`
}

// MountResult is the disks.mount / disks.unmount result.
type MountResult struct {
	OK    bool         `json:"ok"`
	Users []disks.User `json:"users"`
	Log   []string     `json:"log"`
}

type fstabParams struct {
	Entries []disks.Entry `json:"entries"`
}

type mountParams struct {
	Target string `json:"target"`
}

func (o *DiskOps) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *DiskOps) proc() string {
	if o.ProcRoot == "" {
		return "/proc"
	}
	return o.ProcRoot
}

func (o *DiskOps) readFstab() (disks.Fstab, error) {
	b, err := os.ReadFile(o.FstabPath)
	if errors.Is(err, os.ErrNotExist) {
		return disks.ParseFstab(""), nil
	}
	if err != nil {
		return disks.Fstab{}, err
	}
	return disks.ParseFstab(string(b)), nil
}

func readSwaps(proc string) []Swap {
	out := []Swap{}
	b, _ := os.ReadFile(filepath.Join(proc, "swaps")) //nolint:gosec // procfs
	for i, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 4 {
			continue
		}
		size, _ := strconv.ParseUint(f[2], 10, 64)
		used, _ := strconv.ParseUint(f[3], 10, 64)
		out = append(out, Swap{Device: f[0], Type: f[1], Size: size << 10, Used: used << 10})
	}
	return out
}

// check validates entries against the current file and findmnt --verify.
func (o *DiskOps) check(ctx context.Context, entries []disks.Entry) (FstabCheck, disks.Fstab, string, error) {
	cur, err := o.readFstab()
	if err != nil {
		return FstabCheck{}, cur, "", err
	}
	if len(entries) > 200 {
		return FstabCheck{}, cur, "", Errf(rpc.CodeValidation, "too many entries")
	}
	for i := range entries {
		entries[i].Spec, entries[i].File = strings.TrimSpace(entries[i].Spec), strings.TrimSpace(entries[i].File)
		entries[i].Type, entries[i].Options = strings.TrimSpace(entries[i].Type), strings.TrimSpace(entries[i].Options)
		if !slices.ContainsFunc(cur.Entries, func(e disks.Entry) bool { return e.Line == entries[i].Line }) {
			entries[i].Line = 0 // unknown line: treat as new
		}
	}
	res := FstabCheck{Entries: entries, Problems: disks.Validate(entries, cur.Entries)}
	text := disks.Render(cur, entries)
	if !disks.Blocking(res.Problems) {
		vp, err := disks.Verify(ctx, disks.Run(o.Run), text)
		if err != nil {
			return res, cur, "", err
		}
		res.Problems = append(res.Problems, vp...)
	}
	if res.Problems == nil {
		res.Problems = []disks.Problem{}
	}
	res.Blocking = disks.Blocking(res.Problems)
	old, nw := cur.Text, text
	res.Diff = netcfg.UnifiedDiff(o.FstabPath, &old, &nw)
	return res, cur, text, nil
}

// Register installs the disks.* operations and the fstab change handler.
func (o *DiskOps) Register(ops map[string]*Op) {
	Register(ops, &Op{Name: "disks.overview", Action: policy.ActOverviewRead, NoAudit: true, Timeout: time.Minute,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			res := DiskOverview{Swaps: readSwaps(o.proc())}
			var err error
			if res.Blocks, err = disks.Blocks(ctx, disks.Run(o.Run)); err != nil {
				res.Blocks, res.Error = []disks.Block{}, "lsblk"
			}
			if res.Mounts, err = o.FS.Mounts(o.Statfs); err != nil || res.Mounts == nil {
				res.Mounts = []sysinfo.Mount{}
			}
			if res.Fstab, err = o.readFstab(); err != nil {
				return nil, err
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "disks.fstab_check", Action: policy.ActOverviewRead, NoAudit: true, Timeout: time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p fstabParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			res, _, _, err := o.check(ctx, p.Entries)
			return res, err
		}})

	Register(ops, &Op{Name: "disks.fstab_plan", Action: policy.ActDisksWrite, Timeout: time.Minute,
		AuditTarget: func(Call) string { return "file:" + o.FstabPath },
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p fstabParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			res, cur, text, err := o.check(ctx, p.Entries)
			if err != nil {
				return nil, err
			}
			if res.Blocking {
				return res, nil // nothing planned; the problems say why
			}
			if text == cur.Text {
				return nil, Errf(rpc.CodeValidation, "no change")
			}
			payload, err := json.Marshal(fstabPayload{Old: cur.Text, New: text,
				Backup: o.FstabPath + ".daemonica-" + o.now().UTC().Format("20060102-150405")})
			if err != nil {
				return nil, err
			}
			ch, err := o.Planner.Plan(KindFstab, c.Subject.AccountID, "fstab", res.Diff, "medium", payload)
			if err != nil {
				return nil, mapPlannerErr(err)
			}
			ch = redact(ch)
			res.Change = &ch
			c.AuditKV["change"] = ch.ID
			c.AuditKV["entries"] = strconv.Itoa(len(p.Entries))
			return res, nil
		}})

	Register(ops, &Op{Name: "disks.users", Action: policy.ActOverviewRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p mountParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !filepath.IsAbs(p.Target) || filepath.Clean(p.Target) != p.Target {
				return nil, Errf(rpc.CodeValidation, "invalid target")
			}
			return disks.Users(o.proc(), p.Target, 50), nil
		}})

	target := func(c Call) string {
		var p mountParams
		_ = json.Unmarshal(c.Params, &p)
		return "mount:" + p.Target
	}
	Register(ops, &Op{Name: "disks.mount", Action: policy.ActDisksWrite, Timeout: 2 * time.Minute, AuditTarget: target,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p mountParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			cur, err := o.readFstab()
			if err != nil {
				return nil, err
			}
			// Only what fstab describes is mounted (structured, reviewable).
			if !slices.ContainsFunc(cur.Entries, func(e disks.Entry) bool { return e.File == p.Target && e.Type != "swap" }) {
				return nil, Errf(rpc.CodeNotFound, "not in fstab")
			}
			if disks.Mounted(o.proc(), p.Target) {
				return nil, Errf(rpc.CodeConflict, "already mounted")
			}
			if err := o.Mounter.Reload(ctx); err != nil {
				return nil, err
			}
			unit := disks.UnitName(p.Target)
			err = o.Mounter.Unit(ctx, unit, true)
			res := MountResult{Users: []disks.User{}, Log: []string{}, OK: err == nil && disks.Mounted(o.proc(), p.Target)}
			if !res.OK && o.Log != nil {
				res.Log = o.Log(ctx, unit)
			}
			c.AuditKV["ok"] = strconv.FormatBool(res.OK)
			return res, nil
		}})

	Register(ops, &Op{Name: "disks.unmount", Action: policy.ActDisksWrite, Timeout: 2 * time.Minute, AuditTarget: target,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p mountParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !filepath.IsAbs(p.Target) || filepath.Clean(p.Target) != p.Target {
				return nil, Errf(rpc.CodeValidation, "invalid target")
			}
			if disks.Critical(p.Target) {
				return nil, Errf(CodeProtectedMount, "")
			}
			if !disks.Mounted(o.proc(), p.Target) {
				return nil, Errf(rpc.CodeNotFound, "not mounted")
			}
			res := MountResult{Users: disks.Users(o.proc(), p.Target, 50), Log: []string{}}
			if len(res.Users) > 0 {
				c.AuditKV["busy"] = strconv.Itoa(len(res.Users))
				return res, nil
			}
			unit := disks.UnitName(p.Target)
			err := o.Mounter.Unit(ctx, unit, false)
			res.OK = err == nil && !disks.Mounted(o.proc(), p.Target)
			if !res.OK {
				res.Users = disks.Users(o.proc(), p.Target, 50)
				if o.Log != nil {
					res.Log = o.Log(ctx, unit)
				}
			}
			c.AuditKV["ok"] = strconv.FormatBool(res.OK)
			return res, nil
		}})
}

// JournalTail returns the last lines of a unit's journal for DiskOps.Log.
func JournalTail(ctx context.Context, unit string) []string {
	r, err := journal.Run(ctx, journal.Query{Unit: unit, Lines: 10, Boot: "0"})
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(r.Entries))
	for _, e := range r.Entries {
		out = append(out, e.Message)
	}
	return out
}
