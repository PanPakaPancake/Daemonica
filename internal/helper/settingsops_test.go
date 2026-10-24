package helper

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/planner"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
)

func (e *authEnv) callFrom(ip, op, grant string, params any) *rpc.Response {
	r := req(op, grant, params)
	r.SourceIP = ip
	return e.web.Dispatch(context.Background(), r)
}

func TestAllowlistPlanApplyConfirmRollback(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	pm, err := planner.New(filepath.Join(e.dir, "journal"), 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	pm.Register(&AllowlistHandler{Config: e.cfg})
	(&SettingsOps{Config: e.cfg, Planner: pm}).Register(e.web.Ops)
	const me = "198.51.100.7"
	before := e.cfg.Get().Allowlist

	plan := map[string]any{"allowlist": []string{"198.51.100.0/24"}}
	if r := e.callFrom(me, "settings.allowlist_plan", g, plan); code(r) != rpc.CodeStepUpNeeded {
		t.Fatalf("plan without step-up: %+v", r)
	}
	g = stepUp(t, e, sa, g)

	// Lockout and public protection.
	if r := e.callFrom(me, "settings.allowlist_plan", g, map[string]any{"allowlist": []string{"203.0.113.0/24"}}); code(r) != rpc.CodeLockout {
		t.Fatalf("plan excluding own IP: %+v", r)
	}
	if r := e.callFrom(me, "settings.allowlist_plan", g, map[string]any{"allowlist": []string{"0.0.0.0/0"}}); code(r) != rpc.CodeValidation {
		t.Fatalf("public without confirmation: %+v", r)
	}
	if r := e.callFrom(me, "settings.allowlist_plan", g, map[string]any{"allowlist": []string{"not-a-cidr"}}); r.OK {
		t.Fatal("invalid CIDR accepted")
	}

	plan1 := func() planner.Change {
		r := e.callFrom(me, "settings.allowlist_plan", g, plan)
		mustOK(t, r, "plan")
		var ch planner.Change
		_ = json.Unmarshal(r.Result, &ch)
		if ch.ID == "" || len(ch.Payload) != 0 {
			t.Fatalf("bad plan %+v", ch)
		}
		return ch
	}

	// 1) Apply, then no confirmation → automatic rollback.
	ch := plan1()
	if !slices.Equal(e.cfg.Get().Allowlist, before) {
		t.Fatal("plan must not change anything")
	}
	mustOK(t, e.callFrom(me, "settings.change_apply", g, map[string]any{"id": ch.ID}), "apply")
	if !slices.Contains(e.cfg.Get().Allowlist, "198.51.100.0/24") || !slices.Contains(e.cfg.Get().Allowlist, "127.0.0.0/8") {
		t.Fatalf("not applied (loopback must stay): %v", e.cfg.Get().Allowlist)
	}
	time.Sleep(600 * time.Millisecond)
	if !slices.Equal(e.cfg.Get().Allowlist, before) {
		t.Fatalf("timeout did not roll back: %v", e.cfg.Get().Allowlist)
	}

	// 2) Apply, confirm over the old connection is refused, over a new one accepted.
	ch = plan1()
	stale := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	mustOK(t, e.callFrom(me, "settings.change_apply", g, map[string]any{"id": ch.ID}), "apply 2")
	if r := e.callFrom(me, "settings.change_confirm", g, map[string]any{"id": ch.ID, "connection_since": stale}); code(r) != rpc.CodeConflict {
		t.Fatalf("confirm on old connection: %+v", r)
	}
	if r := e.callFrom(me, "settings.change_confirm", g, map[string]any{"id": ch.ID}); code(r) != rpc.CodeConflict {
		t.Fatalf("confirm without connection time: %+v", r)
	}
	mustOK(t, e.callFrom(me, "settings.change_confirm", g, map[string]any{"id": ch.ID, "connection_since": time.Now().UTC()}), "confirm")
	time.Sleep(400 * time.Millisecond)
	if !slices.Contains(e.cfg.Get().Allowlist, "198.51.100.0/24") {
		t.Fatal("confirmed change was rolled back")
	}

	// 3) User-initiated rollback.
	plan = map[string]any{"allowlist": []string{"198.51.100.0/24", "2001:db8::/32"}}
	ch = plan1()
	mustOK(t, e.callFrom(me, "settings.change_apply", g, map[string]any{"id": ch.ID}), "apply 3")
	mustOK(t, e.callFrom(me, "settings.change_rollback", g, map[string]any{"id": ch.ID}), "rollback")
	if slices.Contains(e.cfg.Get().Allowlist, "2001:db8::/32") {
		t.Fatal("rollback did not restore")
	}

	r := e.callFrom(me, "settings.get", g, nil)
	mustOK(t, r, "settings.get")
	var sv SettingsView
	_ = json.Unmarshal(r.Result, &sv)
	if !sv.ClientOK || sv.ClientIP != me {
		t.Fatalf("settings view %+v", sv)
	}
}
