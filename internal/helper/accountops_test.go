package helper

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/testutil/softauthn"
)

func stepUp(t *testing.T, e *authEnv, sa *softauthn.Authenticator, grant string) string {
	t.Helper()
	r, res := e.call(t, e.web, "auth.begin_stepup", grant, nil)
	mustOK(t, r, "begin_stepup")
	var cs CeremonyStart
	_ = json.Unmarshal(res, &cs)
	resp, err := sa.Get(cs.Options, testOrigin, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, res = e.call(t, e.web, "auth.finish_stepup", grant, map[string]any{"ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp)})
	mustOK(t, r, "finish_stepup")
	var rot struct {
		Grant string `json:"grant"`
	}
	_ = json.Unmarshal(res, &rot)
	return rot.Grant
}

func listAccounts(t *testing.T, e *authEnv, grant string) []AccountView {
	t.Helper()
	r, res := e.call(t, e.web, "accounts.list", grant, nil)
	mustOK(t, r, "accounts.list")
	var out []AccountView
	_ = json.Unmarshal(res, &out)
	return out
}

func TestAccountInviteRoleDisableDelete(t *testing.T) {
	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)

	// Listing needs no step-up; changes do (Annex A "(S)").
	if l := listAccounts(t, e, g); len(l) != 1 || !l[0].Self || l[0].Invited {
		t.Fatalf("unexpected list %+v", l)
	}
	inv := map[string]any{"name": "Bob", "role": "operator", "linux_user": "pancake"}
	if r, _ := e.call(t, e.web, "accounts.invite", g, inv); code(r) != rpc.CodeStepUpNeeded {
		t.Fatalf("invite without step-up: %+v", r)
	}
	g = stepUp(t, e, sa, g)

	for _, bad := range []map[string]any{
		{"name": "Root", "role": "admin", "linux_user": "root"},
		{"name": "Sys", "role": "admin", "linux_user": "sshd"},
		{"name": "X", "role": "superuser", "linux_user": "pancake"},
		{"name": "bad\nname", "role": "operator", "linux_user": "pancake"},
		{"name": "Inj", "role": "operator", "linux_user": "pancake; id"},
	} {
		if r, _ := e.call(t, e.web, "accounts.invite", g, bad); r.OK {
			t.Fatalf("invalid invite accepted: %v", bad)
		}
	}

	r, res := e.call(t, e.web, "accounts.invite", g, inv)
	mustOK(t, r, "invite")
	var ir InviteResult
	_ = json.Unmarshal(res, &ir)
	if ir.Token == "" || ir.Account.Role != policy.RoleOperator {
		t.Fatalf("bad invite %+v", ir)
	}
	if r, _ := e.call(t, e.web, "accounts.invite", g, inv); code(r) != rpc.CodeConflict {
		t.Fatalf("duplicate name: %+v", r)
	}
	var bob AccountView
	for _, x := range listAccounts(t, e, g) {
		if x.Name == "Bob" {
			bob = x
		}
	}
	if !bob.Invited {
		t.Fatal("invited flag missing")
	}

	// Redeem the invitation with a new authenticator.
	r, res = e.call(t, e.web, "invite.begin_register", "", map[string]any{"token": ir.Token})
	mustOK(t, r, "invite.begin")
	var cs CeremonyStart
	_ = json.Unmarshal(res, &cs)
	sb := softauthn.New()
	resp, _, err := sb.Create(cs.Options, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	r, res = e.call(t, e.web, "invite.finish_register", "", map[string]any{"token": ir.Token, "ceremony_id": cs.CeremonyID, "response": json.RawMessage(resp)})
	mustOK(t, r, "invite.finish")
	var gb GrantResult
	_ = json.Unmarshal(res, &gb)
	if gb.Account.ID != bob.ID || gb.Grant == "" {
		t.Fatalf("invite grant wrong: %+v", gb)
	}
	// Token is single-use.
	if r, _ := e.call(t, e.web, "invite.begin_register", "", map[string]any{"token": ir.Token}); code(r) != rpc.CodeTokenInvalid {
		t.Fatal("invite token reusable")
	}
	// Reinvite is refused once a passkey exists.
	if r, _ := e.call(t, e.web, "accounts.reinvite", g, map[string]any{"id": bob.ID}); code(r) != rpc.CodeConflict {
		t.Fatalf("reinvite: %+v", r)
	}
	// Operators cannot read or manage accounts.
	if r, _ := e.call(t, e.web, "accounts.list", gb.Grant, nil); code(r) != rpc.CodeForbidden {
		t.Fatalf("operator listed accounts: %+v", r)
	}

	// Self-changes are refused.
	me := mustAccount(t, e)
	for _, op := range []struct {
		name string
		p    map[string]any
	}{
		{"accounts.set_role", map[string]any{"id": me.ID, "role": "readonly"}},
		{"accounts.set_disabled", map[string]any{"id": me.ID, "disabled": true}},
		{"accounts.delete", map[string]any{"id": me.ID, "confirm_name": me.Name}},
	} {
		if r, _ := e.call(t, e.web, op.name, g, op.p); code(r) != rpc.CodeLockout {
			t.Fatalf("%s on self: %+v", op.name, r)
		}
	}

	// Role change ends the target's sessions.
	r, _ = e.call(t, e.web, "accounts.set_role", g, map[string]any{"id": bob.ID, "role": "readonly"})
	mustOK(t, r, "set_role")
	if r, _ := e.call(t, e.web, "session.whoami", gb.Grant, nil); code(r) != rpc.CodeUnauthorized {
		t.Fatal("grant survived role change")
	}
	r, g2 := login(t, e, sb, testOrigin)
	mustOK(t, r, "login after role change")
	r, res = e.call(t, e.web, "session.whoami", g2, nil)
	mustOK(t, r, "whoami")
	var who WhoAmI
	_ = json.Unmarshal(res, &who)
	if who.Role != "readonly" {
		t.Fatalf("role not applied: %+v", who)
	}

	// Disabled accounts cannot log in.
	r, _ = e.call(t, e.web, "accounts.set_disabled", g, map[string]any{"id": bob.ID, "disabled": true})
	mustOK(t, r, "disable")
	if r, _ := login(t, e, sb, testOrigin); r.OK {
		t.Fatal("disabled account logged in")
	}

	// Delete requires the exact name.
	if r, _ := e.call(t, e.web, "accounts.delete", g, map[string]any{"id": bob.ID, "confirm_name": "bob"}); code(r) != rpc.CodeValidation {
		t.Fatalf("delete with wrong name: %+v", r)
	}
	r, _ = e.call(t, e.web, "accounts.delete", g, map[string]any{"id": bob.ID, "confirm_name": "Bob"})
	mustOK(t, r, "delete")
	if l := listAccounts(t, e, g); len(l) != 1 {
		t.Fatalf("account not deleted: %+v", l)
	}
}

func TestLastAdminProtection(t *testing.T) {
	e := newAuthEnv(t)
	setupAdmin(t, e)
	ctx := context.Background()
	admin := mustAccount(t, e)

	// Sole admin: demote, disable and delete are refused.
	if err := e.db.SetRole(ctx, admin.ID, policy.RoleOperator); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := e.db.SetDisabled(ctx, admin.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin: %v", err)
	}
	if err := e.db.DeleteAccount(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}

	// A second admin without a passkey does not count as usable.
	second, err := e.db.CreateAccount(ctx, "Second", policy.RoleAdmin, "pancake", 1000, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetRole(ctx, admin.ID, policy.RoleOperator); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("admin without passkey counted: %v", err)
	}
	if err := e.db.AddPasskey(ctx, second.ID, "k", []byte("cred-2"), []byte("{}"), false, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetRole(ctx, admin.ID, policy.RoleOperator); err != nil {
		t.Fatalf("demote with a second usable admin: %v", err)
	}
	if err := e.db.DeleteAccount(ctx, second.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete new last admin: %v", err)
	}
}
