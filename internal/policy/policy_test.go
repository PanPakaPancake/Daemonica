package policy

import "testing"

// TestGeneratedMatrix walks every action × role × step-up state and checks the
// decision against the table semantics (SPEC §3.4 "generated authorization
// test matrix"). Endpoint-level matrices are generated from the same table in
// the web and helper packages.
func TestGeneratedMatrix(t *testing.T) {
	for _, a := range Actions() {
		for _, r := range Roles {
			for _, su := range []bool{false, true} {
				rule := Lookup(r, a)
				s := Subject{AccountID: "x", Role: r, LinuxUID: 1000, StepUp: su}
				got := Decide(s, a, 0, false)
				var want Decision
				switch {
				case rule.Scope == ScopeNone:
					want = Deny
				case rule.StepUp && !su:
					want = NeedStepUp
				default:
					want = Allow
				}
				if got != want {
					t.Errorf("%s/%s/stepup=%v: got %v want %v", a, r, su, got, want)
				}
			}
		}
	}
}

func TestDenyByDefault(t *testing.T) {
	s := Subject{Role: RoleAdmin, StepUp: true}
	if Decide(s, Action("unknown.thing"), 0, false) != Deny {
		t.Fatal("unknown action must be denied")
	}
	if Decide(Subject{Role: "root", StepUp: true}, ActOverviewRead, 0, false) != Deny {
		t.Fatal("unknown role must be denied")
	}
}

func TestOwnScope(t *testing.T) {
	op := Subject{Role: RoleOperator, LinuxUID: 1001}
	if Decide(op, ActProcSignal, 1001, true) != Allow {
		t.Fatal("operator may signal own process")
	}
	if Decide(op, ActProcSignal, 0, true) != Deny {
		t.Fatal("operator must not signal foreign process")
	}
}

func TestReadOnlyCannotUseSensitiveTools(t *testing.T) {
	ro := Subject{Role: RoleReadOnly, StepUp: true}
	for _, a := range []Action{ActLogsRead, ActFiles, ActTerminal, ActProcSignal, ActFirewallLogs, ActCaptureStart} {
		if Decide(ro, a, 0, false) != Deny {
			t.Errorf("readonly must be denied %s (A-09)", a)
		}
	}
}

func TestCaptureAdminOnlyWithStepUp(t *testing.T) {
	if Decide(Subject{Role: RoleAdmin}, ActCaptureStart, 0, false) != NeedStepUp {
		t.Fatal("capture start requires step-up")
	}
	if Decide(Subject{Role: RoleOperator, StepUp: true}, ActCaptureStart, 0, false) != Deny {
		t.Fatal("operator must not capture")
	}
}

func TestHelpers(t *testing.T) {
	if !ValidRole(RoleOperator) || ValidRole("superuser") {
		t.Fatal("ValidRole")
	}
	for d, s := range map[Decision]string{Allow: "allow", Deny: "deny", NeedStepUp: "step_up_required"} {
		if d.String() != s {
			t.Errorf("%d → %s", d, d.String())
		}
	}
	MustKnow(ActFiles)
	defer func() {
		if recover() == nil {
			t.Fatal("MustKnow must panic for unknown actions")
		}
	}()
	MustKnow(Action("nope"))
}

func TestLookupUnknown(t *testing.T) {
	if Lookup(Role("x"), ActFiles).Scope != ScopeNone {
		t.Fatal("unknown role must map to deny")
	}
}
