// Package policy is the single source of truth for authorization (SPEC §3.4,
// Annex A). It is evaluated inside daemonica-helper for every operation; the
// web process consults the same table only to shape the UI.
//
// Default is deny: an action missing from the table is never allowed.
package policy

import "fmt"

// Role is a dashboard account role.
type Role string

// Roles (D-08).
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleReadOnly Role = "readonly"
)

// Roles lists all roles in a stable order (used by generated tests).
var Roles = []Role{RoleAdmin, RoleOperator, RoleReadOnly}

// ValidRole reports whether r is a known role.
func ValidRole(r Role) bool {
	for _, x := range Roles {
		if x == r {
			return true
		}
	}
	return false
}

// Action is an authorization class. Several helper operations may map to one action.
type Action string

// Scope describes which objects a grant covers.
type Scope int

const (
	// ScopeNone: action not permitted for the role.
	ScopeNone Scope = iota
	// ScopeOwn: only objects belonging to the account's mapped Linux user.
	ScopeOwn
	// ScopeAll: all objects (subject to protected-object rules elsewhere).
	ScopeAll
)

// Rule is the permission of one role for one action.
type Rule struct {
	Scope  Scope
	StepUp bool // fresh passkey verification required (Annex A "(S)")
}

// Actions (Annex A, Phase 1). Names are stable identifiers used in audit records.
const (
	ActOverviewRead       Action = "overview.read"
	ActServiceControl     Action = "services.control"           // start/stop/restart/reload, unprotected units
	ActServiceControlProt Action = "services.control_protected" // same, protected units
	ActServiceEnable      Action = "services.enable"            // enable/disable/mask/unmask
	ActLogsRead           Action = "logs.read"
	ActProcRead           Action = "proc.read"
	ActProcSignal         Action = "proc.signal"
	ActUsersRead          Action = "users.read"
	ActUsersWrite         Action = "users.write"
	ActSSHKeysOwn         Action = "sshkeys.own"
	ActSSHKeysOthers      Action = "sshkeys.others"
	ActNetWrite           Action = "network.write"
	ActFirewallWrite      Action = "firewall.write"
	ActFirewallLogs       Action = "firewall.logs"
	ActCaptureStart       Action = "capture.start"
	ActCaptureManage      Action = "capture.manage"
	ActCaptureDownload    Action = "capture.download"
	ActPackagesWrite      Action = "packages.write"
	ActDisksWrite         Action = "disks.write"
	ActTimeHostWrite      Action = "timehost.write"
	ActPower              Action = "power"
	ActJobsRead           Action = "jobs.read"
	ActJobsRun            Action = "jobs.run"
	ActJobsWrite          Action = "jobs.write"
	ActJobsWriteRoot      Action = "jobs.write_root"
	ActFiles              Action = "files"
	ActFilesRoot          Action = "files.root"
	ActTerminal           Action = "terminal"
	ActTerminalElevated   Action = "terminal.elevated"
	ActAccountsRead       Action = "accounts.read"
	ActAccountsManage     Action = "accounts.manage"
	ActOwnSessions        Action = "self.sessions"
	ActOwnPasskeys        Action = "self.passkeys"
	ActAuditRead          Action = "audit.read"
	ActSettingsWrite      Action = "settings.write"
)

var (
	deny      = Rule{}
	all       = Rule{Scope: ScopeAll}
	allStepUp = Rule{Scope: ScopeAll, StepUp: true}
	own       = Rule{Scope: ScopeOwn}
	ownStepUp = Rule{Scope: ScopeOwn, StepUp: true}
)

// table mirrors Annex A. Order of the inner array: admin, operator, readonly.
var table = map[Action][3]Rule{
	ActOverviewRead:       {all, all, all},
	ActServiceControl:     {all, all, deny},
	ActServiceControlProt: {allStepUp, deny, deny},
	ActServiceEnable:      {allStepUp, deny, deny},
	ActLogsRead:           {all, all, deny},
	ActProcRead:           {all, all, all},
	ActProcSignal:         {all, own, deny},
	ActUsersRead:          {all, all, all},
	ActUsersWrite:         {allStepUp, deny, deny},
	ActSSHKeysOwn:         {own, own, deny},
	ActSSHKeysOthers:      {allStepUp, deny, deny},
	ActNetWrite:           {allStepUp, deny, deny},
	ActFirewallWrite:      {allStepUp, deny, deny},
	ActFirewallLogs:       {all, all, deny},
	ActCaptureStart:       {allStepUp, deny, deny},
	ActCaptureManage:      {all, deny, deny},
	ActCaptureDownload:    {allStepUp, deny, deny},
	ActPackagesWrite:      {allStepUp, deny, deny},
	ActDisksWrite:         {allStepUp, deny, deny},
	ActTimeHostWrite:      {allStepUp, deny, deny},
	ActPower:              {allStepUp, deny, deny},
	ActJobsRead:           {all, all, all},
	ActJobsRun:            {all, all, deny},
	ActJobsWrite:          {all, deny, deny},
	ActJobsWriteRoot:      {allStepUp, deny, deny},
	ActFiles:              {own, own, deny},
	ActFilesRoot:          {allStepUp, deny, deny},
	ActTerminal:           {own, own, deny},
	ActTerminalElevated:   {allStepUp, deny, deny},
	ActAccountsRead:       {all, deny, deny},
	ActAccountsManage:     {allStepUp, deny, deny},
	ActOwnSessions:        {own, own, own},
	ActOwnPasskeys:        {ownStepUp, ownStepUp, ownStepUp},
	ActAuditRead:          {all, deny, deny},
	ActSettingsWrite:      {allStepUp, deny, deny},
}

// Actions returns all actions known to the table (for generated tests).
func Actions() []Action {
	out := make([]Action, 0, len(table))
	for a := range table {
		out = append(out, a)
	}
	return out
}

// Lookup returns the rule for role/action. Unknown role or action yields deny.
func Lookup(r Role, a Action) Rule {
	row, ok := table[a]
	if !ok {
		return deny
	}
	switch r {
	case RoleAdmin:
		return row[0]
	case RoleOperator:
		return row[1]
	case RoleReadOnly:
		return row[2]
	default:
		return deny
	}
}

// Subject is the authenticated principal as resolved by the helper from a grant.
type Subject struct {
	AccountID string
	Role      Role
	LinuxUser string
	LinuxUID  uint32
	// StepUp is true while a fresh, helper-verified passkey step-up is valid (5 min).
	StepUp bool
}

// Decision is the outcome of an authorization check.
type Decision int

const (
	Deny Decision = iota
	Allow
	NeedStepUp
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case NeedStepUp:
		return "step_up_required"
	default:
		return "deny"
	}
}

// Decide evaluates whether s may perform action a on an object owned by
// ownerUID (ownerKnown=false if the object has no owner concept).
func Decide(s Subject, a Action, ownerUID uint32, ownerKnown bool) Decision {
	if !ValidRole(s.Role) {
		return Deny
	}
	rule := Lookup(s.Role, a)
	switch rule.Scope {
	case ScopeNone:
		return Deny
	case ScopeOwn:
		if ownerKnown && ownerUID != s.LinuxUID {
			return Deny
		}
	case ScopeAll:
	default:
		return Deny
	}
	if rule.StepUp && !s.StepUp {
		return NeedStepUp
	}
	return Allow
}

// MustKnow panics if action is not in the table; used at helper start-up to
// verify that every registered operation maps to a policy entry.
func MustKnow(a Action) {
	if _, ok := table[a]; !ok {
		panic(fmt.Sprintf("policy: action %q has no policy entry", a))
	}
}
