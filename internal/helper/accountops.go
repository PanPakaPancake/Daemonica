package helper

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/auth"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// AccountView is the admin list entry of an account.
type AccountView struct {
	Account
	Sessions int  `json:"sessions"`
	Self     bool `json:"self"`
	// Invited: the account has no passkey yet (an invitation is pending or expired).
	Invited bool `json:"invited"`
}

// InviteResult carries a clear invitation token exactly once.
type InviteResult struct {
	Account   Account   `json:"account"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type accountIDParams struct {
	ID string `json:"id"`
}

func accountTarget(c Call) string {
	var p accountIDParams
	_ = json.Unmarshal(c.Params, &p)
	if p.ID == "" {
		var q struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(c.Params, &q)
		return "account_name:" + q.Name
	}
	return "account:" + p.ID
}

func mapAccountErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return Errf(rpc.CodeNotFound, "")
	case errors.Is(err, ErrLastAdmin):
		return Errf(rpc.CodeLockout, "the last usable admin cannot be removed, disabled or demoted")
	case errors.Is(err, ErrDuplicateName):
		return Errf(rpc.CodeConflict, "account name already exists")
	}
	return err
}

// registerAccountOps installs dashboard account administration (SPEC §7.1, Annex A).
// Every change ends the target's sessions so a new role/state applies at once.
// An admin cannot change, disable or delete their own account (self-lockout guard).
func (a *AuthOps) registerAccountOps(ops map[string]*Op) {
	Register(ops, &Op{Name: "accounts.list", Action: policy.ActAccountsRead, NoAudit: true,
		Handle: func(ctx context.Context, c Call) (any, error) {
			accs, err := a.DB.ListAccounts(ctx)
			if err != nil {
				return nil, err
			}
			counts := map[string]int{}
			for _, s := range a.Grants.List("", "", a.now()) {
				counts[s.AccountID]++
			}
			out := make([]AccountView, 0, len(accs))
			for _, x := range accs {
				out = append(out, AccountView{Account: x, Sessions: counts[x.ID], Self: x.ID == c.Subject.AccountID, Invited: x.Passkeys == 0})
			}
			return out, nil
		}})

	Register(ops, &Op{Name: "accounts.linux_users", Action: policy.ActAccountsRead, NoAudit: true,
		Handle: func(context.Context, Call) (any, error) { return a.EligibleLinuxUsers() }})

	type inviteParams struct {
		Name      string `json:"name"`
		Role      string `json:"role"`
		LinuxUser string `json:"linux_user"`
	}
	Register(ops, &Op{Name: "accounts.invite", Action: policy.ActAccountsManage, AuditTarget: accountTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p inviteParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			role := policy.Role(p.Role)
			if validate.AccountName(p.Name) != nil || !policy.ValidRole(role) {
				return nil, Errf(rpc.CodeValidation, "invalid name or role")
			}
			lu, err := a.resolveLinuxUser(p.LinuxUser)
			if err != nil {
				return nil, err
			}
			acc, err := a.DB.CreateAccount(ctx, p.Name, role, lu.Name, lu.UID, nil, a.now())
			if err != nil {
				return nil, mapAccountErr(err)
			}
			return a.issueInvite(acc)
		}})

	Register(ops, &Op{Name: "accounts.reinvite", Action: policy.ActAccountsManage, AuditTarget: accountTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p accountIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			acc, err := a.DB.AccountByID(ctx, p.ID)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			if acc.Passkeys > 0 {
				// Accounts with passkeys add further keys themselves or use console recovery.
				return nil, Errf(rpc.CodeConflict, "account already has a passkey")
			}
			return a.issueInvite(acc)
		}})

	type roleParams struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	Register(ops, &Op{Name: "accounts.set_role", Action: policy.ActAccountsManage, AuditTarget: accountTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p roleParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.notSelf(c, p.ID); err != nil {
				return nil, err
			}
			if err := mapAccountErr(a.DB.SetRole(ctx, p.ID, policy.Role(p.Role))); err != nil {
				return nil, err
			}
			return map[string]int{"sessions_ended": a.Grants.RevokeAccount(p.ID)}, nil
		}})

	type disableParams struct {
		ID       string `json:"id"`
		Disabled bool   `json:"disabled"`
	}
	Register(ops, &Op{Name: "accounts.set_disabled", Action: policy.ActAccountsManage, AuditTarget: accountTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p disableParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.notSelf(c, p.ID); err != nil {
				return nil, err
			}
			if err := mapAccountErr(a.DB.SetDisabled(ctx, p.ID, p.Disabled)); err != nil {
				return nil, err
			}
			ended := 0
			if p.Disabled {
				ended = a.Grants.RevokeAccount(p.ID)
				_ = a.Tokens.RevokePurpose(auth.PurposeInvite, p.ID)
			}
			return map[string]int{"sessions_ended": ended}, nil
		}})

	type deleteParams struct {
		ID          string `json:"id"`
		ConfirmName string `json:"confirm_name"`
	}
	Register(ops, &Op{Name: "accounts.delete", Action: policy.ActAccountsManage, AuditTarget: accountTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p deleteParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if err := a.notSelf(c, p.ID); err != nil {
				return nil, err
			}
			acc, err := a.DB.AccountByID(ctx, p.ID)
			if err != nil {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			if p.ConfirmName != acc.Name {
				return nil, Errf(rpc.CodeValidation, "confirmation name does not match")
			}
			if err := mapAccountErr(a.DB.DeleteAccount(ctx, p.ID)); err != nil {
				return nil, err
			}
			return map[string]int{"sessions_ended": a.Grants.RevokeAccount(p.ID)}, nil
		}})
}

func (a *AuthOps) notSelf(c Call, id string) error {
	if id == c.Subject.AccountID {
		return Errf(rpc.CodeLockout, "you cannot change your own account here")
	}
	return nil
}

func (a *AuthOps) issueInvite(acc Account) (any, error) {
	tok, err := auth.Issue(a.Tokens, auth.PurposeInvite, acc.ID, auth.InviteTTL, a.now())
	if err != nil {
		return nil, err
	}
	return InviteResult{Account: acc, Token: tok, ExpiresAt: a.now().Add(auth.InviteTTL).UTC()}, nil
}
