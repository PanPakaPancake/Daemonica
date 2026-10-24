package helper

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/users"
	"github.com/PanPakaPancake/daemonica/internal/validate"
)

// UserOps manages Linux users and groups (SPEC §7.3). All changes are
// Admin + step-up (Annex A) and run through shadow-utils with argv arrays.
type UserOps struct {
	DB    users.DB
	Run   users.Runner
	Accts *DB // dashboard accounts (mapping protection)
	Now   func() time.Time
	// KeyCount optionally returns the number of SSH keys of a user.
	KeyCount func(ctx context.Context, name string) int
}

func (u *UserOps) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

// UserListing is the users.list result.
type UserListing struct {
	Users  []UserView    `json:"users"`
	Groups []users.Group `json:"groups"`
	Shells []string      `json:"shells"`
}

// UserView adds dashboard information to a Linux user.
type UserView struct {
	users.User
	Accounts []string `json:"dashboard_accounts,omitempty"` // dashboard accounts mapped to this user
	AdminMap bool     `json:"admin_mapped"`                 // mapped to an active admin account
}

type userParams struct {
	Name          string   `json:"name"`
	Gecos         *string  `json:"gecos,omitempty"`
	Shell         *string  `json:"shell,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	SetGroups     bool     `json:"set_groups,omitempty"`
	Expires       *string  `json:"expires,omitempty"`
	Locked        *bool    `json:"locked,omitempty"`
	Sudo          *bool    `json:"sudo,omitempty"`
	Password      string   `json:"password,omitempty"`
	ForceChange   bool     `json:"force_change,omitempty"`
	RemoveHome    bool     `json:"remove_home,omitempty"`
	ConfirmName   string   `json:"confirm_name,omitempty"`
	ConfirmMapped bool     `json:"confirm_mapped,omitempty"` // extra confirmation for users mapped to dashboard accounts
	Advanced      bool     `json:"advanced,omitempty"`       // required to touch system users
	Members       []string `json:"members,omitempty"`
}

func (u *UserOps) mappings(ctx context.Context) (map[string][]string, map[string]bool) {
	byUser, admin := map[string][]string{}, map[string]bool{}
	if u.Accts == nil {
		return byUser, admin
	}
	accs, err := u.Accts.ListAccounts(ctx)
	if err != nil {
		return byUser, admin
	}
	for _, a := range accs {
		byUser[a.LinuxUser] = append(byUser[a.LinuxUser], a.Name)
		if a.Role == policy.RoleAdmin && !a.Disabled {
			admin[a.LinuxUser] = true
		}
	}
	return byUser, admin
}

// guard loads the target user and enforces the protection rules.
func (u *UserOps) guard(ctx context.Context, p userParams, destructive bool) (users.User, error) {
	if validate.LinuxUser(p.Name) != nil {
		return users.User{}, Errf(rpc.CodeValidation, "invalid user name")
	}
	list, _, err := u.DB.List(u.now())
	if err != nil {
		return users.User{}, err
	}
	i := slices.IndexFunc(list, func(x users.User) bool { return x.Name == p.Name })
	if i < 0 {
		return users.User{}, Errf(rpc.CodeNotFound, "user not found")
	}
	t := list[i]
	if t.UID == 0 && destructive {
		return t, Errf(rpc.CodeLockout, "root cannot be deleted or locked")
	}
	if t.System && !p.Advanced {
		return t, Errf(rpc.CodeValidation, "system user: enable advanced mode to change it")
	}
	_, admin := u.mappings(ctx)
	if destructive && admin[t.Name] && !p.ConfirmMapped {
		return t, Errf(rpc.CodeLockout, "user is mapped to an active dashboard admin; explicit confirmation required")
	}
	return t, nil
}

func (u *UserOps) exec(ctx context.Context, stdin []byte, path string, args ...string) error {
	run := u.Run
	if run == nil {
		run = users.ExecRunner
	}
	if err := run(ctx, stdin, path, args...); err != nil {
		var te *users.ToolError
		if errors.As(err, &te) {
			return Errf(rpc.CodeConflict, "%s", te.Error())
		}
		return err
	}
	return nil
}

func (u *UserOps) groupSet() map[string]bool {
	_, gs, _ := u.DB.List(u.now())
	m := map[string]bool{}
	for _, g := range gs {
		m[g.Name] = true
	}
	return m
}

// Register installs users.* and groups.* operations.
func (u *UserOps) Register(ops map[string]*Op) {
	target := func(prefix string) func(c Call) string {
		return func(c Call) string {
			var p userParams
			_ = json.Unmarshal(c.Params, &p)
			return prefix + p.Name
		}
	}

	Register(ops, &Op{Name: "users.list", Action: policy.ActUsersRead, NoAudit: true, Timeout: 60 * time.Second,
		Handle: func(ctx context.Context, _ Call) (any, error) {
			list, groups, err := u.DB.List(u.now())
			if err != nil {
				return nil, err
			}
			byUser, admin := u.mappings(ctx)
			out := UserListing{Groups: groups, Shells: u.DB.Shells()}
			n := 0
			for _, x := range list {
				v := UserView{User: x, Accounts: byUser[x.Name], AdminMap: admin[x.Name]}
				if u.KeyCount != nil && (!x.System) && n < 50 {
					v.KeyCount = u.KeyCount(ctx, x.Name)
					n++
				}
				out.Users = append(out.Users, v)
			}
			return out, nil
		}})

	Register(ops, &Op{Name: "users.create", Action: policy.ActUsersWrite, AuditTarget: target("linux_user:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var s users.CreateSpec
			if err := decode(c, &s); err != nil {
				return nil, err
			}
			args, err := u.DB.CreateArgs(s, u.groupSet())
			if err != nil {
				return nil, Errf(rpc.CodeValidation, "%s", err.Error())
			}
			return nil, u.exec(ctx, nil, users.Useradd, args...)
		}})

	Register(ops, &Op{Name: "users.update", Action: policy.ActUsersWrite, AuditTarget: target("linux_user:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			t, err := u.guard(ctx, p, false)
			if err != nil {
				return nil, err
			}
			var args []string
			if p.Gecos != nil {
				if !users.ValidGecos(*p.Gecos) {
					return nil, Errf(rpc.CodeValidation, "invalid description")
				}
				args = append(args, "--comment", *p.Gecos)
			}
			if p.Shell != nil {
				if !slices.Contains(u.DB.Shells(), *p.Shell) {
					return nil, Errf(rpc.CodeValidation, "shell not allowed")
				}
				args = append(args, "--shell", *p.Shell)
			}
			if p.SetGroups {
				gs := u.groupSet()
				for _, g := range p.Groups {
					if validate.LinuxUser(g) != nil || !gs[g] {
						return nil, Errf(rpc.CodeValidation, "unknown group")
					}
				}
				// sudo membership is managed via users.set_sudo (separate warning/audit).
				hasSudo := slices.ContainsFunc(t.Groups, func(g string) bool { return slices.Contains(users.SudoGroups, g) })
				wantsSudo := slices.ContainsFunc(p.Groups, func(g string) bool { return slices.Contains(users.SudoGroups, g) })
				if hasSudo != wantsSudo {
					return nil, Errf(rpc.CodeValidation, "use the sudo switch to change administrator rights")
				}
				args = append(args, "--groups", strings.Join(p.Groups, ","))
			}
			if p.Expires != nil {
				d, err := users.ParseDate(*p.Expires)
				if err != nil {
					return nil, Errf(rpc.CodeValidation, "invalid date")
				}
				args = append(args, "--expiredate", d)
			}
			if len(args) == 0 {
				return nil, Errf(rpc.CodeValidation, "nothing to change")
			}
			return nil, u.exec(ctx, nil, users.Usermod, append(args, "--", t.Name)...)
		}})

	Register(ops, &Op{Name: "users.set_locked", Action: policy.ActUsersWrite, AuditTarget: target("linux_user:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil || p.Locked == nil {
				return nil, Errf(rpc.CodeBadRequest, "invalid parameters")
			}
			t, err := u.guard(ctx, p, *p.Locked)
			if err != nil {
				return nil, err
			}
			if *p.Locked {
				// Lock the password AND expire the account, so SSH keys stop working too.
				return nil, u.exec(ctx, nil, users.Usermod, "--lock", "--expiredate", "1", "--", t.Name)
			}
			if err := u.exec(ctx, nil, users.Usermod, "--expiredate", "", "--", t.Name); err != nil {
				return nil, err
			}
			if t.Locked && !t.NoPassword {
				return nil, u.exec(ctx, nil, users.Usermod, "--unlock", "--", t.Name)
			}
			return nil, nil
		}})

	Register(ops, &Op{Name: "users.set_sudo", Action: policy.ActUsersWrite, AuditTarget: target("linux_user:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil || p.Sudo == nil {
				return nil, Errf(rpc.CodeBadRequest, "invalid parameters")
			}
			t, err := u.guard(ctx, p, !*p.Sudo)
			if err != nil {
				return nil, err
			}
			if t.UID == 0 {
				return nil, Errf(rpc.CodeValidation, "root does not need sudo")
			}
			if *p.Sudo {
				return nil, u.exec(ctx, nil, users.Gpasswd, "--add", t.Name, "sudo")
			}
			for _, g := range t.Groups {
				if slices.Contains(users.SudoGroups, g) {
					if err := u.exec(ctx, nil, users.Gpasswd, "--delete", t.Name, g); err != nil {
						return nil, err
					}
				}
			}
			return nil, nil
		}})

	Register(ops, &Op{Name: "users.set_password", Action: policy.ActUsersWrite, AuditTarget: target("linux_user:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			t, err := u.guard(ctx, p, false)
			if err != nil {
				return nil, err
			}
			if len([]rune(p.Password)) < 12 || len(p.Password) > 256 || strings.ContainsAny(p.Password, "\n\r\x00:") {
				return nil, Errf(rpc.CodeValidation, "password must have 12–256 characters and no line breaks or ':'")
			}
			// Password only via stdin, never argv or logs (SPEC §7.3).
			if err := u.exec(ctx, []byte(t.Name+":"+p.Password+"\n"), users.Chpasswd); err != nil {
				return nil, err
			}
			if p.ForceChange {
				return nil, u.exec(ctx, nil, users.Chage, "--lastday", "0", "--", t.Name)
			}
			return nil, nil
		}})

	Register(ops, &Op{Name: "users.delete", Action: policy.ActUsersWrite, AuditTarget: target("linux_user:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if p.ConfirmName != p.Name {
				return nil, Errf(rpc.CodeValidation, "type the user name to confirm")
			}
			t, err := u.guard(ctx, p, true)
			if err != nil {
				return nil, err
			}
			args := []string{}
			if p.RemoveHome {
				args = append(args, "--remove")
			}
			return nil, u.exec(ctx, nil, users.Userdel, append(args, "--", t.Name)...)
		}})

	Register(ops, &Op{Name: "groups.create", Action: policy.ActUsersWrite, AuditTarget: target("group:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if validate.LinuxUser(p.Name) != nil {
				return nil, Errf(rpc.CodeValidation, "invalid group name")
			}
			return nil, u.exec(ctx, nil, users.Groupadd, "--", p.Name)
		}})

	Register(ops, &Op{Name: "groups.set_members", Action: policy.ActUsersWrite, AuditTarget: target("group:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if validate.LinuxUser(p.Name) != nil || !u.groupSet()[p.Name] {
				return nil, Errf(rpc.CodeValidation, "unknown group")
			}
			if slices.Contains(users.SudoGroups, p.Name) {
				return nil, Errf(rpc.CodeValidation, "use the sudo switch per user")
			}
			for _, m := range p.Members {
				if validate.LinuxUser(m) != nil {
					return nil, Errf(rpc.CodeValidation, "invalid member")
				}
			}
			return nil, u.exec(ctx, nil, users.Gpasswd, "--members", strings.Join(p.Members, ","), p.Name)
		}})

	Register(ops, &Op{Name: "groups.delete", Action: policy.ActUsersWrite, AuditTarget: target("group:"),
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p userParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if p.ConfirmName != p.Name || validate.LinuxUser(p.Name) != nil {
				return nil, Errf(rpc.CodeValidation, "type the group name to confirm")
			}
			_, gs, _ := u.DB.List(u.now())
			i := slices.IndexFunc(gs, func(g users.Group) bool { return g.Name == p.Name })
			if i < 0 {
				return nil, Errf(rpc.CodeNotFound, "group not found")
			}
			if (gs[i].System && !p.Advanced) || slices.Contains(users.SudoGroups, p.Name) || gs[i].GID == 0 {
				return nil, Errf(rpc.CodeLockout, "protected group")
			}
			return nil, u.exec(ctx, nil, users.Groupdel, "--", p.Name)
		}})
}
