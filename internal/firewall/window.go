package firewall

import (
	"context"
	"strconv"
)

// WindowComment marks the temporary rule of an ACME window.
const WindowComment = "daemonica:acme:window"

func windowSpec(port int, prepend bool) AddSpec {
	return AddSpec{Action: "allow", Direction: "in", Proto: "tcp", Port: strconv.Itoa(port), From: "any", To: "any",
		Comment: WindowComment, Prepend: prepend}
}

// OpenWindow opens port/tcp for every host while ufw blocks it, for an ACME
// challenge (SPEC §3.6 "ACME-Fenster"). The returned function closes the
// window again; it is a no-op when ufw is inactive or the port is reachable.
func (u *Ufw) OpenWindow(ctx context.Context, port int) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if !u.Installed() {
		return noop, nil
	}
	active, err := u.Active(ctx)
	if err != nil || !active {
		return noop, err
	}
	c, err := u.ReadConfig()
	if err != nil {
		return noop, err
	}
	v4 := Reach(c, true, "tcp", port, false, nil)
	v6 := Reach(c, true, "tcp", port, true, nil)
	if v4.Allowed && v6.Allowed {
		return noop, nil
	}
	// A deny rule for the port wins over an appended allow: put the window first.
	byRule := (!v4.Allowed && v4.Reason == "rule") || (!v6.Allowed && v6.Reason == "rule")
	s := windowSpec(port, byRule)
	if err := u.ufw(ctx, s.Args()...); err != nil {
		return noop, err
	}
	return func(ctx context.Context) error { return u.closeWindow(ctx, port) }, nil
}

func (u *Ufw) closeWindow(ctx context.Context, port int) error {
	s := windowSpec(port, false)
	s.Comment = "" // ufw delete matches the rule without its comment
	return u.ufw(ctx, append([]string{"--force", "delete"}, s.Args()...)...)
}

// CloseStaleWindows removes window rules left behind by an interrupted
// issuance (helper crash or restart while a window was open).
func (u *Ufw) CloseStaleWindows(ctx context.Context) error {
	if !u.Installed() {
		return nil
	}
	c, err := u.ReadConfig()
	if err != nil {
		return err
	}
	done := map[string]bool{}
	for _, r := range c.Rules {
		if r.Comment != WindowComment || done[r.DPort] {
			continue
		}
		done[r.DPort] = true
		p, err := strconv.Atoi(r.DPort)
		if err != nil {
			continue
		}
		if err := u.closeWindow(ctx, p); err != nil {
			return err
		}
	}
	return nil
}
