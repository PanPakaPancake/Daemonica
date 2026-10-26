package apt

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const simOut = `NOTE: This is only a simulation!
Reading package lists...
Building dependency tree...
The following packages have been kept back:
  linux-generic linux-headers-generic
The following packages will be upgraded:
  libssl3t64 openssl tzdata
3 upgraded, 1 newly installed, 1 to remove and 2 not upgraded.
Remv oldlib [1.0-1]
Inst libssl3t64 [3.5.0-1ubuntu1] (3.5.0-1ubuntu1.1 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64])
Inst openssl [3.5.0-1ubuntu1] (3.5.0-1ubuntu1.1 Ubuntu:26.04/resolute-security [amd64]) []
Inst tzdata [2026a-1] (2026b-0ubuntu0.26.04 Ubuntu:26.04/resolute-updates [all])
Inst newdep (2.0-1 Debian:13.1/stable [amd64])
Inst libfoo [1.0] (1.1 Debian-Security:13/stable-security [arm64])
Conf libssl3t64 (3.5.0-1ubuntu1.1 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64])
`

func TestParseSim(t *testing.T) {
	s := ParseSim(simOut)
	if len(s.Install) != 5 || len(s.Remove) != 1 || !slices.Equal(s.Kept, []string{"linux-generic", "linux-headers-generic"}) {
		t.Fatalf("sim: %+v", s)
	}
	want := []struct {
		name, old, new, arch string
		sec                  bool
	}{
		{"libssl3t64", "3.5.0-1ubuntu1", "3.5.0-1ubuntu1.1", "amd64", true},
		{"openssl", "3.5.0-1ubuntu1", "3.5.0-1ubuntu1.1", "amd64", true},
		{"tzdata", "2026a-1", "2026b-0ubuntu0.26.04", "all", false},
		{"newdep", "", "2.0-1", "amd64", false},
		{"libfoo", "1.0", "1.1", "arm64", true},
	}
	for i, w := range want {
		p := s.Install[i]
		if p.Name != w.name || p.Old != w.old || p.New != w.new || p.Arch != w.arch || p.Security != w.sec {
			t.Errorf("%d: %+v", i, p)
		}
	}
	if len(s.Install[0].Origins) != 2 || s.Remove[0].Name != "oldlib" || s.Remove[0].Old != "1.0-1" {
		t.Fatalf("origins/remove: %+v %+v", s.Install[0], s.Remove)
	}
}

func TestNamesAndCritical(t *testing.T) {
	for _, ok := range []string{"openssh-server", "libc6:amd64", "g++", "python3.12"} {
		if !ValidName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-y", "--purge", "Foo", "a b", "x;rm", "../x", "a:"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	c := Critical([]Pkg{{Name: "openssh-server"}, {Name: "vim"}, {Name: "linux-image-7.0.0-38-generic"}, {Name: "linux-image-6.0-1-generic"}, {Name: "sudo:amd64"}}, "7.0.0-38-generic")
	if !slices.Equal(c, []string{"openssh-server", "linux-image-7.0.0-38-generic", "sudo:amd64"}) {
		t.Fatalf("critical: %v", c)
	}
}

func TestParseInstalled(t *testing.T) {
	out := "ii \tbash\t5.2-1\tamd64\t7000\tshells\tGNU Bourne Again SHell\nrc \told\t1\tamd64\t\t\tgone\nun \tnone\t\t\t\t\t\nhi \tvim\t2:9.1\tamd64\t4000\teditors\tVi IMproved\n"
	l := ParseInstalled(out, map[string]bool{"vim": true})
	if len(l) != 3 || l[0].Name != "bash" || l[0].SizeKiB != 7000 || l[1].Status != "rc" || !l[2].Auto || l[2].Status != "hi" {
		t.Fatalf("installed: %+v", l)
	}
}

func TestNeedRestart(t *testing.T) {
	n := ParseNeedRestart("NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 7.0.0-38-generic\nNEEDRESTART-KEXP: 7.0.0-40-generic\nNEEDRESTART-KSTA: 3\nNEEDRESTART-UCSTA: 1\n" +
		"NEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: cron.service\nNEEDRESTART-SVC: bad;unit\nNEEDRESTART-SESS: timo @ session #3\n")
	if n.Kernel != 3 || n.KernelExpect != "7.0.0-40-generic" || n.Microcode != 1 || !slices.Equal(n.Services, []string{"cron.service", "ssh.service"}) || len(n.Sessions) != 1 {
		t.Fatalf("needrestart: %+v", n)
	}
}

func TestSources(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "etc/apt/sources.list.d")
	_ = os.MkdirAll(d, 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/apt/sources.list"), []byte("# comment\ndeb [arch=amd64 signed-by=/usr/share/keyrings/x.gpg] http://deb.debian.org/debian trixie main contrib\n"+
		"deb-src https://security.debian.org/debian-security trixie-security main\nbogus line\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "ubuntu.sources"), []byte("Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute resolute-updates\nComponents: main universe\n"+
		"Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n## disabled\nTypes: deb\nURIs: https://example.org/repo\nSuites: stable\nEnabled: no\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n abc\n\nTypes: deb\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "ignored.save"), []byte("deb http://x y z\n"), 0o644)
	s := ReadSources(root)
	if len(s.Entries) != 4 || len(s.Files) != 2 {
		t.Fatalf("sources: %+v", s)
	}
	e := s.Entries
	if e[0].SignedBy != "/usr/share/keyrings/x.gpg" || e[0].HTTPS || !e[0].Official || e[0].Suites[0] != "trixie" || len(e[0].Components) != 2 {
		t.Errorf("one-line: %+v", e[0])
	}
	if !e[1].HTTPS || e[1].Types[0] != "deb-src" || len(s.Files[0].Errors) != 1 {
		t.Errorf("https/errors: %+v %+v", e[1], s.Files[0])
	}
	if e[2].Format != "deb822" || len(e[2].Suites) != 2 || !e[2].Enabled || !e[2].Official || e[2].File != "/etc/apt/sources.list.d/ubuntu.sources" {
		t.Errorf("deb822: %+v", e[2])
	}
	if e[3].Enabled || e[3].Official || !e[3].HTTPS || e[3].SignedBy != "(embedded key)" || len(s.Files[1].Errors) != 1 {
		t.Errorf("disabled: %+v %+v", e[3], s.Files[1])
	}
}

func TestUnattended(t *testing.T) {
	if _, err := RenderUnattended(Unattended{Enabled: true, AutoReboot: true, RebootTime: "25:00"}, "ubuntu"); err == nil {
		t.Fatal("bad time accepted")
	}
	if _, err := RenderUnattended(Unattended{Enabled: true}, "fedora"); err == nil {
		t.Fatal("unknown distro accepted")
	}
	u := Unattended{Enabled: true, AutoReboot: true, RebootTime: "03:30"}
	text, err := RenderUnattended(u, "debian")
	if err != nil || !strings.Contains(text, `"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";`) ||
		!strings.Contains(text, "#clear Unattended-Upgrade::Origins-Pattern;") || !strings.Contains(text, `Automatic-Reboot-Time "03:30"`) {
		t.Fatalf("render: %v\n%s", err, text)
	}
	if back, ok := ParseManaged(text); !ok || back != u {
		t.Fatalf("parse back: %+v %v", back, ok)
	}
	if _, ok := ParseManaged("APT::Periodic::Unattended-Upgrade \"1\";\n"); ok {
		t.Fatal("foreign file treated as managed")
	}
	off, _ := RenderUnattended(Unattended{}, "ubuntu")
	if back, _ := ParseManaged(off); back.Enabled || strings.Contains(off, "Reboot-Time") {
		t.Fatalf("off: %s", off)
	}

	c := ParseAptConfig(`APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Automatic-Reboot "false";
`)
	var st UnattendedStatus
	st.Effective(c)
	if !st.UpdateLists || !st.Upgrade || st.AutoReboot || len(st.Origins) != 2 || st.SecurityOnly {
		t.Fatalf("effective: %+v", st)
	}
	c.Lists["Unattended-Upgrade::Allowed-Origins"] = c.Lists["Unattended-Upgrade::Allowed-Origins"][1:]
	st.Effective(c)
	if !st.SecurityOnly {
		t.Fatalf("security only: %+v", st)
	}
	if LastRun("2026-10-24 06:01:02,123 INFO Starting unattended upgrades script\nx\n2026-10-25 06:11:12,000 INFO Starting unattended upgrades script\n") != "2026-10-25 06:11:12" {
		t.Fatal("last run")
	}
}

func TestSearchAndPolicy(t *testing.T) {
	l, more := ParseSearch("htop - interactive processes viewer\nbad name - x\nbtop - resource monitor\n")
	if len(l) != 2 || more || l[1].Name != "btop" {
		t.Fatalf("search: %+v", l)
	}
	m := ParsePolicy("htop:\n  Installed: 3.4.1-1\n  Candidate: 3.4.1-2\n  Version table:\n *** 3.4.1-1 500\nbtop:\n  Installed: (none)\n  Candidate: 1.4.0-1\n")
	if m["htop"].Installed != "3.4.1-1" || m["htop"].Candidate != "3.4.1-2" || m["btop"].Installed != "" {
		t.Fatalf("policy: %+v", m)
	}
	for _, bad := range []string{"-o", "a", "x y", "foo$", "(a|b)", "a*"} {
		if ValidTerm(bad) {
			t.Errorf("term %q accepted", bad)
		}
	}
}

func TestCommands(t *testing.T) {
	c := Commands(KindSelected, []string{"openssl", "libssl3t64"}, []string{"libssl3t64"})
	if len(c) != 2 || c[0][0] != AptGet || !slices.Contains(c[0], "--only-upgrade") || !slices.Contains(c[0], "Dpkg::Options::=--force-confold") ||
		c[0][len(c[0])-1] != "libssl3t64" || !slices.Equal(c[1], []string{AptMark, "auto", "libssl3t64"}) {
		t.Fatalf("commands: %q", c)
	}
	if c := Commands(KindDryRun, nil, nil); len(c) != 1 || c[0][0] != UnattendedBin {
		t.Fatalf("dry run: %q", c)
	}
	for _, k := range Kinds {
		if len(Commands(k, []string{"x"}, nil)) != 1 {
			t.Errorf("kind %s has no command", k)
		}
	}
}

type fakeUnits struct {
	started []Unit
	alive   map[string]bool
}

func (f *fakeUnits) Start(_ context.Context, u Unit) error {
	f.started = append(f.started, u)
	f.alive[u.Name] = true
	return nil
}

func (f *fakeUnits) Exists(_ context.Context, unit string) bool { return f.alive[unit] }

func TestRunner(t *testing.T) {
	ctx := context.Background()
	fu := &fakeUnits{alive: map[string]bool{}}
	now := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	r := &Runner{Dir: t.TempDir(), Units: fu, Now: func() time.Time { return now }, Keep: 2}
	if err := r.Init(); err != nil {
		t.Fatal(err)
	}
	j, err := r.Start(ctx, KindUpgrade, nil, nil, "acc")
	if err != nil || j.State != StateRunning || len(fu.started) != 1 || fu.started[0].Name != UnitPrefix+j.ID+".service" {
		t.Fatalf("start: %+v %v", j, err)
	}
	if _, err := r.Start(ctx, KindUpdate, nil, nil, "acc"); err != ErrBusy {
		t.Fatalf("second start: %v", err)
	}
	logPath := fu.started[0].Log
	write := func(s string) {
		f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	write("Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42 (unattended-upgr)\n")
	if g, _ := r.Get(ctx, j.ID); g.Phase != "lock" || !strings.Contains(g.Current, "unattended-upgr") {
		t.Fatalf("lock: %+v", g)
	}
	write("dlstatus:1:42.5:Retrieving file 1 of 2\nGet:1 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 openssl\n")
	if g, _ := r.Get(ctx, j.ID); g.Phase != "download" || g.Percent != 42.5 {
		t.Fatalf("download: %+v", g)
	}
	write("pmstatus:openssl:60:Installing openssl (amd64)\nConfiguration file '/etc/ssl/openssl.cnf'\n ==> Keeping old config file as default.\nW: something odd\n")
	g, _ := r.Get(ctx, j.ID)
	if g.Phase != "install" || g.Percent != 60 || g.Current != "Installing openssl (amd64)" {
		t.Fatalf("install: %+v", g)
	}
	text, next, err := r.Log(j.ID, 0)
	if err != nil || strings.Contains(text, "dlstatus") || strings.Contains(text, "pmstatus") || !strings.Contains(text, "Get:1") {
		t.Fatalf("log: %q %v", text, err)
	}
	write("partial")
	if more, n2, _ := r.Log(j.ID, next); more != "" || n2 != next {
		t.Fatalf("incomplete line returned: %q", more)
	}
	write(" line\n" + ResultMarker + " exit-code exited 100\n")
	fu.alive[UnitPrefix+j.ID+".service"] = false
	g, _ = r.Get(ctx, j.ID)
	if g.State != StateFailed || g.Exit != 100 || g.Result != "exit-code" || g.Ended == nil ||
		!slices.Equal(g.Conffiles, []string{"/etc/ssl/openssl.cnf"}) || !slices.Equal(g.Issues, []string{"W: something odd"}) {
		t.Fatalf("finished: %+v", g)
	}
	if more, _, _ := r.Log(j.ID, next); more != "partial line\n" {
		t.Fatalf("rest: %q", more)
	}

	// A unit that vanished without a result line ends as unknown; the next
	// job may start; old jobs are pruned.
	now = now.Add(time.Minute)
	j2, err := r.Start(ctx, KindUpdate, nil, nil, "acc")
	if err != nil {
		t.Fatal(err)
	}
	fu.alive[UnitPrefix+j2.ID+".service"] = false
	if g, _ := r.Get(ctx, j2.ID); g.State != StateUnknown {
		t.Fatalf("vanished: %+v", g)
	}
	now = now.Add(time.Minute)
	j3, _ := r.Start(ctx, KindUpdate, nil, nil, "acc")
	fu.alive[UnitPrefix+j3.ID+".service"] = false
	list := r.List(ctx)
	if len(list) != 2 || list[0].ID != j3.ID || list[1].ID != j2.ID {
		t.Fatalf("list: %+v", list)
	}
	if _, err := r.Get(ctx, j.ID); err != ErrNotFound {
		t.Fatalf("pruned job: %v", err)
	}
	if _, err := r.Get(ctx, "../x"); err != ErrNotFound {
		t.Fatal("bad id")
	}
	if p := Properties(fu.started[0]); len(p) == 0 {
		t.Fatal("no properties")
	}
}

func TestRebootRequired(t *testing.T) {
	root := t.TempDir()
	if ok, _ := RebootRequired(root); ok {
		t.Fatal("no file")
	}
	_ = os.MkdirAll(filepath.Join(root, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "run/reboot-required"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(root, "run/reboot-required.pkgs"), []byte("linux-base\nlinux-base\nevil;x\n"), 0o644)
	if ok, pkgs := RebootRequired(root); !ok || !slices.Equal(pkgs, []string{"linux-base"}) {
		t.Fatalf("reboot: %v %v", ok, pkgs)
	}
}
