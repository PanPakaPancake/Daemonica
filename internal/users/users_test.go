package users

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) DB {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/passwd":     "root:x:0:0:root:/root:/bin/bash\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\npancake:x:1000:1000:Pan Cake:/home/pancake:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
		"etc/group":      "root:x:0:\nsudo:x:27:pancake\nadm:x:4:pancake,bob\npancake:x:1000:\nbob:x:1001:\n",
		"etc/shadow":     "root:*:20000:0:99999:7:::\npancake:!:20000:0:99999:7:::\nbob:$y$abc:0:0:90:7::20000:\n",
		"etc/login.defs": "UID_MIN 1000\nUID_MAX 60000\nGID_MIN 1000\nGID_MAX 60000\n",
		"etc/shells":     "# comment\n/bin/sh\n/bin/bash\n",
	}
	for p, c := range files {
		full := filepath.Join(root, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o644)
	}
	return DB{Root: root}
}

func TestList(t *testing.T) {
	us, gs, err := fixture(t).List(time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC))
	if err != nil || len(us) != 5 || len(gs) != 5 {
		t.Fatalf("%v %d %d", err, len(us), len(gs))
	}
	by := map[string]User{}
	for _, u := range us {
		by[u.Name] = u
	}
	if !by["sshd"].System || by["pancake"].System || by["root"].System || !by["nobody"].System {
		t.Fatal("system classification")
	}
	p := by["pancake"]
	if !p.Sudo || !p.Locked || !p.NoPassword || strings.Join(p.Groups, ",") != "pancake,sudo,adm" {
		t.Fatalf("pancake %+v", p)
	}
	b := by["bob"]
	if b.Sudo || !b.MustChange || b.PwMaxDays != 90 || !b.Expired || b.ExpiresOn != "2024-10-04" {
		t.Fatalf("bob %+v", b)
	}
}

func TestCreateArgs(t *testing.T) {
	d := fixture(t)
	gs := map[string]bool{"adm": true, "sudo": true}
	args, err := d.CreateArgs(CreateSpec{Name: "alice", Gecos: "Alice A", Groups: []string{"adm"}, CreateHome: true}, gs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args, " "); got != "--user-group --create-home --comment Alice A --shell /bin/bash --groups adm -- alice" {
		t.Fatalf("args %q", got)
	}
	bad := []CreateSpec{
		{Name: "-oroot"}, {Name: "a;b"}, {Name: "Root"},
		{Name: "x", Gecos: "a:b"}, {Name: "x", Gecos: "evil\n"},
		{Name: "x", Shell: "/bin/evil"}, {Name: "x", Home: "../etc"}, {Name: "x", Home: "/home/a b"},
		{Name: "x", Groups: []string{"wheel"}}, {Name: "x", Groups: []string{"adm,root"}},
	}
	for _, b := range bad {
		if _, err := d.CreateArgs(b, gs); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}

func TestShellsAndDates(t *testing.T) {
	sh := fixture(t).Shells()
	if strings.Join(sh, ",") != "/bin/sh,/bin/bash,/usr/sbin/nologin" {
		t.Fatal(sh)
	}
	if _, err := ParseDate("2026-13-01"); err == nil {
		t.Fatal("bad date accepted")
	}
	if v, err := ParseDate(""); err != nil || v != "" {
		t.Fatal("empty date")
	}
}
