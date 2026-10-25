package files

import "testing"

func TestValidPath(t *testing.T) {
	good := []string{"/", "/etc", "/home/a b/c.txt", "/tmp/ünïcode"}
	bad := []string{"", "etc", "/etc/", "/etc/../root", "/a//b", "/a/./b", "/a\x00b", "/\xff"}
	for _, p := range good {
		if !ValidPath(p) {
			t.Errorf("ValidPath(%q) = false", p)
		}
	}
	for _, p := range bad {
		if ValidPath(p) {
			t.Errorf("ValidPath(%q) = true", p)
		}
	}
}

func TestValidName(t *testing.T) {
	good := []string{"a", "a b", ".hidden", "-rf", "ünï.txt", "x;id", "$(id)"}
	bad := []string{"", ".", "..", "a/b", "a\x00", "a\nb", "evil\u202etxt.exe", "\xff", string(make([]byte, 256))}
	for _, n := range good {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range bad {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}

func TestTargetResolve(t *testing.T) {
	if _, n, err := (Target{Dir: "/tmp", Raw: "/w=="}).Resolve(); err != nil || n != "\xff" {
		t.Fatalf("raw: %q %v", n, err)
	}
	for _, tg := range []Target{{Dir: "tmp", Name: "a"}, {Dir: "/tmp", Name: "../etc"}, {Dir: "/tmp", Name: ".."},
		{Dir: "/tmp", Raw: "Li4="}, {Dir: "/tmp", Raw: "YS9i"}, {Dir: "/tmp", Raw: "!!"}, {Dir: "/tmp"}} {
		if _, _, err := tg.Resolve(); err == nil {
			t.Errorf("Resolve(%+v) accepted", tg)
		}
	}
}

func TestBlockedAndProtected(t *testing.T) {
	blocked := []string{"/var/lib/daemonica", "/var/lib/daemonica-helper/accounts.db", "/etc/daemonica",
		"/run/daemonica/helper.sock", "/var/log/daemonica/audit.log", "/var/lib/daemonica/tls/privkey.pem"}
	free := []string{"/var/lib", "/var/lib/apt", "/etc/passwd", "/home/daemonica", "/opt/daemonica", "/var/lib/x/daemonica"}
	for _, p := range blocked {
		if !Blocked(p) {
			t.Errorf("Blocked(%q) = false", p)
		}
	}
	for _, p := range free {
		if Blocked(p) {
			t.Errorf("Blocked(%q) = true", p)
		}
	}
	for _, p := range []string{"/", "/etc", "/var", "/var/lib", "/run", "/var/lib/daemonica"} {
		if !ContainsBlocked(p) {
			t.Errorf("ContainsBlocked(%q) = false", p)
		}
	}
	for _, p := range []string{"/home", "/var/lib/apt", "/etc/ssh", "/tmp/x"} {
		if ContainsBlocked(p) {
			t.Errorf("ContainsBlocked(%q) = true", p)
		}
	}
	if !Protected("/") || !Protected("/home") || Protected("/home/alice") {
		t.Error("Protected")
	}
	if !Virtual("/proc/1/mem") || !Virtual("/sys") || Virtual("/procs") {
		t.Error("Virtual")
	}
}

func TestSensitive(t *testing.T) {
	for _, p := range []string{"/etc/shadow", "/etc/gshadow-", "/etc/ssh/ssh_host_ed25519_key", "/home/a/.ssh/id_ed25519", "/root/.ssh/id_rsa"} {
		if !Sensitive(p) {
			t.Errorf("Sensitive(%q) = false", p)
		}
	}
	for _, p := range []string{"/etc/passwd", "/etc/ssh/ssh_host_ed25519_key.pub", "/home/a/.ssh/id_ed25519.pub", "/home/a/.ssh/authorized_keys"} {
		if Sensitive(p) {
			t.Errorf("Sensitive(%q) = true", p)
		}
	}
}

func TestDisplay(t *testing.T) {
	cases := map[string]string{
		"plain.txt":          "plain.txt",
		"a\nb":               `a\u{000A}b`,
		"evil\u202etxt.exe":  `evil\u{202E}txt.exe`,
		"bad\xffbyte":        `bad\xffbyte`,
		"\x1b[31mred\x1b[0m": `\u{001B}[31mred\u{001B}[0m`,
	}
	for in, want := range cases {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModeString(t *testing.T) {
	cases := map[uint32]string{0o755: "rwxr-xr-x", 0o640: "rw-r-----", 0o4755: "rwsr-xr-x", 0o2644: "rw-r-Sr--", 0o1777: "rwxrwxrwt", 0o1776: "rwxrwxrwT"}
	for m, want := range cases {
		if got := ModeString(m); got != want {
			t.Errorf("ModeString(%o) = %q, want %q", m, got, want)
		}
	}
}

func FuzzTargetResolve(f *testing.F) {
	f.Add("/tmp", "a", "")
	f.Add("/", "..", "")
	f.Add("/tmp", "", "Li4=")
	f.Fuzz(func(t *testing.T, dir, name, raw string) {
		d, n, err := (Target{Dir: dir, Name: name, Raw: raw}).Resolve()
		if err != nil {
			return
		}
		if !ValidPath(d) || n == "" || n == "." || n == ".." || len(n) > MaxName {
			t.Fatalf("accepted %q %q", d, n)
		}
		for i := 0; i < len(n); i++ {
			if n[i] == '/' || n[i] == 0 {
				t.Fatalf("accepted separator in %q", n)
			}
		}
	})
}

func TestParseNumFilter(t *testing.T) {
	for _, c := range []struct {
		in      string
		yes, no []float64
		bad     bool
	}{
		{in: "10", yes: []float64{10, 11}, no: []float64{9}},
		{in: ">1K", yes: []float64{1025}, no: []float64{1024}},
		{in: "<= 1,5 MiB", yes: []float64{1.5 * (1 << 20)}, no: []float64{1.5*(1<<20) + 1}},
		{in: "=0", yes: []float64{0}, no: []float64{1}},
		{in: "1K-2K", yes: []float64{1024, 2048}, no: []float64{1023, 2049}},
		{in: "2K-1K", bad: true},
		{in: ">x", bad: true},
		{in: "-5", bad: true},
	} {
		f, err := ParseNumFilter(c.in)
		if (err != nil) != c.bad {
			t.Fatalf("%q: err %v", c.in, err)
		}
		for _, v := range c.yes {
			if !f.Match(v) {
				t.Errorf("%q should match %v", c.in, v)
			}
		}
		for _, v := range c.no {
			if f.Match(v) {
				t.Errorf("%q should not match %v", c.in, v)
			}
		}
	}
	if f, err := ParseNumFilter(" "); f != nil || err != nil {
		t.Fatal("empty filter")
	}
}

func TestModeMatches(t *testing.T) {
	if !ModeMatches(0o644, "644") || !ModeMatches(0o644, "0644") || ModeMatches(0o640, "644") {
		t.Fatal("octal")
	}
	if !ModeMatches(0o4755, "rws") || !ModeMatches(0o755, "R-X") || ModeMatches(0o700, "r-x") || !ModeMatches(0o700, "") {
		t.Fatal("ls form")
	}
}
