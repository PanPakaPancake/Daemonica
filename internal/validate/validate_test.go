package validate

import "testing"

// injection payloads that must be rejected by every identifier validator.
var payloads = []string{
	"", "; rm -rf /", "$(id)", "`id`", "a\nb", "a b", "../etc", "-rf", "--help",
	"a\x00b", "%n", "a|b", "a&b", "a>b", "\u202eevil",
}

func TestLinuxUser(t *testing.T) {
	for _, ok := range []string{"alice", "_svc", "bob-2", "a"} {
		if LinuxUser(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range append(payloads, "Root", "1user", "averyveryveryveryverylongusername1") {
		if LinuxUser(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestInterface(t *testing.T) {
	for _, ok := range []string{"eth0", "enp0s3", "br-lan", "eth0.100", "wg0"} {
		if Interface(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range append(payloads, "averylonginterfacename") {
		if Interface(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestUnit(t *testing.T) {
	for _, ok := range []string{"nginx.service", "getty@tty1.service", "daemonica-job-backup.timer"} {
		if Unit(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range append(payloads, "nginx", "a/b.service", "x.service\n[Service]", "-x.service") {
		if Unit(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDomain(t *testing.T) {
	for _, ok := range []string{"dash.example.org", "a-b.example.co.uk"} {
		if Domain(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range append(payloads, "localhost", "Dash.Example.org", "example.org.", "-a.example.org", "a..b") {
		if Domain(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestNoControl(t *testing.T) {
	if NoControl("hello world – ok", 100) != nil {
		t.Fatal("rejected plain text")
	}
	for _, bad := range []string{"a\nb", "a\x1b[31m", "a\x00", string([]byte{0xff})} {
		if NoControl(bad, 100) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func FuzzUnit(f *testing.F) {
	f.Add("nginx.service")
	f.Fuzz(func(t *testing.T, s string) {
		if Unit(s) == nil {
			for _, r := range s {
				if r == '\n' || r == '/' || r == ' ' || r == '%' {
					t.Fatalf("accepted unsafe unit %q", s)
				}
			}
		}
	})
}
