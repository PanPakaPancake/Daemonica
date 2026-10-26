package timehost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hostinger = "127.0.0.1\tlocalhost\n\n127.0.1.1\tubuntu-26.localhost\tubuntu-26\n127.0.1.1\tsrv1166373.hstgr.cloud\tsrv1166373\n127.0.1.1\tdaemonica.404squad.cloud\tdaemonica\n"

func TestRenameHosts(t *testing.T) {
	cases := []struct{ in, old, nw, want string }{
		{"127.0.0.1 localhost\n127.0.1.1 srv1.example.org srv1\n::1 ip6-localhost\n", "srv1", "web2",
			"127.0.0.1 localhost\n127.0.1.1\tweb2.example.org web2\n::1 ip6-localhost\n"},
		{"127.0.0.1 localhost\n127.0.1.1 old other # keep\n", "old", "new",
			"127.0.0.1 localhost\n127.0.1.1\tnew other\t# keep\n"},
		{"127.0.0.1 localhost\n::1 ip6-localhost\n", "srv1", "web2",
			"127.0.0.1 localhost\n127.0.1.1\tweb2\n::1 ip6-localhost\n"},
		{"127.0.1.1 unrelated\n", "srv1", "web2", "127.0.1.1\tunrelated web2\n"},
		// Several 127.0.1.1 lines (Hostinger image): only the line naming
		// the host changes; an unchanged name changes nothing.
		{hostinger, "daemonica", "daemonica", hostinger},
		{hostinger, "daemonica", "web2", strings.Replace(hostinger, "127.0.1.1\tdaemonica.404squad.cloud\tdaemonica", "127.0.1.1\tweb2.404squad.cloud web2", 1)},
		{"127.0.1.1 a\n127.0.1.1 b # x\n", "srv1", "web2", "127.0.1.1 a\n127.0.1.1\tb web2\t# x\n"},
		{"", "", "web2", "127.0.1.1\tweb2\n"},
		{"127.0.1.1   srv1.example.org srv1\n", "srv1", "srv1", "127.0.1.1   srv1.example.org srv1\n"},
	}
	for _, c := range cases {
		if got := RenameHosts(c.in, c.old, c.nw); got != c.want {
			t.Errorf("RenameHosts(%q,%q,%q) = %q, want %q", c.in, c.old, c.nw, got, c.want)
		}
	}
}

func TestCloudInitResets(t *testing.T) {
	root := t.TempDir()
	if CloudInitResets(root) {
		t.Fatal("no cloud-init")
	}
	_ = os.MkdirAll(filepath.Join(root, "etc/cloud/cloud.cfg.d"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/cloud/cloud.cfg"), []byte("preserve_hostname: false\n"), 0o644)
	if !CloudInitResets(root) {
		t.Fatal("cloud-init resets")
	}
	_ = os.WriteFile(filepath.Join(root, "etc/cloud/cloud.cfg.d/99-keep.cfg"), []byte("# x\npreserve_hostname: True\n"), 0o644)
	if CloudInitResets(root) {
		t.Fatal("preserved")
	}
}

func TestCloudInitHostsMode(t *testing.T) {
	root := t.TempDir()
	if CloudInitHostsMode(root) != "" {
		t.Fatal("no cloud-init")
	}
	_ = os.MkdirAll(filepath.Join(root, "etc/cloud/cloud.cfg.d"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/cloud/cloud.cfg"), []byte("manage_etc_hosts: True\npreserve_hostname: false\n"), 0o644)
	if CloudInitHostsMode(root) != HostsTemplate {
		t.Fatal("template")
	}
	_ = os.WriteFile(filepath.Join(root, "etc/cloud/cloud.cfg.d/99-off.cfg"), []byte("manage_etc_hosts: false\n"), 0o644)
	if CloudInitHostsMode(root) != "" {
		t.Fatal("switched off in cloud.cfg.d")
	}
	// The provider's user data (merged config of this boot) wins, as on Hostinger.
	_ = os.MkdirAll(filepath.Join(root, "run/cloud-init"), 0o755)
	_ = os.WriteFile(filepath.Join(root, MergedCloudConfig), []byte(`{"manage_etc_hosts":"localhost","preserve_hostname":true}`), 0o644)
	if CloudInitHostsMode(root) != HostsLocalhost || CloudInitResets(root) {
		t.Fatal("merged config")
	}
}

func TestValid(t *testing.T) {
	for _, h := range []string{"web2", "a", "srv-1", "x0"} {
		if !ValidHostname(h) {
			t.Errorf("%q rejected", h)
		}
	}
	for _, h := range []string{"", "Web", "-a", "a-", "a.b", "a b", "a_b", string(make([]byte, 64))} {
		if ValidHostname(h) {
			t.Errorf("%q accepted", h)
		}
	}
	if !ValidPretty("Timos Server ✓") || ValidPretty("a\nb") {
		t.Error("pretty")
	}
	list := []string{"Europe/Berlin", "Etc/UTC", "America/Argentina/Buenos_Aires"}
	for _, z := range list {
		if !ValidTimezone(z, list) {
			t.Errorf("%q rejected", z)
		}
	}
	for _, z := range []string{"Europe/Paris", "../etc/passwd", "Europe/../Etc/UTC", ""} {
		if ValidTimezone(z, append(list, z)) && z != "Europe/Paris" {
			t.Errorf("%q accepted", z)
		}
	}
	if ValidTimezone("Europe/Paris", list) {
		t.Error("unlisted zone accepted")
	}
}

func TestBootID(t *testing.T) {
	d := t.TempDir()
	_ = os.MkdirAll(filepath.Join(d, "sys/kernel/random"), 0o755)
	_ = os.WriteFile(filepath.Join(d, "sys/kernel/random/boot_id"), []byte("abc\n"), 0o644)
	if BootID(d) != "abc" || BootID(t.TempDir()) != "" {
		t.Fatal("boot id")
	}
}
