package sshkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
)

func wire(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out
}

func mpint(b *big.Int) []byte {
	v := b.Bytes()
	if len(v) > 0 && v[0]&0x80 != 0 {
		v = append([]byte{0}, v...)
	}
	return v
}

func ed25519Line(comment string) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire([]byte("ssh-ed25519"), pub)) + " " + comment
}

func rsaLine(bits int) string {
	k, _ := rsa.GenerateKey(rand.Reader, bits)
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(wire([]byte("ssh-rsa"), mpint(big.NewInt(int64(k.E))), mpint(k.N))) + " r@h"
}

func ecdsaLine() string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pt := elliptic.Marshal(elliptic.P256(), k.X, k.Y) //nolint:staticcheck // test fixture encoding
	return "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(wire([]byte("ecdsa-sha2-nistp256"), []byte("nistp256"), pt))
}

func TestParseValidKeys(t *testing.T) {
	for _, l := range []string{ed25519Line("pancake@laptop"), rsaLine(3072), ecdsaLine()} {
		k, err := Parse(l)
		if err != nil {
			t.Fatalf("%s: %v", l[:20], err)
		}
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") || len(k.Fingerprint) != 50 {
			t.Fatalf("fingerprint %q", k.Fingerprint)
		}
	}
	k, _ := Parse(ed25519Line("a b c"))
	if k.Comment != "a b c" || k.Bits != 256 {
		t.Fatalf("%+v", k)
	}
}

func TestParseRejects(t *testing.T) {
	ed := ed25519Line("x")
	blob := strings.Fields(ed)[1]
	cases := map[string]string{
		"weak rsa":       rsaLine(2048),
		"dss":            "ssh-dss AAAAB3NzaC1kc3MAAACBAP= x",
		"type mismatch":  "ssh-rsa " + blob,
		"bad base64":     "ssh-ed25519 !!!notbase64",
		"private key":    "-----BEGIN OPENSSH PRIVATE KEY-----",
		"newline inject": ed + "\nssh-ed25519 " + blob + " evil",
		"control char":   ed + "\x1b[31m",
		"unknown option": `bogus-opt ` + ed,
		"option inject":  `command="x",no-pty,evil ` + ed,
		"from injection": `from="1.2.3.4 ssh-ed25519" ` + ed,
		"truncated blob": "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire([]byte("ssh-ed25519"), []byte("short"))),
		"empty":          "   ",
	}
	for name, l := range cases {
		if _, err := Parse(l); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestOptions(t *testing.T) {
	ed := ed25519Line("c")
	k, err := Parse(`restrict,from="10.0.0.0/8,192.168.1.*",command="/usr/bin/rsync --server -e \"x\"" ` + ed)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Options) != 3 || k.Options[0] != "restrict" {
		t.Fatalf("options %q", k.Options)
	}
	k2, err := k.WithOptions([]string{"no-port-forwarding", `from="203.0.113.7"`})
	if err != nil || !strings.HasPrefix(k2.Raw, `no-port-forwarding,from="203.0.113.7" ssh-ed25519 `) {
		t.Fatalf("%v %q", err, k2.Raw)
	}
	if _, err := k.WithOptions([]string{`command="a" ssh-rsa x"`}); err == nil {
		t.Fatal("unescaped inner quote accepted")
	}
	if _, err := k.WithOptions([]string{`command="x\"`}); err == nil {
		t.Fatal("trailing backslash accepted")
	}
	if _, err := k.WithOptions([]string{"from=\"1.2.3.4\nevil\""}); err == nil {
		t.Fatal("newline in option accepted")
	}
}

func TestFileRoundTrip(t *testing.T) {
	a, b := ed25519Line("a"), ed25519Line("b")
	content := "# my keys\n" + a + "\nssh-dss AAAA legacy\n\n" + b + "\n"
	f, invalid := ParseFile(content)
	if len(f.Keys) != 2 || len(invalid) != 1 || invalid[0] != 3 {
		t.Fatalf("keys=%d invalid=%v", len(f.Keys), invalid)
	}
	if f.String() != content {
		t.Fatalf("round trip changed content:\n%q", f.String())
	}
	c, _ := Parse(ed25519Line("c"))
	if f.Has(c) {
		t.Fatal("has")
	}
	f.Add(c)
	if !f.Remove(f.Keys[0].Fingerprint) {
		t.Fatal("remove")
	}
	out := f.String()
	if strings.Contains(out, " a\n") || !strings.Contains(out, "# my keys") || !strings.Contains(out, "ssh-dss AAAA legacy") || !strings.Contains(out, " c\n") {
		t.Fatalf("unexpected file:\n%s", out)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(ed25519Line("x"))
	f.Add(`restrict,command="a b" ssh-ed25519 AAAA c`)
	f.Fuzz(func(t *testing.T, s string) {
		k, err := Parse(s)
		if err == nil && strings.ContainsAny(k.Raw, "\n\r\x00") {
			t.Fatalf("accepted line renders with newline: %q", k.Raw)
		}
	})
}
