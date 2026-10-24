package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainAppendVerifyAndResume(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append(Event{Action: "test.op", Result: ResultOK, Target: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	head := l.LastHash()
	_ = l.Close()

	// Resume continues the chain.
	l2, err := Open(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if l2.LastHash() != head {
		t.Fatal("resume lost chain head")
	}
	if _, err := l2.Append(Event{Action: "test.op2", Result: ResultDenied}); err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()

	data, _ := os.ReadFile(p)
	res := Verify(bytes.NewReader(data), "")
	if !res.OK || res.Records != 6 {
		t.Fatalf("verify failed: %+v", res)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(p, "")
	for _, a := range []string{"a.one", "a.two", "a.three"} {
		_, _ = l.Append(Event{Action: a, Result: ResultOK})
	}
	_ = l.Close()
	data, _ := os.ReadFile(p)

	modified := strings.Replace(string(data), `"action":"a.two"`, `"action":"a.TWO"`, 1)
	if r := Verify(strings.NewReader(modified), ""); r.OK || r.BadLine != 2 {
		t.Fatalf("modification not detected: %+v", r)
	}

	lines := strings.SplitAfter(string(data), "\n")
	deleted := lines[0] + lines[2]
	if r := Verify(strings.NewReader(deleted), ""); r.OK {
		t.Fatal("deletion not detected")
	}
}

func TestSanitizeStripsControlChars(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(p, "")
	ev, err := l.Append(Event{Action: "fs.write", Result: ResultOK, Target: "file\n{\"forged\":1}\x1b[31m"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(ev.Target, "\n\x1b") {
		t.Fatalf("control chars not stripped: %q", ev.Target)
	}
}

func TestULIDShape(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(p, "")
	ev, _ := l.Append(Event{Action: "x.y", Result: ResultOK})
	if len(ev.EventID) != 26 {
		t.Fatalf("ulid len %d: %s", len(ev.EventID), ev.EventID)
	}
}
