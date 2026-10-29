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

func TestRotationContinuesChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p, "")
	if err != nil {
		t.Fatal(err)
	}
	l.MaxSize, l.Keep = 2000, 2
	for i := 0; i < 40; i++ {
		if _, err := l.Append(Event{Action: "test.op", Result: ResultOK, Target: strings.Repeat("x", 50)}); err != nil {
			t.Fatal(err)
		}
	}
	head := l.LastHash()
	_ = l.Close()
	files := Files(p, 2)
	if len(files) != 3 {
		t.Fatalf("files %v", files)
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Fatal("more files kept than Keep")
	}
	// The oldest file was rotated away: its successor's anchor is accepted and reported.
	res := VerifyAll(p, 2)
	if !res.OK || res.LastHash != head || res.Files != 3 || res.Anchor == "" {
		t.Fatalf("verify all: %+v", res)
	}
	// Queries see the rotated files too, newest first.
	rc, err := OpenAll(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	page, err := Query(rc, Filter{Limit: MaxQueryLimit})
	_ = rc.Close()
	if err != nil || len(page.Events) != res.Records || page.Events[0].Hash != head {
		t.Fatalf("query over rotated files: %d events, err %v", len(page.Events), err)
	}
	// Tampering in a rotated file is found and located.
	b, _ := os.ReadFile(files[1])
	if err := os.WriteFile(files[1], bytes.Replace(b, []byte(`"test.op"`), []byte(`"test.xx"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := VerifyAll(p, 2); res.OK || res.File != files[1] || res.BadLine != 1 {
		t.Fatalf("tampering not located: %+v", res)
	}
}

func TestVerifyAllSingleFileNeedsGenesis(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p, "sha256:"+strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Event{Action: "test.op", Result: ResultOK}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	// Without rotated files the log must start at GenesisHash (a cut head is detected).
	if res := VerifyAll(p, 2); res.OK {
		t.Fatalf("foreign anchor accepted: %+v", res)
	}
}

func TestAppendOnlyRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	l, err := Open(p, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range Files(p, 2) {
			_ = setAppendOnlyPath(f, false)
		}
	})
	if err := l.EnableAppendOnly(); err != nil {
		_ = l.Close()
		t.Skipf("chattr +a not available here: %v", err)
	}
	l.MaxSize, l.Keep = 1500, 2
	for i := 0; i < 30; i++ {
		if _, err := l.Append(Event{Action: "test.op", Result: ResultOK, Target: strings.Repeat("y", 50)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	for _, f := range Files(p, 2) {
		if err := os.WriteFile(f, []byte("{}\n"), 0o600); err == nil {
			t.Fatalf("%s could be overwritten", f)
		}
	}
	if res := VerifyAll(p, 2); !res.OK || res.Files != 3 {
		t.Fatalf("verify: %+v", res)
	}
}
