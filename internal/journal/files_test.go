package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/log/apt"), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := range 20 {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", i%3))
		if i%2 == 0 {
			b.WriteString(" sshd \x1b[31mFAIL\x1b[0m")
		}
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(root, "var/log/auth.log"), []byte(b.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "var/log/syslog")); err != nil {
		t.Fatal(err)
	}

	files := ListFiles(root)
	if len(files) != 1 || files[0].Path != "/var/log/auth.log" {
		t.Fatalf("files %+v", files)
	}
	r, err := ReadFile(root, FileQuery{Path: "/var/log/auth.log", Lines: 3, Grep: "SSHD"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Lines) != 3 || !r.Truncated || strings.ContainsRune(strings.Join(r.Lines, ""), 0x1b) {
		t.Fatalf("result %+v", r)
	}
	for _, bad := range []FileQuery{{Path: "/etc/shadow"}, {Path: "/var/log/../../etc/shadow"}, {Path: "/var/log/syslog"}, {Path: "/var/log/auth.log", Grep: "a\nb"}} {
		if _, err := ReadFile(root, bad); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	all, _ := ReadFile(root, FileQuery{Path: "/var/log/auth.log"})
	if len(all.Lines) != 20 || all.Truncated || all.Lines[19] != "line x" {
		t.Fatalf("all %+v", all)
	}
}
