//go:build linux

package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

func code(err error) string {
	var oe *worker.OpError
	if errors.As(err, &oe) {
		return oe.Code
	}
	if err != nil {
		return "other:" + err.Error()
	}
	return ""
}

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func chunked(data []byte, end bool) io.Reader {
	var b bytes.Buffer
	_, _ = rpc.ChunkWriter{W: &b}.Write(data)
	if end {
		_ = rpc.WriteChunk(&b, nil)
	}
	return &rpc.ChunkReader{R: &b}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestListSortFilterPage(t *testing.T) {
	d := tempDir(t)
	for _, n := range []string{"b.txt", "A.txt", ".hidden", "c.log"} {
		if err := os.WriteFile(filepath.Join(d, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Mkdir(filepath.Join(d, "zdir"), 0o700)
	_ = os.Symlink("zdir", filepath.Join(d, "link"))
	_ = os.WriteFile(filepath.Join(d, "bad\xffname"), nil, 0o600)

	r, err := List(ListArgs{Path: d})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range r.Entries {
		names = append(names, e.Name)
	}
	got := strings.Join(names, ",")
	// directories (incl. symlinks to directories) first, then case-insensitive names.
	if got != `link,zdir,A.txt,b.txt,bad\xffname,c.log` {
		t.Fatalf("order: %s", got)
	}
	if r.Entries[0].Type != "symlink" || r.Entries[0].TargetType != "dir" || r.Entries[0].Target != "zdir" {
		t.Fatalf("symlink entry: %+v", r.Entries[0])
	}
	if r.Entries[4].Raw == "" {
		t.Fatal("non-UTF-8 name without raw")
	}
	r, _ = List(ListArgs{Path: d, Hidden: true, Filter: "TXT", Limit: 1, Offset: 1})
	if r.Total != 2 || len(r.Entries) != 1 || r.Entries[0].Name != "b.txt" {
		t.Fatalf("filter/page: %+v", r)
	}
	r, _ = List(ListArgs{Path: d, DirsOnly: true})
	if r.Total != 2 {
		t.Fatalf("dirs only: %d", r.Total)
	}
	if _, err := List(ListArgs{Path: d + "/../x"}); code(err) != CodeInvalid {
		t.Fatalf("unclean path: %v", err)
	}
}

func TestCreateRenameRawDelete(t *testing.T) {
	d := tempDir(t)
	if _, err := Create(CreateArgs{Dir: d, Name: "new.txt", Kind: "file"}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(d, "new.txt"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("default mode %o", fi.Mode().Perm())
	}
	if _, err := Create(CreateArgs{Dir: d, Name: "new.txt", Kind: "file"}); code(err) != CodeExists {
		t.Fatalf("duplicate create: %v", err)
	}
	if _, err := Create(CreateArgs{Dir: d, Name: "a\nb", Kind: "file"}); code(err) != CodeInvalid {
		t.Fatalf("control char name: %v", err)
	}
	if _, err := Rename(RenameArgs{Target: Target{Dir: d, Name: "new.txt"}, NewName: "renamed.txt"}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(d, "other"), nil, 0o600)
	if _, err := Rename(RenameArgs{Target: Target{Dir: d, Name: "renamed.txt"}, NewName: "other"}); code(err) != CodeExists {
		t.Fatalf("rename must not replace: %v", err)
	}
	// Raw (non-UTF-8) names can be renamed and deleted.
	_ = os.WriteFile(filepath.Join(d, "x\xff"), nil, 0o600)
	if _, err := Rename(RenameArgs{Target: Target{Dir: d, Raw: "eP8="}, NewName: "fixed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(DeleteArgs{Target: Target{Dir: d, Name: "fixed"}}); err != nil {
		t.Fatal(err)
	}
	// Non-empty directory needs Recursive.
	_ = os.MkdirAll(filepath.Join(d, "tree/a/b"), 0o700)
	_ = os.WriteFile(filepath.Join(d, "tree/a/b/f"), []byte("x"), 0o600)
	_ = os.Symlink("/etc", filepath.Join(d, "tree/a/etc"))
	if _, err := Delete(DeleteArgs{Target: Target{Dir: d, Name: "tree"}}); code(err) != CodeNotEmpty {
		t.Fatalf("non-recursive: %v", err)
	}
	r, err := Delete(DeleteArgs{Target: Target{Dir: d, Name: "tree"}, Recursive: true})
	if err != nil || r.Entries < 5 {
		t.Fatalf("recursive: %+v %v", r, err)
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatal("recursive delete followed a symlink!")
	}
}

func TestWriteSymlinkedDirRefused(t *testing.T) {
	d := tempDir(t)
	_ = os.Mkdir(filepath.Join(d, "real"), 0o700)
	_ = os.Symlink("real", filepath.Join(d, "alias"))
	if _, err := Create(CreateArgs{Dir: d + "/alias", Name: "f", Kind: "file"}); code(err) != CodeSymlink {
		t.Fatalf("write through symlinked dir: %v", err)
	}
	// Reading through it is fine and reports the canonical path.
	r, err := List(ListArgs{Path: d + "/alias"})
	if err != nil || r.Path != d+"/real" {
		t.Fatalf("list via symlink: %+v %v", r, err)
	}
	// Final symlinks are never chmod'ed or written.
	_ = os.WriteFile(filepath.Join(d, "real/t"), []byte("x"), 0o600)
	_ = os.Symlink("real/t", filepath.Join(d, "tl"))
	if _, err := Chmod(ChmodArgs{Target: Target{Dir: d, Name: "tl"}, Mode: 0o777}); code(err) != CodeSymlink {
		t.Fatalf("chmod symlink: %v", err)
	}
	if _, err := Write(WriteArgs{Target: Target{Dir: d, Name: "tl"}, ExpectedHash: sum([]byte("x"))}, chunked([]byte("y"), true)); code(err) != CodeSymlink {
		t.Fatalf("write symlink: %v", err)
	}
}

func TestEditorRoundTrip(t *testing.T) {
	d := tempDir(t)
	p := filepath.Join(d, "conf")
	orig := []byte("a = 1\r\nb = 2\r\n")
	_ = os.WriteFile(p, orig, 0o640)
	_ = os.Chmod(p, 0o604)

	var out bytes.Buffer
	if _, err := Read(ReadArgs{Target: Target{Dir: d, Name: "conf"}, Edit: true}, &out); err != nil {
		t.Fatal(err)
	}
	metaRaw, err := rpc.ReadChunk(&out)
	if err != nil {
		t.Fatal(err)
	}
	var meta ReadMeta
	_ = json.Unmarshal(metaRaw, &meta)
	content, _ := io.ReadAll(&rpc.ChunkReader{R: &out})
	if meta.Hash != sum(orig) || !bytes.Equal(content, orig) || meta.Binary {
		t.Fatalf("read: %+v %q", meta, content)
	}
	// Stale hash → conflict, file unchanged.
	if _, err := Write(WriteArgs{Target: Target{Dir: d, Name: "conf"}, ExpectedHash: sum([]byte("old"))}, chunked([]byte("new"), true)); code(err) != CodeConflict {
		t.Fatalf("conflict: %v", err)
	}
	// Aborted stream → nothing written.
	if _, err := Write(WriteArgs{Target: Target{Dir: d, Name: "conf"}, ExpectedHash: meta.Hash}, chunked([]byte("new"), false)); code(err) != CodeAborted {
		t.Fatalf("aborted: %v", err)
	}
	res, err := Write(WriteArgs{Target: Target{Dir: d, Name: "conf"}, ExpectedHash: meta.Hash}, chunked([]byte("c = 3\r\n"), true))
	if err != nil || !res.Atomic {
		t.Fatalf("write: %+v %v", res, err)
	}
	fi, _ := os.Stat(p)
	got, _ := os.ReadFile(p)
	if fi.Mode().Perm() != 0o604 || string(got) != "c = 3\r\n" {
		t.Fatalf("after write: %o %q", fi.Mode().Perm(), got)
	}
	// Binary content is not offered to the editor.
	_ = os.WriteFile(filepath.Join(d, "bin"), []byte{0x7f, 'E', 'L', 'F', 0}, 0o600)
	out.Reset()
	if _, err := Read(ReadArgs{Target: Target{Dir: d, Name: "bin"}, Edit: true}, &out); err != nil {
		t.Fatal(err)
	}
	metaRaw, _ = rpc.ReadChunk(&out)
	_ = json.Unmarshal(metaRaw, &meta)
	if !meta.Binary || meta.Hash != "" {
		t.Fatalf("binary: %+v", meta)
	}
	// Hard-linked files are rewritten in place (link kept).
	_ = os.Link(p, filepath.Join(d, "hard"))
	cur, _ := os.ReadFile(p)
	if res, err := Write(WriteArgs{Target: Target{Dir: d, Name: "conf"}, ExpectedHash: sum(cur)}, chunked([]byte("d"), true)); err != nil || res.Atomic {
		t.Fatalf("hardlink write: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "hard")); string(b) != "d" {
		t.Fatalf("hard link lost: %q", b)
	}
}

func TestUpload(t *testing.T) {
	d := tempDir(t)
	data := bytes.Repeat([]byte("0123456789"), 100_000) // 1 MB, several chunks
	res, err := Upload(UploadArgs{Dir: d, Name: "up.bin", Size: int64(len(data)), Max: 2 << 20}, chunked(data, true))
	if err != nil || res.Size != int64(len(data)) || res.SHA256 != sum(data) {
		t.Fatalf("upload: %+v %v", res, err)
	}
	fi, _ := os.Stat(filepath.Join(d, "up.bin"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if _, err := Upload(UploadArgs{Dir: d, Name: "up.bin", Size: 1, Max: 10}, chunked([]byte("x"), true)); code(err) != CodeExists {
		t.Fatalf("no overwrite: %v", err)
	}
	if _, err := Upload(UploadArgs{Dir: d, Name: "up.bin", Overwrite: true, Size: 1, Max: 10}, chunked([]byte("x"), true)); err != nil {
		t.Fatal(err)
	}
	// Too large and aborted uploads leave nothing behind.
	if _, err := Upload(UploadArgs{Dir: d, Name: "big", Size: 1, Max: 10}, chunked(make([]byte, 11), true)); code(err) != CodeTooLarge {
		t.Fatalf("too large: %v", err)
	}
	if _, err := Upload(UploadArgs{Dir: d, Name: "cut", Size: 5, Max: 10}, chunked([]byte("abc"), false)); code(err) != CodeAborted {
		t.Fatalf("aborted: %v", err)
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
	if _, err := CheckUpload(UploadArgs{Dir: d, Name: "huge", Size: 1 << 62, Max: 1 << 62}); code(err) != CodeNoSpace {
		t.Fatalf("space preflight: %v", err)
	}
}

func TestTransfer(t *testing.T) {
	d := tempDir(t)
	_ = os.MkdirAll(filepath.Join(d, "src/sub"), 0o750)
	_ = os.WriteFile(filepath.Join(d, "src/sub/f"), []byte("data"), 0o604)
	_ = os.Symlink("sub/f", filepath.Join(d, "src/l"))
	_ = os.Mkdir(filepath.Join(d, "dst"), 0o700)
	if _, err := Transfer(TransferArgs{Target: Target{Dir: d, Name: "src"}, DestDir: d + "/src/sub", Copy: true}); code(err) != CodeInvalid {
		t.Fatalf("copy into itself: %v", err)
	}
	r, err := Transfer(TransferArgs{Target: Target{Dir: d, Name: "src"}, DestDir: d + "/dst", Copy: true})
	if err != nil || r.Bytes != 4 {
		t.Fatalf("copy: %+v %v", r, err)
	}
	fi, _ := os.Stat(filepath.Join(d, "dst/src/sub/f"))
	if fi.Mode().Perm() != 0o604 {
		t.Fatalf("copied mode %o", fi.Mode().Perm())
	}
	if l, _ := os.Readlink(filepath.Join(d, "dst/src/l")); l != "sub/f" {
		t.Fatalf("symlink copied as %q", l)
	}
	if _, err := Transfer(TransferArgs{Target: Target{Dir: d, Name: "src"}, DestDir: d + "/dst"}); code(err) != CodeExists {
		t.Fatalf("move onto existing: %v", err)
	}
	if _, err := Transfer(TransferArgs{Target: Target{Dir: d, Name: "src"}, DestDir: d + "/dst", NewName: "moved"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, "src")); !os.IsNotExist(err) {
		t.Fatal("source still present after move")
	}
}

func TestRulesOnCanonicalPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// Blocked: a daemonica* directory below /run, reached via a symlink elsewhere.
	blk := "/run/daemonica-fstest"
	if err := os.MkdirAll(blk, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(blk) }()
	_ = os.WriteFile(blk+"/secret", []byte("s"), 0o600)
	d := tempDir(t)
	_ = os.Symlink(blk, filepath.Join(d, "innocent"))
	_ = os.Symlink(blk+"/secret", filepath.Join(d, "innocent-file"))
	if _, err := List(ListArgs{Path: d + "/innocent"}); code(err) != CodeBlocked {
		t.Fatalf("list blocked via symlink: %v", err)
	}
	var out bytes.Buffer
	if _, err := Read(ReadArgs{Target: Target{Dir: d, Name: "innocent-file"}, Edit: true}, &out); code(err) != CodeBlocked {
		t.Fatalf("read blocked via symlink: %v", err)
	}
	if _, err := Delete(DeleteArgs{Target: Target{Dir: "/run", Name: "daemonica-fstest"}, Recursive: true}); code(err) != CodeBlocked {
		t.Fatalf("delete blocked: %v", err)
	}
	if _, err := Delete(DeleteArgs{Target: Target{Dir: "/", Name: "etc"}, Recursive: true}); code(err) != CodeProtected {
		t.Fatalf("delete /etc: %v", err)
	}
	// Sensitive: needs the helper's permit.
	if _, err := Read(ReadArgs{Target: Target{Dir: "/etc", Name: "shadow"}, Edit: true}, &out); code(err) != CodeSensitive {
		t.Fatalf("shadow without permit: %v", err)
	}
	out.Reset()
	if _, err := Read(ReadArgs{Target: Target{Dir: "/etc", Name: "shadow"}, Edit: true, Guard: Guard{SensitiveOK: true}}, &out); err != nil {
		t.Fatalf("shadow with permit: %v", err)
	}
	// Virtual files: editor read allowed, download refused, devices never.
	if _, err := Read(ReadArgs{Target: Target{Dir: "/proc", Name: "uptime"}}, io.Discard); code(err) != CodeVirtual {
		t.Fatalf("download /proc: %v", err)
	}
	if _, err := Read(ReadArgs{Target: Target{Dir: "/dev", Name: "zero"}, Edit: true}, io.Discard); code(err) != CodeNotRegular {
		t.Fatalf("device: %v", err)
	}
}

func TestRangeRead(t *testing.T) {
	d := tempDir(t)
	_ = os.WriteFile(filepath.Join(d, "f"), []byte("0123456789"), 0o600)
	var out bytes.Buffer
	if _, err := Read(ReadArgs{Target: Target{Dir: d, Name: "f"}, Offset: 2, Length: 3}, &out); err != nil {
		t.Fatal(err)
	}
	_, _ = rpc.ReadChunk(&out)
	b, _ := io.ReadAll(&rpc.ChunkReader{R: &out})
	if string(b) != "234" {
		t.Fatalf("range: %q", b)
	}
	if _, err := Read(ReadArgs{Target: Target{Dir: d, Name: "f"}, Offset: 11}, io.Discard); code(err) != CodeRange {
		t.Fatalf("bad range: %v", err)
	}
}
