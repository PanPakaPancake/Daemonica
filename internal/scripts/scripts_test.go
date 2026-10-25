package scripts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type tfile struct {
	data string
	mode int64
	link string
}

func tarball(t *testing.T, files map[string]tfile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "abc"}})
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "o-r-abc/", Mode: 0o755})
	for name, f := range files {
		h := &tar.Header{Name: "o-r-abc/" + name, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg}
		if f.link != "" {
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, f.link, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if f.link == "" {
			_, _ = tw.Write([]byte(f.data))
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestValidation(t *testing.T) {
	for _, p := range []string{"a.sh", "dir/b-c_d@e+f.py", "x/y/z"} {
		if !ValidPath(p) {
			t.Errorf("rejected %q", p)
		}
	}
	for _, p := range []string{"", "/a", "a/", "a//b", "../a", "a/..", ".hidden", "a/.git/x", "a b", "a;b", "%n", "a\nb", "ä"} {
		if ValidPath(p) {
			t.Errorf("accepted %q", p)
		}
	}
	for in, want := range map[string]string{"o/r": "o/r", "https://github.com/o/r.git": "o/r", "github.com/o/r/": "o/r"} {
		if got, ok := NormalizeRepo(in); !ok || got != want {
			t.Errorf("repo %q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"o", "o/r/x", "https://evil.example/o/r", "o/r?x", "-o/r"} {
		if _, ok := NormalizeRepo(in); ok {
			t.Errorf("repo accepted %q", in)
		}
	}
	for _, r := range []string{"", "main", "v1.2", "feature/x"} {
		if !ValidRef(r) {
			t.Errorf("ref rejected %q", r)
		}
	}
	for _, r := range []string{"a..b", "/x", "x/", "a b", "x?y"} {
		if ValidRef(r) {
			t.Errorf("ref accepted %q", r)
		}
	}
	if _, f := (Spec{Repo: "o/r", Token: "a b"}).Normalize(); f != "token" {
		t.Errorf("token: %q", f)
	}
	if _, f := (Spec{Repo: "o/r", ID: "local"}).Normalize(); f != "id" {
		t.Errorf("id local: %q", f)
	}
}

func TestParseTarball(t *testing.T) {
	data := tarball(t, map[string]tfile{
		"README.md":          {data: "hi", mode: 0o644},
		"bin/backup.sh":      {data: "#!/bin/sh\necho ok\n", mode: 0o755},
		"bin/lib/util.py":    {data: "print(1)\n", mode: 0o644},
		"bin/.secret":        {data: "x", mode: 0o644},
		".github/ci.yml":     {data: "x", mode: 0o644},
		"bin/link":           {link: "/etc/shadow"},
		"bin/has space.sh":   {data: "x", mode: 0o755},
		"bin/big.bin":        {data: strings.Repeat("x", MaxFileSize+1), mode: 0o644},
		"other/elsewhere.sh": {data: "x", mode: 0o755},
	})
	tr, skipped, err := ParseTarball(bytes.NewReader(data), "bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 || !tr["backup.sh"].Exec || tr["lib/util.py"].Exec || string(tr["backup.sh"].Data) != "#!/bin/sh\necho ok\n" {
		t.Fatalf("tree: %v", tr)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Path] = s.Reason
	}
	if reasons["link"] != "symlink" || reasons["has space.sh"] != "name" || reasons["big.bin"] != "size" || len(reasons) != 3 {
		t.Fatalf("skipped: %v", skipped)
	}
	all, _, err := ParseTarball(bytes.NewReader(data), "")
	if err != nil || len(all) != 4 {
		t.Fatalf("whole repo: %v %v", all, err)
	}
}

const sha1 = "1111111111111111111111111111111111111111"
const sha2 = "2222222222222222222222222222222222222222"

// fakeGitHub serves two commits of o/r; "main" points to head.
type fakeGitHub struct {
	head    string
	trees   map[string][]byte
	limited bool
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("User-Agent") == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if f.limited {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.URL.Path == "/repos/priv/r/commits/HEAD" {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"sha":%q,"commit":{"message":"private","author":{"name":"a","date":"2026-10-01T00:00:00Z"}}}`, sha1)
		return
	}
	if ref, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/commits/"); ok {
		sha := ref
		if ref == "HEAD" || ref == "main" {
			sha = f.head
		}
		if _, ok := f.trees[sha]; !ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		_, _ = fmt.Fprintf(w, `{"sha":%q,"commit":{"message":"commit %s\n\nbody","author":{"name":"Timo","date":"2026-10-25T12:00:00Z"}}}`, sha, sha[:4])
		return
	}
	if sha, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/tarball/"); ok {
		if b, ok := f.trees[sha]; ok {
			_, _ = w.Write(b)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func newLib(t *testing.T) (*Library, *fakeGitHub) {
	t.Helper()
	fg := &fakeGitHub{head: sha1, trees: map[string][]byte{
		sha1: tarball(t, map[string]tfile{"backup.sh": {data: "#!/bin/sh\necho v1\n", mode: 0o755}, "old.sh": {data: "x\n", mode: 0o755}}),
		sha2: tarball(t, map[string]tfile{"backup.sh": {data: "#!/bin/sh\necho v2\n", mode: 0o755}, "new.py": {data: "print(2)\n", mode: 0o644}}),
	}}
	srv := httptest.NewServer(fg)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	l := &Library{Root: filepath.Join(dir, "lib"), StateFile: filepath.Join(dir, "scripts.json"), GitHub: &GitHub{API: srv.URL, HTTP: srv.Client()}}
	if err := l.Init(); err != nil {
		t.Fatal(err)
	}
	return l, fg
}

func TestGitHub(t *testing.T) {
	l, fg := newLib(t)
	ctx := context.Background()
	c, err := l.GitHub.Resolve(ctx, "o/r", "main", "")
	if err != nil || c.SHA != sha1 || c.Message != "commit 1111" || c.Author != "Timo" {
		t.Fatalf("resolve: %+v %v", c, err)
	}
	var fe *FetchError
	if _, err := l.GitHub.Resolve(ctx, "o/r", "nope", ""); !errors.As(err, &fe) || fe.Code != FetchNotFound {
		t.Fatalf("unknown ref: %v", err)
	}
	if _, err := l.GitHub.Resolve(ctx, "priv/r", "", ""); !errors.As(err, &fe) || fe.Code != FetchNotFound {
		t.Fatalf("private without token: %v", err)
	}
	if c, err := l.GitHub.Resolve(ctx, "priv/r", "", "tok"); err != nil || c.SHA != sha1 {
		t.Fatalf("private with token: %+v %v", c, err)
	}
	tr, _, err := l.GitHub.Tree(ctx, "o/r", sha2, "", "")
	if err != nil || len(tr) != 2 {
		t.Fatalf("tree: %v %v", tr, err)
	}
	fg.limited = true
	if _, err := l.GitHub.Resolve(ctx, "o/r", "", ""); !errors.As(err, &fe) || fe.Code != FetchRateLimited {
		t.Fatalf("rate limit: %v", err)
	}
}

func TestLibraryLifecycle(t *testing.T) {
	old := syscall.Umask(0o077) // like the helper unit
	defer syscall.Umask(old)
	l, fg := newLib(t)
	ctx := context.Background()
	spec, f := Spec{ID: "ops", Repo: "https://github.com/o/r"}.Normalize()
	if f != "" {
		t.Fatal(f)
	}
	c1, _ := l.GitHub.Resolve(ctx, spec.Repo, spec.Ref, "")
	t1, _, _ := l.GitHub.Tree(ctx, spec.Repo, c1.SHA, "", "")
	if _, err := l.Add(spec, c1, t1, "adm"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Add(spec, c1, t1, "adm"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	// World-readable despite the umask, so jobs of every user can run it.
	for p, want := range map[string]os.FileMode{l.Root: 0o755, l.SourceDir("ops"): 0o755, l.Abs("ops", "backup.sh"): 0o755} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}

	if _, err := l.SaveLocal("cleanup.sh", []byte("#!/bin/bash\nrm -f /tmp/x\n"), true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := l.SaveLocal("cleanup.sh", []byte("x"), true, ""); !errors.Is(err, ErrExists) {
		t.Fatalf("create over existing: %v", err)
	}
	if _, err := l.SaveLocal("cleanup.sh", []byte("x"), true, "deadbeef"); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	for _, n := range []string{"../evil", "a/b", ".x", "a b"} {
		if _, err := l.SaveLocal(n, []byte("x"), false, ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("name %q: %v", n, err)
		}
	}
	if _, err := l.SaveLocal("bin", []byte("\x00"), false, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("binary: %v", err)
	}
	b, h, err := l.Read(LocalID, "cleanup.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.SaveLocal("cleanup.sh", append(b, "echo done\n"...), false, h); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(l.Abs(LocalID, "cleanup.sh")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("local mode %v", fi.Mode())
	}
	files, err := l.Files()
	if err != nil || len(files) != 3 || files[0].Source != LocalID || files[0].Shebang != "#!/bin/bash" {
		t.Fatalf("files: %+v %v", files, err)
	}

	// Update: diff against the installed tree, then swap.
	fg.head = sha2
	c2, _ := l.GitHub.Resolve(ctx, "o/r", "", "")
	t2, _, _ := l.GitHub.Tree(ctx, "o/r", c2.SHA, "", "")
	cur, _ := l.ReadTree("ops")
	ch := Compare(cur, t2)
	got := map[string]string{}
	for _, c := range ch {
		got[c.Path] = c.Status
	}
	if got["backup.sh"] != "modified" || got["old.sh"] != "removed" || got["new.py"] != "added" || len(got) != 3 {
		t.Fatalf("changes: %+v", ch)
	}
	if !strings.Contains(ch[0].Diff, "-echo v1\n+echo v2") {
		t.Fatalf("diff: %q", ch[0].Diff)
	}
	src, err := l.Update("ops", c2, t2, "adm")
	if err != nil || src.Commit.SHA != sha2 {
		t.Fatalf("update: %+v %v", src, err)
	}
	if _, err := os.Stat(l.Abs("ops", "old.sh")); err == nil {
		t.Fatal("removed file still installed")
	}
	if ents, _ := os.ReadDir(l.Root); len(ents) != 2 {
		t.Fatalf("leftovers in root: %v", ents)
	}
	if err := l.RemoveSource("ops"); err != nil {
		t.Fatal(err)
	}
	if srcs, _ := l.Sources(); len(srcs) != 0 {
		t.Fatalf("sources: %v", srcs)
	}
	if err := l.DeleteLocal("cleanup.sh"); err != nil {
		t.Fatal(err)
	}
	if err := l.DeleteLocal("cleanup.sh"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestCompareBudget(t *testing.T) {
	big := strings.Repeat("<line>\n", 120_000)
	ch := Compare(nil, Tree{"a": {Data: []byte(big)}, "b": {Data: []byte("x\n")}, "c": {Data: []byte{0, 1}}})
	if !ch[0].Omitted || ch[0].Diff != "" || ch[1].Diff == "" || !ch[2].Binary {
		t.Fatalf("%+v", ch)
	}
}
