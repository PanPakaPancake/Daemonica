package helper

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/jobs"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/scripts"
)

func scriptTarball(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, data := range files {
		_ = tw.WriteHeader(&tar.Header{Name: "o-r-x/" + name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(data))
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestScriptOpsRoles(t *testing.T) {
	const c1, c2 = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	head := c1
	trees := map[string][]byte{
		c1: scriptTarball(map[string]string{"backup.sh": "#!/bin/sh\necho 1\n"}),
		c2: scriptTarball(map[string]string{"backup.sh": "#!/bin/sh\necho 2 > /tmp/x\n"}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ref, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/commits/"); ok {
			if ref == "HEAD" {
				ref = head
			}
			if _, ok := trees[ref]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"sha":%q,"commit":{"message":"m","author":{"name":"a","date":"2026-10-25T00:00:00Z"}}}`, ref)
			return
		}
		if sha, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/tarball/"); ok && trees[sha] != nil {
			_, _ = w.Write(trees[sha])
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	e := newAuthEnv(t)
	g, sa, _ := setupAdmin(t, e)
	dir := t.TempDir()
	lib := &scripts.Library{Root: filepath.Join(dir, "lib"), StateFile: filepath.Join(dir, "scripts.json"), GitHub: &scripts.GitHub{API: srv.URL, HTTP: srv.Client()}}
	if err := lib.Init(); err != nil {
		t.Fatal(err)
	}
	var jobList []jobs.Job
	(&ScriptOps{L: lib, Jobs: func() ([]jobs.Job, error) { return jobList, nil }}).Register(e.web.Ops)
	const ip = "198.51.100.7"

	// Preview: input and download problems are data.
	r := e.callFrom(ip, "scripts.preview", g, map[string]any{"spec": map[string]any{"repo": "https://evil.example/x"}})
	mustOK(t, r, "preview bad repo")
	var sc ScriptCandidate
	_ = json.Unmarshal(r.Result, &sc)
	if sc.Error == nil || sc.Error.Field != "repo" {
		t.Fatalf("bad repo: %+v", sc)
	}
	r = e.callFrom(ip, "scripts.preview", g, map[string]any{"spec": map[string]any{"repo": "o/r", "ref": "gone"}})
	sc = ScriptCandidate{}
	_ = json.Unmarshal(r.Result, &sc)
	if sc.Error == nil || sc.Error.Field != "fetch" || sc.Error.Code != scripts.FetchNotFound {
		t.Fatalf("unknown ref: %+v", sc)
	}
	r = e.callFrom(ip, "scripts.preview", g, map[string]any{"spec": map[string]any{"repo": "o/r", "token": "secret"}})
	mustOK(t, r, "preview")
	sc = ScriptCandidate{}
	_ = json.Unmarshal(r.Result, &sc)
	if sc.Candidate == nil || sc.Candidate.Commit.SHA != c1 || sc.Spec.ID != "r" || sc.Spec.Token != "" || len(sc.Candidate.Changes) != 1 {
		t.Fatalf("preview: %+v", sc)
	}

	// Changing the library needs step-up.
	add := map[string]any{"spec": map[string]any{"id": "r", "repo": "o/r", "token": "secret"}, "commit": c1}
	if c := code(e.callFrom(ip, "scripts.add", g, add)); c != rpc.CodeStepUpNeeded {
		t.Fatalf("add without step-up: %s", c)
	}
	if c := code(e.callFrom(ip, "scripts.save", g, map[string]any{"name": "x.sh", "content": "echo"})); c != rpc.CodeStepUpNeeded {
		t.Fatalf("save without step-up: %s", c)
	}
	gs := stepUp(t, e, sa, g)
	r = e.callFrom(ip, "scripts.add", gs, add)
	mustOK(t, r, "add")
	if strings.Contains(string(r.Result), "secret") {
		t.Fatalf("token leaked: %s", r.Result)
	}
	mustOK(t, e.callFrom(ip, "scripts.save", gs, map[string]any{"name": "x.sh", "content": "#!/bin/sh\necho\n", "exec": true}), "save")
	if c := code(e.callFrom(ip, "scripts.save", gs, map[string]any{"name": "../x.sh", "content": "echo"})); c != rpc.CodeValidation {
		t.Fatalf("traversal: %s", c)
	}

	// Check offers the new commit with a diff and the jobs using a file.
	jobList = []jobs.Job{{ID: "nightly", Script: lib.Abs("r", "backup.sh")}, {ID: "tidy", Program: lib.Abs(scripts.LocalID, "x.sh")}}
	head = c2
	r = e.callFrom(ip, "scripts.check", gs, map[string]any{"id": "r"})
	mustOK(t, r, "check")
	sc = ScriptCandidate{}
	_ = json.Unmarshal(r.Result, &sc)
	if sc.Candidate == nil || sc.Candidate.Current || len(sc.Candidate.Changes) != 1 || sc.Candidate.Changes[0].UsedBy[0] != "nightly" ||
		!strings.Contains(sc.Candidate.Changes[0].Diff, "+echo 2 > /tmp/x") {
		t.Fatalf("check: %+v", sc.Candidate)
	}
	mustOK(t, e.callFrom(ip, "scripts.update", gs, map[string]any{"id": "r", "commit": c2}), "update")
	if src, _ := lib.Source("r"); src.Commit.SHA != c2 || src.Token != "secret" {
		t.Fatalf("after update: %+v", src)
	}

	// In use: neither the source nor the local script can be removed.
	if c := code(e.callFrom(ip, "scripts.remove", gs, map[string]any{"id": "r"})); c != rpc.CodeConflict {
		t.Fatalf("remove in use: %s", c)
	}
	if c := code(e.callFrom(ip, "scripts.delete", gs, map[string]any{"name": "x.sh"})); c != rpc.CodeConflict {
		t.Fatalf("delete in use: %s", c)
	}

	// Read-only sees the library but cannot fetch or change it; operators neither.
	ro, _ := e.web.Grants.Issue(policy.Subject{AccountID: "ro", Role: policy.RoleReadOnly, LinuxUser: "carol", LinuxUID: 1002}, time.Now())
	r = e.callFrom(ip, "scripts.list", ro, nil)
	mustOK(t, r, "list")
	var list ScriptList
	_ = json.Unmarshal(r.Result, &list)
	if len(list.Files) != 2 || len(list.Sources) != 1 || !list.Sources[0].HasToken || strings.Contains(string(r.Result), "secret") {
		t.Fatalf("list: %s", r.Result)
	}
	r = e.callFrom(ip, "scripts.read", ro, map[string]any{"source": "r", "path": "backup.sh"})
	mustOK(t, r, "read")
	var content ScriptContent
	_ = json.Unmarshal(r.Result, &content)
	if !content.Text || !strings.Contains(content.Content, "echo 2") {
		t.Fatalf("read: %+v", content)
	}
	op, _ := e.web.Grants.Issue(policy.Subject{AccountID: "op", Role: policy.RoleOperator, LinuxUser: "erin", LinuxUID: 1004}, time.Now())
	for _, g := range []string{ro, op} {
		if c := code(e.callFrom(ip, "scripts.check", g, map[string]any{"id": "r"})); c != rpc.CodeForbidden {
			t.Fatalf("check by %s: %s", g, c)
		}
		if c := code(e.callFrom(ip, "scripts.delete", g, map[string]any{"name": "x.sh"})); c != rpc.CodeForbidden {
			t.Fatalf("delete by %s: %s", g, c)
		}
	}
	jobList = nil
	mustOK(t, e.callFrom(ip, "scripts.remove", gs, map[string]any{"id": "r"}), "remove")
	mustOK(t, e.callFrom(ip, "scripts.delete", gs, map[string]any{"name": "x.sh"}), "delete")
}
