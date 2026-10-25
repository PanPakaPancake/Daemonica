//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/helper"
	"github.com/PanPakaPancake/daemonica/internal/policy"
)

// TestEditorValidationAndVersions runs the real validators (sshd -t,
// visudo -c) and the /etc version store against the VM's configuration.
// Nothing is reloaded; the test files are removed afterwards.
func TestEditorValidationAndVersions(t *testing.T) {
	e := newFSEnv(t, 16)
	adm := e.grant(policy.RoleAdmin, true)
	if code := e.call(adm, "fs.root_enable", nil, nil); code != "" {
		t.Fatalf("root_enable: %s", code)
	}
	write := func(dir, name, hash, content string, create, force bool) helper.SaveResult {
		t.Helper()
		p := map[string]any{"dir": dir, "name": name, "expected_hash": hash, "as_root": true}
		if create {
			p["create"] = true
		}
		if force {
			p["force"] = true
		}
		var res helper.SaveResult
		if err := e.c.Upload(context.Background(), "fs.write", adm, "", p, bytes.NewReader([]byte(content)), nil, &res); err != nil {
			t.Fatalf("write %s/%s: %v", dir, name, err)
		}
		return res
	}
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			return "<" + err.Error() + ">"
		}
		return string(b)
	}

	t.Run("sshd", func(t *testing.T) {
		if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
			t.Skip("sshd not installed")
		}
		dir, name := "/etc/ssh/sshd_config.d", "99-daemonica-itest.conf"
		p := filepath.Join(dir, name)
		_ = os.Remove(p)
		t.Cleanup(func() { _ = os.Remove(p) })

		// A broken new file is removed again.
		res := write(dir, name, "", "DaemonicaBogusOption yes\n", true, false)
		if res.Saved || res.Validation == nil || !res.Validation.RolledBack || res.Validation.Output == "" {
			t.Fatalf("broken new file: %+v %+v", res, res.Validation)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("broken new file kept: %v", err)
		}
		// A valid file passes the check.
		res = write(dir, name, "", "# daemonica itest\n", true, false)
		if !res.Saved || res.Validation == nil || !res.Validation.OK {
			t.Fatalf("valid new file: %+v %+v", res, res.Validation)
		}
		good := res.Hash
		// A broken edit is rolled back to the previous content.
		res = write(dir, name, good, "DaemonicaBogusOption yes\n", false, false)
		if res.Saved || res.Validation == nil || !res.Validation.RolledBack {
			t.Fatalf("broken edit: %+v %+v", res, res.Validation)
		}
		if got := read(p); got != "# daemonica itest\n" {
			t.Fatalf("not rolled back: %q", got)
		}
		// A valid edit keeps the previous version.
		res = write(dir, name, good, "# daemonica itest 2\n", false, false)
		if !res.Saved || res.Version == "" {
			t.Fatalf("valid edit: %+v", res)
		}
		var vs struct {
			Versions []helper.Version `json:"versions"`
		}
		if code := e.call(adm, "fs.versions", map[string]any{"dir": dir, "name": name, "as_root": true}, &vs); code != "" || len(vs.Versions) != 1 {
			t.Fatalf("versions: %s %+v", code, vs)
		}
		var meta map[string]any
		ds, err := e.c.Download(context.Background(), "fs.version_read", adm, "", map[string]any{"dir": dir, "name": name, "id": vs.Versions[0].ID, "as_root": true}, &meta)
		if err != nil {
			t.Fatalf("version_read: %v", err)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(ds)
		_ = ds.Finish(nil)
		_ = ds.Close()
		if buf.String() != "# daemonica itest\n" {
			t.Fatalf("version content %q", buf.String())
		}
		// Only someone who can read the file sees its history.
		op := e.grant(policy.RoleOperator, false)
		if code := e.call(op, "fs.versions", map[string]any{"dir": "/etc", "name": "sudoers"}, nil); code != "permission_denied" {
			t.Fatalf("versions without read access: %s", code)
		}
	})

	t.Run("nginx", func(t *testing.T) {
		if _, err := os.Stat("/usr/sbin/nginx"); err != nil {
			t.Skip("nginx not installed")
		}
		dir, name := "/etc/nginx/conf.d", "daemonica-itest.conf"
		if _, err := os.Stat(dir); err != nil {
			t.Skip("no /etc/nginx/conf.d")
		}
		p := filepath.Join(dir, name)
		_ = os.Remove(p)
		t.Cleanup(func() { _ = os.Remove(p) })
		res := write(dir, name, "", "daemonica_bogus_directive on;\n", true, false)
		if res.Saved || res.Validation == nil || !res.Validation.RolledBack || res.Validation.Tool != "nginx -t" {
			t.Fatalf("broken nginx snippet: %+v %+v", res, res.Validation)
		}
		// "Save anyway" keeps it.
		res = write(dir, name, "", "daemonica_bogus_directive on;\n", true, true)
		if !res.Saved || res.Validation == nil || res.Validation.OK {
			t.Fatalf("forced nginx snippet: %+v %+v", res, res.Validation)
		}
		if res = write(dir, name, res.Hash, "# daemonica itest\n", false, false); !res.Saved || !res.Validation.OK {
			t.Fatalf("valid nginx snippet: %+v %+v", res, res.Validation)
		}
	})

	t.Run("sudoers", func(t *testing.T) {
		if _, err := os.Stat("/usr/sbin/visudo"); err != nil {
			t.Skip("visudo not installed")
		}
		dir, name := "/etc/sudoers.d", "daemonica-itest"
		p := filepath.Join(dir, name)
		_ = os.Remove(p)
		t.Cleanup(func() { _ = os.Remove(p) })
		for _, force := range []bool{false, true} {
			res := write(dir, name, "", "this is not a sudoers line\n", true, force)
			if res.Saved || res.Validation == nil || !res.Validation.Blocking || res.Validation.OK {
				t.Fatalf("broken sudoers (force=%v): %+v %+v", force, res, res.Validation)
			}
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatalf("broken sudoers written (force=%v)", force)
			}
		}
		if res := write(dir, name, "", "# daemonica itest\n", true, false); !res.Saved {
			t.Fatalf("valid sudoers: %+v", res)
		}
		if got := read(p); got != "# daemonica itest\n" {
			t.Fatalf("sudoers content %q", got)
		}
	})
}
