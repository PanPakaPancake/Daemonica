package disks

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const lsblkNew = `{"blockdevices": [
 {"name":"vda","path":"/dev/vda","type":"disk","size":274877906944,"fstype":null,"fsver":null,"uuid":null,"partuuid":null,"label":null,"mountpoints":[null],
  "model":"QEMU HARDDISK","serial":"abc","ro":false,"rm":false,"rota":true,"tran":null,"fsused":null,"fsavail":null,
  "children":[{"name":"vda1","path":"/dev/vda1","type":"part","size":1048576,"fstype":"ext4","fsver":"1.0","uuid":"1111-2222","partuuid":"p-1","label":"root",
   "mountpoints":["/","/var/snap"],"model":null,"serial":null,"ro":false,"rm":false,"rota":true,"tran":null,"fsused":"1000","fsavail":2000}]}]}`

const lsblkOld = `{"blockdevices": [{"name":"sda","path":"/dev/sda","type":"disk","size":"500","mountpoint":"/data","ro":"0","rm":"1","rota":"1"}]}`

func TestLsblk(t *testing.T) {
	bs, err := ParseLsblk([]byte(lsblkNew))
	if err != nil || len(bs) != 1 || len(bs[0].Children) != 1 {
		t.Fatalf("parse: %v %+v", err, bs)
	}
	d, p := bs[0], bs[0].Children[0]
	if d.Size != 274877906944 || d.Model != "QEMU HARDDISK" || !d.Rotational || len(d.Mountpoints) != 0 {
		t.Errorf("disk: %+v", d)
	}
	if p.UUID != "1111-2222" || !slices.Equal(p.Mountpoints, []string{"/", "/var/snap"}) || p.FSUsed != 1000 || p.FSAvail != 2000 || p.Label != "root" {
		t.Errorf("part: %+v", p)
	}
	if f := Flatten(bs); len(f) != 2 || f[1].Name != "vda1" || f[0].Children != nil {
		t.Errorf("flatten: %+v", f)
	}
	old, err := ParseLsblk([]byte(lsblkOld))
	if err != nil || old[0].Size != 500 || !old[0].Removable || old[0].ReadOnly || !slices.Equal(old[0].Mountpoints, []string{"/data"}) {
		t.Fatalf("old format: %v %+v", err, old)
	}
	if _, err := ParseLsblk([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
}

const fstabText = `# /etc/fstab: static file system information.
UUID=1111-2222	/	ext4	errors=remount-ro	0	1
# data disk
/dev/sdb1   /srv/my\040data   xfs   defaults   0   2
/swap.img	none	swap	sw	0	0
bogus
`

func TestFstabRoundTrip(t *testing.T) {
	f := ParseFstab(fstabText)
	if len(f.Entries) != 3 || len(f.Errors) != 1 {
		t.Fatalf("parse: %+v", f)
	}
	if f.Entries[1].File != "/srv/my data" || f.Entries[1].Line != 4 || f.Entries[0].Pass != 1 || f.Entries[2].Type != "swap" {
		t.Fatalf("entries: %+v", f.Entries)
	}
	if got := Render(f, f.Entries); got != fstabText {
		t.Fatalf("unchanged render differs:\n%s", got)
	}
	e := slices.Clone(f.Entries)
	e[1].Options = "defaults,nofail,noexec"
	e = slices.Delete(e, 2, 3)
	e = append(e, Entry{Spec: "UUID=3333", File: "/backup", Type: "ext4", Options: "nofail", Pass: 2})
	got := Render(f, e)
	want := "# /etc/fstab: static file system information.\nUUID=1111-2222\t/\text4\terrors=remount-ro\t0\t1\n# data disk\n" +
		"/dev/sdb1\t/srv/my\\040data\txfs\tdefaults,nofail,noexec\t0\t2\nbogus\n\n# Added by Daemonica\nUUID=3333\t/backup\text4\tnofail\t0\t2\n"
	if got != want {
		t.Fatalf("render:\n%q\nwant\n%q", got, want)
	}
	if back := ParseFstab(got); back.Entries[1].File != "/srv/my data" {
		t.Fatal("escape round trip")
	}
}

func codes(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, strconv.Itoa(p.Index)+":"+p.Field+":"+p.Code)
	}
	return out
}

func TestValidate(t *testing.T) {
	orig := ParseFstab(fstabText).Entries
	ok := []Entry{orig[0], {Spec: "UUID=3333", File: "/backup", Type: "ext4", Options: "nofail,noexec,nosuid,nodev", Pass: 2}, {Spec: "tmpfs", File: "/run/x", Type: "tmpfs", Options: "size=10%,mode=1777"}}
	if ps := Validate(ok, orig); len(ps) != 0 {
		t.Fatalf("valid entries: %v", codes(ps))
	}
	bad := []Entry{
		{Spec: "UUID=1 2;rm", File: "/a", Type: "ext4"},
		{Spec: "/dev/sdc1", File: "relative", Type: "ext4", Options: "nofail"},
		{Spec: "/dev/sdc2", File: "/b", Type: "EXT4!", Options: "a b"},
		{Spec: "/dev/sdc3", File: "/c/../d", Type: "ext4", Freq: 3, Pass: 9, Options: "nofail"},
		{Spec: "UUID=4", File: "/srv", Type: "ext4"},
		{Spec: "UUID=5", File: "/srv", Type: "ext4", Options: "nofail"},
	}
	got := codes(Validate(bad, orig))
	for _, w := range []string{"0:spec:invalid", "1:file:invalid", "1:spec:prefer_uuid", "2:type:invalid", "2:options:invalid", "3:file:invalid",
		"3:freq:invalid", "3:pass:invalid", "4:options:nofail_recommended", "5:file:duplicate", "-1::root_missing"} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if !Blocking(Validate(bad, orig)) || Blocking([]Problem{{Code: "prefer_uuid", Warning: true}}) {
		t.Fatal("blocking")
	}
}

func TestParseVerify(t *testing.T) {
	out := "findmnt: /tmp/x/fstab: parse error at line 3 -- ignored\n\n1 parse error, 2 errors, 1 warning\n/mnt/nope\n" +
		"   [E] unreachable on boot required target: No such file or directory\n   [ ] target exists\n/\n   [W] cannot detect on-disk filesystem type (Operation not permitted)\n"
	ps := ParseVerify(out, "/tmp/x/fstab")
	if len(ps) != 3 || ps[0].Msg != "findmnt: fstab: parse error at line 3 -- ignored" || ps[0].Warning ||
		ps[1].Msg != "/mnt/nope: unreachable on boot required target: No such file or directory" || ps[1].Warning || !ps[2].Warning || !strings.HasPrefix(ps[2].Msg, "/: ") {
		t.Fatalf("verify: %+v", ps)
	}
	if ps := ParseVerify("\n0 parse errors, 0 errors, 0 warnings\nSuccess, no errors or warnings detected\n", "f"); len(ps) != 0 {
		t.Fatalf("clean: %+v", ps)
	}
}

func TestUnitNameAndCritical(t *testing.T) {
	for in, want := range map[string]string{"/": "-.mount", "/srv/data": "srv-data.mount", "/mnt/my-disk": `mnt-my\x2ddisk.mount`,
		"/srv/my data": `srv-my\x20data.mount`, "/.hidden/x": `\x2ehidden-x.mount`, "/home/": "home.mount"} {
		if got := UnitName(in); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
	for _, c := range []string{"/", "/boot/efi", "/var", "/run/user/1000", "/proc", "/sys/fs/cgroup"} {
		if !Critical(c) {
			t.Errorf("%s not critical", c)
		}
	}
	for _, c := range []string{"/srv/data", "/mnt/backup", "/runner"} {
		if Critical(c) {
			t.Errorf("%s critical", c)
		}
	}
}

func TestUsersAndMounted(t *testing.T) {
	proc := t.TempDir()
	mk := func(pid, comm, cwd string, fds ...string) {
		d := filepath.Join(proc, pid)
		_ = os.MkdirAll(filepath.Join(d, "fd"), 0o755)
		_ = os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.Symlink(cwd, filepath.Join(d, "cwd"))
		_ = os.Symlink("/", filepath.Join(d, "root"))
		for i, f := range fds {
			_ = os.Symlink(f, filepath.Join(d, "fd", strconv.Itoa(i)))
		}
	}
	mk("10", "bash", "/srv/data/x")
	mk("11", "rsync", "/root", "/dev/null", "/srv/data/file")
	mk("12", "nginx", "/srv/database")
	_ = os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	_ = os.WriteFile(filepath.Join(proc, "self/mountinfo"), []byte("36 1 8:1 / / rw - ext4 /dev/vda1 rw\n40 36 8:17 / /srv/my\\040data rw - xfs /dev/sdb1 rw\n"), 0o644)
	u := Users(proc, "/srv/data", 10)
	if len(u) != 2 || u[0].Comm != "bash" || u[0].Why != "cwd" || u[1].Why != "file" {
		t.Fatalf("users: %+v", u)
	}
	if !Mounted(proc, "/srv/my data") || Mounted(proc, "/srv/data") || !Mounted(proc, "/") {
		t.Fatal("mounted")
	}
}
