package sysinfo

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T, files map[string]string) FS {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return FS{Root: root}
}

func TestCPUAndLoadAndMem(t *testing.T) {
	f := fixture(t, map[string]string{
		"proc/stat":    "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nbtime 1700000000\n",
		"proc/loadavg": "0.50 0.25 0.10 1/123 4567\n",
		"proc/meminfo": "MemTotal:       8000000 kB\nMemFree:        1000000 kB\nMemAvailable:   6000000 kB\nBuffers:          100000 kB\nCached:          2000000 kB\nSwapTotal:      1000000 kB\nSwapFree:        750000 kB\n",
		"proc/uptime":  "3600.25 7000.00\n",
	})
	a, n, err := f.CPUStat()
	if err != nil || n != 2 || a.Total() != 1000 {
		t.Fatalf("cpu %+v n=%d err=%v", a, n, err)
	}
	b := a
	b.User += 50
	b.Idle += 50
	if p := CPUPercent(a, b); p != 50 {
		t.Fatalf("cpu pct %v", p)
	}
	if CPUPercent(b, a) != 0 {
		t.Fatal("counter wrap must yield 0")
	}
	l, _ := f.LoadAvg()
	if l.One != 0.5 || l.Fifteen != 0.1 {
		t.Fatalf("load %+v", l)
	}
	m, _ := f.MemInfo()
	if m.Total != 8000000*1024 || m.Used != 2000000*1024 || m.SwapUsed != 250000*1024 {
		t.Fatalf("mem %+v", m)
	}
	up, _ := f.Uptime()
	if up < time.Hour || up > time.Hour+time.Second {
		t.Fatalf("uptime %v", up)
	}
	if f.BootTime().Unix() != 1700000000 {
		t.Fatal("btime")
	}
}

func TestOSReleaseAndReboot(t *testing.T) {
	f := fixture(t, map[string]string{
		"etc/os-release":               "PRETTY_NAME=\"Ubuntu 26.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"26.04\"\n",
		"var/run/reboot-required":      "*** System restart required ***\n",
		"var/run/reboot-required.pkgs": "linux-image-7.0\nlinux-image-7.0\nlibc6\n",
	})
	p, id, v := f.OSRelease()
	if p != "Ubuntu 26.04.1 LTS" || id != "ubuntu" || v != "26.04" {
		t.Fatal(p, id, v)
	}
	r, pkgs := f.RebootRequired()
	if !r || len(pkgs) != 2 {
		t.Fatalf("reboot %v %v", r, pkgs)
	}
}

func TestMountsFiltersPseudoAndComputes(t *testing.T) {
	f := fixture(t, map[string]string{
		"proc/self/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\ntmpfs /tmp tmpfs rw 0 0\ntmpfs /run/user/0 tmpfs rw 0 0\n/dev/sdb1 /mnt/my\\040disk ext4 ro 0 0\n/dev/loop0 /snap/core/1 squashfs ro 0 0\n",
	})
	stat := func(p string, st *syscall.Statfs_t) error {
		st.Bsize, st.Blocks, st.Bfree, st.Bavail, st.Files, st.Ffree = 4096, 1000, 400, 300, 100, 25
		return nil
	}
	ms, err := f.Mounts(stat)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range ms {
		names = append(names, m.Mountpoint)
	}
	if strings.Join(names, ",") != "/,/mnt/my disk,/tmp" {
		t.Fatalf("mounts %v", names)
	}
	m := ms[0]
	if m.Used != 600*4096 || int(m.UsedPct) != 66 || m.InodesUsed != 75 || int(m.InodesPct) != 75 {
		t.Fatalf("usage %+v", m)
	}
	if !ms[1].ReadOnly {
		t.Fatal("ro flag")
	}
}

func TestProcessesParsing(t *testing.T) {
	f := fixture(t, map[string]string{
		"proc/stat":         "cpu  1 0 0 0 0 0 0 0\nbtime 1700000000\n",
		"etc/passwd":        "root:x:0:0::/root:/bin/bash\npancake:x:1000:1000::/home/pancake:/bin/bash\n",
		"proc/1/stat":       "1 (systemd) S 0 1 1 0 -1 4194560 0 0 0 0 10 5 0 0 20 0 1 0 100 0 0",
		"proc/1/status":     "Name:\tsystemd\nUid:\t0\t0\t0\t0\n",
		"proc/1/statm":      "100 10 0 0 0 0 0",
		"proc/1/cmdline":    "/sbin/init\x00splash\x00",
		"proc/42/stat":      "42 (evil) name\x1b[31m) R 1 42 42 0 -1 0 0 0 0 0 200 100 0 0 20 0 3 0 500 0 0",
		"proc/42/status":    "Name:\tevil\nUid:\t1000\t1000\t1000\t1000\n",
		"proc/42/statm":     "100 20 0 0 0 0 0",
		"proc/42/cmdline":   "sh\x00-c\x00echo \x1b]0;pwned\x07‮",
		"proc/self/stat":    "x",
		"proc/notapid/stat": "x",
	})
	ps, err := f.Processes(map[int]uint64{42: 200}, 1000, 2, f.Users())
	if err != nil || len(ps) != 2 {
		t.Fatalf("procs %v %v", ps, err)
	}
	var p42 Process
	for _, p := range ps {
		if p.PID == 42 {
			p42 = p
		}
	}
	if p42.Name != "evil) name[31m" || p42.User != "pancake" || p42.PPID != 1 || p42.Threads != 3 {
		t.Fatalf("p42 %+v", p42)
	}
	if strings.ContainsAny(p42.Command, "\x1b\x07‮") {
		t.Fatalf("control chars not neutralised: %q", p42.Command)
	}
	if p42.CPU != 20 { // (300-200)*2/1000*100
		t.Fatalf("cpu %v", p42.CPU)
	}
	if p42.Start.Unix() != 1700000005 {
		t.Fatalf("start %v", p42.Start)
	}
	if top := TopBy(ps, 1); top[0].PID != 42 {
		t.Fatal("top order")
	}
}

func TestSanitizeTextTruncatesOnRuneBoundary(t *testing.T) {
	s := SanitizeText(strings.Repeat("ä", 10), 5)
	if len(s) > 5 || !strings.HasPrefix("ääää", s) {
		t.Fatalf("%q", s)
	}
	if SanitizeText("a\xffb", 10) != "a�b" {
		t.Fatal("invalid utf-8 not replaced")
	}
}

func FuzzParseProcStat(f *testing.F) {
	f.Add([]byte("1 (systemd) S 0 1 1 0 -1 4194560 0 0 0 0 10 5 0 0 20 0 1 0 100 0 0"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _, _, _, _, _ = parseProcStat(b) })
}
