//go:build integration

package integration

import (
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// TestOpenPortsMatchSS checks the "open ports" view against `ss -tuln` (SPEC §7.6 acceptance).
func TestOpenPortsMatchSS(t *testing.T) {
	out, err := exec.Command("ss", "-H", "-tuln").Output()
	if err != nil {
		t.Skip("ss not available")
	}
	var want []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndexByte(local, ':')
		addr := strings.Trim(local[:i], "[]")
		if j := strings.IndexByte(addr, '%'); j >= 0 { // 127.0.0.53%lo
			addr = addr[:j]
		}
		if addr == "*" {
			addr = "::"
		}
		want = append(want, f[0]+" "+addr+" "+local[i+1:])
	}
	ps, err := (&netcfg.Reader{}).Ports()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range ps {
		got = append(got, strings.TrimSuffix(p.Proto, "6")+" "+p.Address+" "+strconv.Itoa(p.Port))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Fatalf("ports differ from ss:\nss:  %v\ngot: %v", want, got)
	}
}
