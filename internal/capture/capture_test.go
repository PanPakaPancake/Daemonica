package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func pcapHeader(link uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], 96)
	binary.LittleEndian.PutUint32(b[20:], link)
	return b
}

func record(data []byte, sec uint32) []byte {
	b := make([]byte, 16, 16+len(data))
	binary.LittleEndian.PutUint32(b[0:], sec)
	binary.LittleEndian.PutUint32(b[4:], 500)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(data))) //nolint:gosec // test
	binary.LittleEndian.PutUint32(b[12:], uint32(len(data))+100)
	return append(b, data...)
}

func eth(etype uint16, payload []byte) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{1, 2, 3, 4, 5, 6})
	copy(b[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(b[12:], etype)
	return append(b, payload...)
}

func ip4(proto byte, src, dst [4]byte, l4 []byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(l4))) //nolint:gosec // test
	b[8], b[9] = 64, proto
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	return append(b, l4...)
}

func tcpSyn(sp, dp uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	b[12], b[13] = 0x50, 0x02
	binary.BigEndian.PutUint16(b[14:], 64240)
	return b
}

func dnsQuery(name string, qtype uint16) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b
}

func udp(sp, dp uint16, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:], sp)
	binary.BigEndian.PutUint16(b[2:], dp)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload))) //nolint:gosec // test
	return append(b, payload...)
}

func ip6(next byte, l4 []byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(l4))) //nolint:gosec // test
	b[6], b[7] = next, 64
	b[8], b[9], b[23] = 0x20, 0x01, 1
	b[24], b[25], b[39] = 0x20, 0x01, 2
	return append(b, l4...)
}

func TestSummarize(t *testing.T) {
	a, b := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	vlan := append([]byte{0, 5, 0x08, 0x00}, ip4(1, a, b, []byte{8, 0, 0, 0})...)
	arpReq := []byte{0, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2}
	hopByHop := append([]byte{58, 0, 0, 0, 0, 0, 0, 0}, 128, 0, 0, 0)
	cases := []struct {
		link uint32
		data []byte
		want string // proto | src | dst | info
	}{
		{LinkEthernet, eth(0x0800, ip4(6, a, b, tcpSyn(40000, 22))), "tcp|10.0.0.1:40000|10.0.0.2:22|flags [S] win 64240"},
		{LinkEthernet, eth(0x8100, vlan), "icmp|10.0.0.1|10.0.0.2|echo request"},
		{LinkEthernet, eth(0x0806, arpReq), "arp|10.0.0.1|10.0.0.2|who-has 10.0.0.2 tell 10.0.0.1"},
		{LinkRaw, ip4(17, a, b, udp(5000, 53, dnsQuery("example.org", 28))), "dns|10.0.0.1:5000|10.0.0.2:53|query AAAA example.org"},
		{LinkRaw, ip6(17, udp(546, 547, []byte{1, 2, 3})), "dhcpv6|[2001::1]:546|[2001::2]:547|length 3"},
		{LinkRaw, ip6(0, hopByHop), "icmpv6|2001::1|2001::2|echo request"},
		{LinkEthernet, eth(0x0800, ip4(6, a, b, []byte{1})), "tcp|10.0.0.1|10.0.0.2|truncated tcp"},
		{LinkEthernet, []byte{1, 2, 3}, "?|||truncated ethernet"},
		{LinkRaw, ip4(17, a, b, udp(1, 53, []byte{0, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0, 3, '<', '>', '\'', 0, 0, 1})), "dns|10.0.0.1:1|10.0.0.2:53|response rcode 3 A ???"},
		{999, []byte{1}, "?|||link type 999"},
	}
	for i, c := range cases {
		s := Summarize(c.link, Record{Data: c.data, OrigLen: len(c.data)})
		got := s.Proto + "|" + s.Src + "|" + s.Dst + "|" + s.Info
		if got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
}

func FuzzSummarize(f *testing.F) {
	a, b := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	f.Add(uint32(LinkEthernet), eth(0x0800, ip4(6, a, b, tcpSyn(1, 2))))
	f.Add(uint32(LinkRaw), ip6(0, []byte{58, 0}))
	f.Add(uint32(LinkSLL2), make([]byte, 30))
	f.Fuzz(func(_ *testing.T, link uint32, data []byte) {
		_ = Summarize(link, Record{Data: data})
	})
}

func TestSpec(t *testing.T) {
	ok := Spec{Iface: "eth0", AcceptWarning: true, DashboardPort: 8443, Builder: Builder{Proto: "tcp", Host: "10.1.2.3/8", Ports: []int{80, 443}, Dir: "dst"}}
	s, err := ok.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if f := s.Filter(); f != "tcp and dst net 10.0.0.0/8 and (dst port 80 or dst port 443) and not (tcp port 8443)" {
		t.Fatal(f)
	}
	args := strings.Join(s.Args(), " ")
	if args != "tcpdump -i eth0 -s 96 -U -n -w - -c 100000 -p -- tcp and dst net 10.0.0.0/8 and (dst port 80 or dst port 443) and not (tcp port 8443)" {
		t.Fatal(args)
	}
	if s.DurationSec != 300 || s.SizeBytes != 100<<20 {
		t.Fatal("defaults")
	}
	s.IncludeDash, s.Builder = true, Builder{}
	if s.Filter() != "" || strings.Contains(strings.Join(s.Args(), " "), "--") {
		t.Fatal("empty filter")
	}
	adv := Spec{Iface: "eth0", AcceptWarning: true, Expr: "  tcp[13] & 2 != 0  ", DashboardPort: 8443}
	if s, err := adv.Normalize(); err != nil || s.Filter() != "(tcp[13] & 2 != 0) and not (tcp port 8443)" {
		t.Fatal(err, s.Filter())
	}
	bad := []Spec{
		{Iface: "eth0"},
		{Iface: "eth0; rm", AcceptWarning: true},
		{Iface: "any", AcceptWarning: true},
		{Iface: "averyveryverylongname", AcceptWarning: true},
		{Iface: "eth0", AcceptWarning: true, Expr: "-w /etc/passwd"},
		{Iface: "eth0", AcceptWarning: true, Expr: "port 22 $(id)"},
		{Iface: "eth0", AcceptWarning: true, Expr: "host 'x'"},
		{Iface: "eth0", AcceptWarning: true, DurationSec: 3600},
		{Iface: "eth0", AcceptWarning: true, SizeBytes: 2 << 30},
		{Iface: "eth0", AcceptWarning: true, FullPackets: true},
		{Iface: "eth0", AcceptWarning: true, Builder: Builder{Proto: "icmp", Ports: []int{1}}},
		{Iface: "eth0", AcceptWarning: true, Builder: Builder{Host: "fe80::1%eth0"}},
		{Iface: "eth0", AcceptWarning: true, Builder: Builder{Ports: []int{0}}},
	}
	for i, b := range bad {
		if _, err := b.Normalize(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	full, err := Spec{Iface: "eth0", AcceptWarning: true, FullPackets: true, AcceptFullWarn: true, Promisc: true}.Normalize()
	if err != nil || full.Snaplen() != FullSnaplen || strings.Contains(strings.Join(full.Args(), " "), " -p") {
		t.Fatal("full/promisc", err)
	}
}

// fakeStarter streams the given pcap bytes, then blocks until stopped.
type fakeStarter struct {
	mu      sync.Mutex
	data    []byte
	hold    bool
	stopped int
	args    []string
}

func (f *fakeStarter) Start(_ context.Context, _ string, args []string, _ Spec) (io.ReadCloser, func(), error) {
	r, w := io.Pipe()
	f.args = args
	done := make(chan struct{})
	var once sync.Once
	go func() {
		_, _ = w.Write(f.data)
		if f.hold {
			<-done
		}
		_ = w.Close()
	}()
	return r, func() {
		once.Do(func() {
			f.mu.Lock()
			f.stopped++
			f.mu.Unlock()
			close(done)
		})
	}, nil
}

func (f *fakeStarter) Cleanup(context.Context) {}

func stream(n int) []byte {
	var b bytes.Buffer
	b.Write(pcapHeader(LinkEthernet))
	for i := 0; i < n; i++ {
		b.Write(record(eth(0x0800, ip4(6, [4]byte{10, 0, 0, byte(i % 3)}, [4]byte{10, 0, 0, 9}, tcpSyn(uint16(1000+i), 22))), uint32(1000+i))) //nolint:gosec // test
	}
	return b.Bytes()
}

func manager(t *testing.T, fs *fakeStarter) *Manager {
	t.Helper()
	m := &Manager{Dir: filepath.Join(t.TempDir(), "captures"), Starter: fs, Free: func(string) (uint64, uint64, error) { return 50, 100, nil }}
	if err := m.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m
}

func wait(t *testing.T, m *Manager) Meta {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c := m.Current(); c != nil && c.Meta.State != "running" {
			return c.Meta
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("capture did not end")
	return Meta{}
}

func spec(t *testing.T, mod func(*Spec)) Spec {
	s := Spec{Iface: "eth0", AcceptWarning: true}
	if mod != nil {
		mod(&s)
	}
	s, err := s.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManagerLimits(t *testing.T) {
	ctx := context.Background()
	// Packet limit.
	fs := &fakeStarter{data: stream(50), hold: true}
	m := manager(t, fs)
	meta, err := m.Start(ctx, spec(t, func(s *Spec) { s.Packets = 20 }), "acc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(ctx, spec(t, nil), "acc"); !errors.Is(err, ErrBusy) {
		t.Fatal("second capture must be refused")
	}
	end := wait(t, m)
	if end.Reason != "packets" || end.Captured != 20 || end.State != "done" || fs.stopped != 1 {
		t.Fatalf("packets: %+v stopped=%d", end, fs.stopped)
	}
	st, _ := os.Stat(filepath.Join(m.Dir, meta.ID+".pcap"))
	if st.Mode().Perm() != 0o600 || st.Size() != end.Bytes {
		t.Fatalf("file: %v %d/%d", st.Mode(), st.Size(), end.Bytes)
	}
	// The stored file is a valid pcap with exactly 20 records.
	f, _ := os.Open(filepath.Join(m.Dir, meta.ID+".pcap"))
	h, err := ReadHeader(f)
	n := 0
	for err == nil {
		if _, _, err = ReadRecord(f, h, nil); err == nil {
			n++
		}
	}
	_ = f.Close()
	if n != 20 {
		t.Fatalf("records: %d", n)
	}
	l, _ := m.Lines(meta.ID, "15", 0)
	if len(l.Entries) != 5 || l.Entries[0].Seq != 16 || l.Cursor != "20" || l.Running {
		t.Fatalf("lines: %+v", l)
	}
	l, _ = m.Lines(meta.ID, "0", 3)
	if len(l.Entries) != 3 || l.Entries[2].Seq != 20 || l.Skipped != 17 {
		t.Fatalf("limited lines: %d %d", len(l.Entries), l.Skipped)
	}
	cur := m.Current()
	if cur.Stats.Packets != 20 || cur.Stats.Protos["tcp"] != 20 || cur.Stats.Talkers[0].Host != "10.0.0.9" {
		t.Fatalf("stats: %+v", cur.Stats)
	}

	// Size limit: 1 MiB is the minimum, so feed big records.
	var big bytes.Buffer
	big.Write(pcapHeader(LinkRaw))
	for i := 0; i < 30; i++ {
		big.Write(record(make([]byte, 60000), 1))
	}
	fs.data, fs.stopped = big.Bytes(), 0
	if _, err := m.Start(ctx, spec(t, func(s *Spec) { s.SizeBytes = 1 << 20 }), "acc"); err != nil {
		t.Fatal(err)
	}
	if end := wait(t, m); end.Reason != "size" || end.Bytes > 1<<20 || end.Captured != 17 {
		t.Fatalf("size: %+v", end)
	}

	// Stop by the user; the process ending by itself.
	fs.data = stream(3)
	meta, _ = m.Start(ctx, spec(t, nil), "acc")
	time.Sleep(50 * time.Millisecond)
	if err := m.Stop(meta.ID); err != nil {
		t.Fatal(err)
	}
	if end := m.Current().Meta; end.Reason != "stopped" || end.Captured != 3 {
		t.Fatalf("stopped: %+v", end)
	}
	fs.hold = false
	m.Start(ctx, spec(t, nil), "acc") //nolint:errcheck // checked by wait
	if end := wait(t, m); end.Reason != "ended" {
		t.Fatalf("ended: %+v", end)
	}
	// Garbage instead of pcap fails.
	fs.data = []byte("not a pcap stream at all!")
	m.Start(ctx, spec(t, nil), "acc") //nolint:errcheck // checked by wait
	if end := wait(t, m); end.State != "failed" || end.Reason != "error" {
		t.Fatalf("garbage: %+v", end)
	}

	// Low disk refuses to start.
	m.Free = func(string) (uint64, uint64, error) { return 5, 100, nil }
	if _, err := m.Start(ctx, spec(t, nil), "acc"); !errors.Is(err, ErrLowDisk) {
		t.Fatal("low disk must refuse")
	}

	list, _ := m.List()
	if len(list) != 5 {
		t.Fatalf("list: %d", len(list))
	}
	// Retention: everything older than 1 h goes; the total limit removes the oldest.
	m.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if n := m.Prune(time.Hour, 1<<40); n != 5 {
		t.Fatalf("pruned %d", n)
	}
	if list, _ := m.List(); len(list) != 0 {
		t.Fatal("not pruned")
	}
}

func TestInitMarksRunningFailed(t *testing.T) {
	m := manager(t, &fakeStarter{})
	_ = m.saveMeta(Meta{ID: "0123456789abcdef", State: "running", Started: time.Now()})
	_ = m.Init(context.Background())
	c, err := m.Get("0123456789abcdef")
	if err != nil || c.State != "failed" || c.Ended == nil {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := m.Get("../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatal("path id")
	}
	if m.Delete(c.ID) != nil || m.DeleteAll() != 0 {
		t.Fatal("delete")
	}
}

func TestUnitProperties(t *testing.T) {
	s := spec(t, func(s *Spec) { s.Promisc = true })
	props := unitProperties(s.Args(), s, 7)
	got := map[string]any{}
	for _, p := range props {
		got[p.Name] = p.Value.Value()
	}
	if got["DynamicUser"] != true || got["NoNewPrivileges"] != true || got["ProtectSystem"] != "strict" || got["AmbientCapabilities"] != uint64(1<<13|1<<12) {
		t.Fatalf("%v", got)
	}
	if fam := got["RestrictAddressFamilies"].(boolList); !fam.Allow || strings.Join(fam.List, ",") != "AF_PACKET,AF_UNIX" {
		t.Fatal(fam)
	}
	if got["RuntimeMaxUSec"] != uint64(330_000_000) {
		t.Fatal(got["RuntimeMaxUSec"])
	}
}
