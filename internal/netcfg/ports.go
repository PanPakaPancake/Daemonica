package netcfg

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Port is a listening TCP socket or a bound, unconnected UDP socket — the
// same set `ss -tuln` shows.
type Port struct {
	Proto     string    `json:"proto"` // tcp, tcp6, udp, udp6
	Address   string    `json:"address"`
	Port      int       `json:"port"`
	UID       int       `json:"uid"`
	User      string    `json:"user,omitempty"`
	Processes []PortPID `json:"processes"`
}

// PortPID is a process holding the socket.
type PortPID struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

const (
	tcpListen   = "0A"
	udpUnconn   = "07"
	maxPortRows = 4096
)

// Ports lists the listening sockets with their processes.
func (r *Reader) Ports() ([]Port, error) {
	owners := r.socketOwners()
	out := []Port{}
	for _, f := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", tcpListen}, {"/proc/net/tcp6", "tcp6", tcpListen},
		{"/proc/net/udp", "udp", udpUnconn}, {"/proc/net/udp6", "udp6", udpUnconn},
	} {
		ps, err := r.readSockets(f.file, f.proto, f.state, owners)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		out = append(out, ps...)
	}
	names := map[int]string{}
	for i := range out {
		n, ok := names[out[i].UID]
		if !ok {
			if u, err := user.LookupId(strconv.Itoa(out[i].UID)); err == nil {
				n = u.Username
			}
			names[out[i].UID] = n
		}
		out[i].User = n
	}
	slices.SortFunc(out, func(a, b Port) int {
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Proto+a.Address, b.Proto+b.Address)
	})
	return out, nil
}

func (r *Reader) readSockets(file, proto, state string, owners map[string][]PortPID) ([]Port, error) {
	f, err := os.Open(r.path(file)) //nolint:gosec // fixed /proc path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []Port
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() && len(out) < maxPortRows {
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
		fl := strings.Fields(sc.Text())
		if len(fl) < 10 || fl[3] != state {
			continue
		}
		addr, port, ok := parseHexAddr(fl[1])
		if !ok {
			continue
		}
		uid, _ := strconv.Atoi(fl[7])
		p := Port{Proto: proto, Address: addr.String(), Port: port, UID: uid, Processes: owners[fl[9]]}
		if p.Processes == nil {
			p.Processes = []PortPID{}
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0035" (IPv4) or the 32-digit IPv6 form;
// /proc prints each 32-bit word in host byte order (little endian here).
func parseHexAddr(s string) (netip.Addr, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	b, err := hex.DecodeString(a)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, 0, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip, _ := netip.AddrFromSlice(b)
	return ip.Unmap(), int(port), true
}

// socketOwners maps socket inodes to the processes holding them (via /proc/<pid>/fd).
func (r *Reader) socketOwners() map[string][]PortPID {
	out := map[string][]PortPID{}
	ents, err := os.ReadDir(r.path("/proc"))
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := r.path(filepath.Join("/proc", e.Name()))
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		name := readTrim(dir + "/comm")
		for _, fd := range fds {
			l, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")
			if !slices.ContainsFunc(out[ino], func(p PortPID) bool { return p.PID == pid }) {
				out[ino] = append(out[ino], PortPID{PID: pid, Name: name})
			}
		}
	}
	return out
}
