// Package capture runs packet captures (SPEC §7.6 M1.5d): tcpdump only
// captures into a pcap stream inside a restricted transient unit; this
// package enforces the limits, stores the file and summarises packets with
// its own bounds-checked parser (no protocol dissection by tcpdump).
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Link types (pcap LINKTYPE_*).
const (
	LinkEthernet = 1
	LinkRaw      = 101
	LinkSLL      = 113
	LinkSLL2     = 276
	linkRawAlt   = 12
	linkRawAlt2  = 14
	// MaxRecord bounds one record (tcpdump's maximum snaplen).
	MaxRecord = 262144
)

// Header is the pcap file header.
type Header struct {
	Order    binary.ByteOrder
	Nano     bool
	Snaplen  uint32
	LinkType uint32
	Raw      [24]byte
}

// ErrFormat reports a stream that is not pcap.
var ErrFormat = errors.New("capture: not a pcap stream")

// ReadHeader reads the 24-byte pcap file header.
func ReadHeader(r io.Reader) (Header, error) {
	var h Header
	if _, err := io.ReadFull(r, h.Raw[:]); err != nil {
		return h, err
	}
	switch {
	case binary.LittleEndian.Uint32(h.Raw[:4]) == 0xa1b2c3d4:
		h.Order = binary.LittleEndian
	case binary.BigEndian.Uint32(h.Raw[:4]) == 0xa1b2c3d4:
		h.Order = binary.BigEndian
	case binary.LittleEndian.Uint32(h.Raw[:4]) == 0xa1b23c4d:
		h.Order, h.Nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(h.Raw[:4]) == 0xa1b23c4d:
		h.Order, h.Nano = binary.BigEndian, true
	default:
		return h, ErrFormat
	}
	h.Snaplen = h.Order.Uint32(h.Raw[16:20])
	h.LinkType = h.Order.Uint32(h.Raw[20:24]) & 0x0fffffff
	return h, nil
}

// Record is one captured packet as stored in the file.
type Record struct {
	Time    time.Time
	OrigLen int
	Data    []byte
	Raw     []byte // record header + data, as written to the file
}

// ReadRecord reads the next record; buf is reused when large enough.
func ReadRecord(r io.Reader, h Header, buf []byte) (Record, []byte, error) {
	var rh [16]byte
	if _, err := io.ReadFull(r, rh[:]); err != nil {
		return Record{}, buf, err
	}
	sec := h.Order.Uint32(rh[0:4])
	frac := h.Order.Uint32(rh[4:8])
	incl := h.Order.Uint32(rh[8:12])
	orig := h.Order.Uint32(rh[12:16])
	if incl > MaxRecord {
		return Record{}, buf, fmt.Errorf("%w: record of %d bytes", ErrFormat, incl)
	}
	n := 16 + int(incl)
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	copy(buf, rh[:])
	if _, err := io.ReadFull(r, buf[16:]); err != nil {
		return Record{}, buf, err
	}
	ns := int64(frac) * 1000
	if h.Nano {
		ns = int64(frac)
	}
	return Record{Time: time.Unix(int64(sec), ns).UTC(), OrigLen: int(orig), Data: buf[16:], Raw: buf}, buf, nil
}

// Summary is one line of the live view. All fields are plain text built
// from validated values; payload is never included.
type Summary struct {
	Seq   uint64    `json:"seq"`
	Time  time.Time `json:"time"`
	Src   string    `json:"src"`
	Dst   string    `json:"dst"`
	Proto string    `json:"proto"`
	Len   int       `json:"len"`
	Info  string    `json:"info"`
	// Talker keys for statistics (addresses without ports).
	srcHost, dstHost string
}

type buf []byte

func (b buf) u8(i int) (int, bool) {
	if i < 0 || i >= len(b) {
		return 0, false
	}
	return int(b[i]), true
}

func (b buf) u16(i int) (int, bool) {
	if i < 0 || i+2 > len(b) {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(b[i:])), true
}

// Summarize decodes one packet. It never panics on truncated or hostile data:
// every access is bounds-checked and unknown layers end the decoding.
func Summarize(link uint32, rec Record) Summary {
	s := Summary{Time: rec.Time, Len: rec.OrigLen, Proto: "?"}
	d := buf(rec.Data)
	var etype int
	var ok bool
	switch link {
	case LinkEthernet:
		off := 12
		if etype, ok = d.u16(off); !ok {
			s.Info = "truncated ethernet"
			return s
		}
		for i := 0; i < 2 && (etype == 0x8100 || etype == 0x88a8); i++ {
			off += 4
			if etype, ok = d.u16(off); !ok {
				s.Info = "truncated vlan"
				return s
			}
		}
		if etype < 0x0600 { // 802.3 length field (LLC)
			s.Proto, s.Info = "llc", "802.3 frame"
			return s
		}
		d = d[off+2:]
	case LinkSLL:
		if etype, ok = d.u16(14); !ok {
			return s
		}
		d = d[16:]
	case LinkSLL2:
		if etype, ok = d.u16(0); !ok || len(d) < 20 {
			return s
		}
		d = d[20:]
	case LinkRaw, linkRawAlt, linkRawAlt2:
		v, ok := d.u8(0)
		if !ok {
			return s
		}
		switch v >> 4 {
		case 4:
			etype = 0x0800
		case 6:
			etype = 0x86dd
		}
	default:
		s.Info = "link type " + strconv.Itoa(int(link))
		return s
	}
	switch etype {
	case 0x0800:
		ipv4(&s, d)
	case 0x86dd:
		ipv6(&s, d)
	case 0x0806:
		arp(&s, d)
	default:
		s.Proto, s.Info = "eth", fmt.Sprintf("ethertype 0x%04x", etype)
	}
	return s
}

func addr(b []byte) string {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return "?"
	}
	return a.Unmap().String()
}

func ipv4(s *Summary, d buf) {
	s.Proto = "ipv4"
	vihl, ok := d.u8(0)
	if !ok || len(d) < 20 || vihl>>4 != 4 {
		s.Info = "truncated ipv4"
		return
	}
	ihl := (vihl & 0x0f) * 4
	s.srcHost, s.dstHost = addr(d[12:16]), addr(d[16:20])
	s.Src, s.Dst = s.srcHost, s.dstHost
	frag, _ := d.u16(6)
	proto, _ := d.u8(9)
	if ihl < 20 || ihl > len(d) {
		s.Info = "bad header length"
		return
	}
	if frag&0x1fff != 0 {
		s.Info = "fragment"
		return
	}
	l4(s, proto, d[ihl:], false)
}

func ipv6(s *Summary, d buf) {
	s.Proto = "ipv6"
	if len(d) < 40 || d[0]>>4 != 6 {
		s.Info = "truncated ipv6"
		return
	}
	s.srcHost, s.dstHost = addr(d[8:24]), addr(d[24:40])
	s.Src, s.Dst = s.srcHost, s.dstHost
	next := int(d[6])
	p := buf(d[40:])
	for i := 0; i < 8; i++ { // extension headers, bounded
		switch next {
		case 0, 43, 60:
			n, ok1 := p.u8(0)
			l, ok2 := p.u8(1)
			if !ok1 || !ok2 || (l+1)*8 > len(p) {
				s.Info = "truncated extension header"
				return
			}
			next, p = n, p[(l+1)*8:]
		case 44:
			n, ok := p.u8(0)
			fo, ok2 := p.u16(2)
			if !ok || !ok2 || len(p) < 8 {
				s.Info = "truncated fragment header"
				return
			}
			if fo&0xfff8 != 0 {
				s.Info = "fragment"
				return
			}
			next, p = n, p[8:]
		default:
			l4(s, next, p, true)
			return
		}
	}
	s.Info = "too many extension headers"
}

func hostPort(h string, port int, v6 bool) string {
	if v6 {
		return "[" + h + "]:" + strconv.Itoa(port)
	}
	return h + ":" + strconv.Itoa(port)
}

func l4(s *Summary, proto int, d buf, v6 bool) {
	switch proto {
	case 6:
		s.Proto = "tcp"
		sp, ok1 := d.u16(0)
		dp, ok2 := d.u16(2)
		fl, ok3 := d.u8(13)
		if !ok1 || !ok2 {
			s.Info = "truncated tcp"
			return
		}
		s.Src, s.Dst = hostPort(s.srcHost, sp, v6), hostPort(s.dstHost, dp, v6)
		if ok3 {
			s.Info = "flags [" + tcpFlags(fl) + "]"
			if w, ok := d.u16(14); ok {
				s.Info += " win " + strconv.Itoa(w)
			}
		}
	case 17:
		s.Proto = "udp"
		sp, ok1 := d.u16(0)
		dp, ok2 := d.u16(2)
		ul, _ := d.u16(4)
		if !ok1 || !ok2 {
			s.Info = "truncated udp"
			return
		}
		s.Src, s.Dst = hostPort(s.srcHost, sp, v6), hostPort(s.dstHost, dp, v6)
		switch {
		case sp == 53 || dp == 53 || sp == 5353 || dp == 5353:
			s.Proto, s.Info = "dns", dnsInfo(d[min(8, len(d)):])
		case (sp == 67 || sp == 68) && (dp == 67 || dp == 68):
			s.Proto, s.Info = "dhcp", "length "+strconv.Itoa(max(ul-8, 0))
		case (sp == 546 || sp == 547) && (dp == 546 || dp == 547):
			s.Proto, s.Info = "dhcpv6", "length "+strconv.Itoa(max(ul-8, 0))
		default:
			s.Info = "length " + strconv.Itoa(max(ul-8, 0))
		}
	case 1:
		s.Proto = "icmp"
		t, ok := d.u8(0)
		c, _ := d.u8(1)
		if !ok {
			s.Info = "truncated icmp"
			return
		}
		s.Info = icmpName(t, c, icmp4Names)
	case 58:
		s.Proto = "icmpv6"
		t, ok := d.u8(0)
		c, _ := d.u8(1)
		if !ok {
			s.Info = "truncated icmpv6"
			return
		}
		s.Info = icmpName(t, c, icmp6Names)
	default:
		s.Info = "ip protocol " + strconv.Itoa(proto)
	}
}

func tcpFlags(f int) string {
	var b strings.Builder
	for _, x := range []struct {
		bit int
		c   byte
	}{{0x02, 'S'}, {0x01, 'F'}, {0x04, 'R'}, {0x08, 'P'}, {0x20, 'U'}, {0x10, '.'}} {
		if f&x.bit != 0 {
			b.WriteByte(x.c)
		}
	}
	if b.Len() == 0 {
		return "none"
	}
	return b.String()
}

var icmp4Names = map[int]string{0: "echo reply", 3: "destination unreachable", 5: "redirect", 8: "echo request", 11: "time exceeded"}
var icmp6Names = map[int]string{1: "destination unreachable", 2: "packet too big", 3: "time exceeded", 128: "echo request", 129: "echo reply",
	133: "router solicitation", 134: "router advertisement", 135: "neighbor solicitation", 136: "neighbor advertisement"}

func icmpName(t, c int, names map[int]string) string {
	if n, ok := names[t]; ok {
		if c != 0 {
			return n + " (code " + strconv.Itoa(c) + ")"
		}
		return n
	}
	return "type " + strconv.Itoa(t) + " code " + strconv.Itoa(c)
}

var dnsTypes = map[int]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}

// dnsInfo reads the first question name (labels only, no compression
// pointers in questions) and renders only letters, digits, '-', '_' and '.'.
func dnsInfo(d buf) string {
	flags, ok := d.u16(2)
	qd, ok2 := d.u16(4)
	if !ok || !ok2 {
		return "truncated dns"
	}
	kind := "query"
	if flags&0x8000 != 0 {
		kind = "response"
		if rc := flags & 0x0f; rc != 0 {
			kind += " rcode " + strconv.Itoa(rc)
		}
	}
	if qd == 0 {
		return kind
	}
	var name strings.Builder
	i := 12
	for n := 0; n < 64; n++ {
		l, ok := d.u8(i)
		if !ok || l&0xc0 != 0 {
			return kind
		}
		i++
		if l == 0 {
			break
		}
		if i+l > len(d) || name.Len()+l > 253 {
			return kind
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		for _, c := range d[i : i+l] {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				name.WriteByte(c)
			} else {
				name.WriteByte('?')
			}
		}
		i += l
	}
	qt, _ := d.u16(i)
	t := dnsTypes[qt]
	if t == "" {
		t = "type" + strconv.Itoa(qt)
	}
	n := name.String()
	if n == "" {
		n = "."
	}
	return kind + " " + t + " " + n
}

func arp(s *Summary, d buf) {
	s.Proto = "arp"
	op, ok := d.u16(6)
	hl, ok2 := d.u8(4)
	pl, ok3 := d.u8(5)
	if !ok || !ok2 || !ok3 || pl != 4 || 8+2*hl+2*pl > len(d) {
		s.Info = "arp"
		return
	}
	spa := addr(d[8+hl : 8+hl+4])
	tpa := addr(d[8+2*hl+4 : 8+2*hl+8])
	s.Src, s.Dst, s.srcHost, s.dstHost = spa, tpa, spa, tpa
	switch op {
	case 1:
		s.Info = "who-has " + tpa + " tell " + spa
	case 2:
		s.Info = spa + " is-at " + mac(d[8:8+hl])
	default:
		s.Info = "op " + strconv.Itoa(op)
	}
}

func mac(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}
