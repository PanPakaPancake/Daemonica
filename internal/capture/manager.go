package capture

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Starter runs tcpdump in its sandbox and returns its stdout (the pcap
// stream) and a function that stops it.
type Starter interface {
	Start(ctx context.Context, unit string, args []string, spec Spec) (io.ReadCloser, func(), error)
	// Cleanup stops capture units left from an earlier helper run.
	Cleanup(ctx context.Context)
}

// UnitPrefix names the transient capture units.
const UnitPrefix = "daemonica-capture-"

// Limits of the live view and storage.
const (
	RingSize         = 10_000
	MaxLinesPerCall  = 500
	DefaultRetention = 24 * time.Hour
	MaxRetention     = 7 * 24 * time.Hour
	DefaultTotal     = 1 << 30
	MinFreeRatio     = 0.10
	maxTalkers       = 2000
)

// Meta describes a capture (stored as <id>.json beside <id>.pcap).
type Meta struct {
	ID          string     `json:"id"`
	Template    string     `json:"template,omitempty"`
	Iface       string     `json:"iface"`
	Filter      string     `json:"filter"`
	Snaplen     int        `json:"snaplen"`
	Promisc     bool       `json:"promisc"`
	DurationSec int        `json:"duration_sec"`
	Packets     int        `json:"packets"`
	SizeBytes   int64      `json:"size_bytes"`
	Started     time.Time  `json:"started"`
	Ended       *time.Time `json:"ended,omitempty"`
	State       string     `json:"state"`            // running, done, failed
	Reason      string     `json:"reason,omitempty"` // duration, packets, size, disk, stopped, ended, error
	Error       string     `json:"error,omitempty"`  // what failed, for reason "error"
	Captured    int        `json:"captured"`
	Bytes       int64      `json:"bytes"`
	Account     string     `json:"account,omitempty"`
}

// Stats of a capture for the live statistics.
type Stats struct {
	Packets  int            `json:"packets"`
	Bytes    int64          `json:"bytes"`
	Protos   map[string]int `json:"protos"`
	Talkers  []Talker       `json:"talkers"` // top 10 by bytes
	Seconds  float64        `json:"seconds"`
	PPS      float64        `json:"pps"`
	BPS      float64        `json:"bps"`
	talkerBy map[string]*Talker
}

// Talker is a host with its traffic.
type Talker struct {
	Host    string `json:"host"`
	Packets int    `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

type running struct {
	meta    Meta
	stop    func()
	ring    []Summary
	seq     uint64
	stats   Stats
	started time.Time
	done    chan struct{}
}

// Manager runs at most one capture at a time and keeps the files.
type Manager struct {
	Dir     string
	Starter Starter
	Now     func() time.Time
	// Free returns free and total bytes of the filesystem holding Dir.
	Free func(dir string) (free, total uint64, err error)

	mu   sync.Mutex
	cur  *running // running or the last one (for its lines and stats)
	busy bool
}

// Errors.
var (
	ErrBusy     = errors.New("capture: a capture is already running")
	ErrNotFound = errors.New("capture: not found")
	ErrLowDisk  = errors.New("capture: less than 10 % free disk space")
)

var idRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ValidID checks a capture id.
func ValidID(id string) bool { return idRE.MatchString(id) }

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func statfsFree(dir string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil //nolint:gosec // block sizes are positive
}

func (m *Manager) lowDisk() bool {
	free := m.Free
	if free == nil {
		free = statfsFree
	}
	f, t, err := free(m.Dir)
	return err != nil || t == 0 || float64(f)/float64(t) < MinFreeRatio
}

func (m *Manager) path(id, ext string) string { return filepath.Join(m.Dir, id+ext) }

// Init creates the directory, ends leftover units and marks captures that
// were running when the helper stopped as failed.
func (m *Manager) Init(ctx context.Context) error {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	if m.Starter != nil {
		m.Starter.Cleanup(ctx)
	}
	list, _ := m.List()
	for _, c := range list {
		if c.State == "running" {
			c.State, c.Reason = "failed", "helper restarted"
			end := m.now().UTC()
			c.Ended = &end
			_ = m.saveMeta(c)
		}
	}
	return nil
}

func (m *Manager) saveMeta(meta Meta) error {
	b, _ := json.MarshalIndent(meta, "", "  ")
	tmp := m.path(meta.ID, ".json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path(meta.ID, ".json"))
}

// Start validates nothing beyond the limits it enforces: spec must be
// normalised and the filter compiled by the caller.
func (m *Manager) Start(ctx context.Context, spec Spec, account string) (Meta, error) {
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return Meta{}, ErrBusy
	}
	m.busy = true
	m.mu.Unlock()
	release := func() { m.mu.Lock(); m.busy = false; m.mu.Unlock() }
	if m.lowDisk() {
		release()
		return Meta{}, ErrLowDisk
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	meta := Meta{ID: id, Template: spec.Template, Iface: spec.Iface, Filter: spec.Filter(), Snaplen: spec.Snaplen(), Promisc: spec.Promisc,
		DurationSec: spec.DurationSec, Packets: spec.Packets, SizeBytes: spec.SizeBytes, Started: m.now().UTC(), State: "running", Account: account}
	f, err := os.OpenFile(m.path(id, ".pcap"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // id is hex
	if err != nil {
		release()
		return Meta{}, err
	}
	if err := m.saveMeta(meta); err != nil {
		_ = f.Close()
		release()
		return Meta{}, err
	}
	out, stop, err := m.Starter.Start(context.WithoutCancel(ctx), UnitPrefix+id+".service", spec.Args(), spec)
	if err != nil {
		_ = f.Close()
		end := m.now().UTC()
		meta.State, meta.Reason, meta.Ended = "failed", "error", &end
		_ = m.saveMeta(meta)
		release()
		return meta, err
	}
	r := &running{meta: meta, stop: stop, started: m.now(), done: make(chan struct{}),
		stats: Stats{Protos: map[string]int{}, talkerBy: map[string]*Talker{}}}
	m.mu.Lock()
	m.cur = r
	m.mu.Unlock()
	go m.loop(r, out, f, spec)
	return meta, nil
}

// end records the first reason and stops the capture process.
func (m *Manager) end(r *running, reason string) {
	m.mu.Lock()
	first := r.meta.Reason == ""
	if first {
		r.meta.Reason = reason
	}
	m.mu.Unlock()
	if first {
		r.stop()
	}
}

func (m *Manager) loop(r *running, out io.ReadCloser, f *os.File, spec Spec) {
	defer close(r.done)
	timer := time.AfterFunc(time.Duration(spec.DurationSec)*time.Second, func() { m.end(r, "duration") })
	stopDisk := make(chan struct{})
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopDisk:
				return
			case <-t.C:
				if m.lowDisk() {
					m.end(r, "disk")
				}
			}
		}
	}()
	w := bufio.NewWriterSize(f, 64<<10)
	written := int64(0)
	failed := false
	br := bufio.NewReaderSize(out, 256<<10)
	hdr, err := ReadHeader(br)
	if err == nil {
		_, err = w.Write(hdr.Raw[:])
		written = 24
	}
	if err != nil {
		failed = true
	}
	var cause error
	if failed {
		cause = err
	}
	var buf []byte
	for !failed {
		var rec Record
		rec, buf, err = ReadRecord(br, hdr, buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, os.ErrClosed) {
				failed, cause = true, err
			}
			break
		}
		if written+int64(len(rec.Raw)) > spec.SizeBytes {
			m.end(r, "size")
			break
		}
		if _, err := w.Write(rec.Raw); err != nil {
			failed, cause = true, err
			break
		}
		written += int64(len(rec.Raw))
		s := Summarize(hdr.LinkType, rec)
		m.mu.Lock()
		r.meta.Captured++
		r.meta.Bytes = written
		r.seq++
		s.Seq = r.seq
		r.ring = append(r.ring, s)
		if len(r.ring) > RingSize {
			r.ring = slices.Delete(r.ring, 0, len(r.ring)-RingSize)
		}
		r.stats.add(s)
		n := r.meta.Captured
		m.mu.Unlock()
		if n >= spec.Packets {
			m.end(r, "packets")
			break
		}
	}
	timer.Stop()
	close(stopDisk)
	if failed {
		m.end(r, "error")
	}
	m.end(r, "ended") // process ended by itself (or no-op)
	_ = out.Close()
	_ = w.Flush()
	_ = f.Sync()
	_ = f.Close()
	m.mu.Lock()
	end := m.now().UTC()
	r.meta.Ended = &end
	r.meta.Bytes = written
	r.meta.State = "done"
	if r.meta.Reason == "error" && cause != nil {
		r.meta.Error = Clean(cause.Error(), 200)
	}
	if r.meta.Reason == "error" && r.meta.Captured == 0 {
		r.meta.State = "failed"
	}
	r.stats.finish(r.started, m.now())
	meta := r.meta
	m.busy = false
	m.mu.Unlock()
	_ = m.saveMeta(meta)
}

func (s *Stats) add(x Summary) {
	s.Packets++
	s.Bytes += int64(x.Len)
	s.Protos[x.Proto]++
	for _, h := range []string{x.srcHost, x.dstHost} {
		if h == "" {
			continue
		}
		t := s.talkerBy[h]
		if t == nil {
			if len(s.talkerBy) >= maxTalkers {
				continue
			}
			t = &Talker{Host: h}
			s.talkerBy[h] = t
		}
		t.Packets++
		t.Bytes += int64(x.Len)
	}
}

func (s *Stats) finish(start, now time.Time) {
	s.Seconds = now.Sub(start).Seconds()
	if s.Seconds > 0 {
		s.PPS = float64(s.Packets) / s.Seconds
		s.BPS = float64(s.Bytes) / s.Seconds
	}
	ts := make([]Talker, 0, len(s.talkerBy))
	for _, t := range s.talkerBy {
		ts = append(ts, *t)
	}
	sort.Slice(ts, func(i, j int) bool {
		return ts[i].Bytes > ts[j].Bytes || ts[i].Bytes == ts[j].Bytes && ts[i].Host < ts[j].Host
	})
	s.Talkers = ts[:min(10, len(ts))]
}

// Stop ends the running capture.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	r := m.cur
	running := r != nil && r.meta.ID == id && r.meta.State == "running"
	m.mu.Unlock()
	if !running {
		return ErrNotFound
	}
	m.end(r, "stopped")
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
	}
	return nil
}

// Live is the state of the current (or last) capture.
type Live struct {
	Meta  Meta  `json:"meta"`
	Stats Stats `json:"stats"`
}

// Current returns the running or last capture of this helper run.
func (m *Manager) Current() *Live {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return nil
	}
	st := m.cur.stats
	st.Protos = maps(st.Protos)
	end := m.now()
	if m.cur.meta.Ended != nil {
		end = *m.cur.meta.Ended
	}
	st.finish(m.cur.started, end)
	return &Live{Meta: m.cur.meta, Stats: st}
}

func maps(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Lines are summary lines after a sequence number.
type Lines struct {
	Entries   []Summary `json:"entries"`
	Cursor    string    `json:"cursor"`
	Truncated bool      `json:"truncated"`
	Skipped   int       `json:"skipped"` // lines no longer in the buffer or over the per-call limit
	Running   bool      `json:"running"`
}

// Lines returns up to max lines after the cursor of capture id; when more are
// waiting, the newest are returned and the rest counted as skipped.
func (m *Manager) Lines(id, after string, max int) (Lines, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.cur
	if r == nil || r.meta.ID != id {
		return Lines{}, ErrNotFound
	}
	if max <= 0 || max > MaxLinesPerCall {
		max = MaxLinesPerCall
	}
	var a uint64
	if after != "" {
		v, err := strconv.ParseUint(after, 10, 64)
		if err != nil {
			return Lines{}, ErrNotFound
		}
		a = v
	}
	out := Lines{Entries: []Summary{}, Cursor: strconv.FormatUint(r.seq, 10), Running: r.meta.State == "running"}
	if a >= r.seq {
		return out, nil
	}
	waiting := int(r.seq - a)
	avail := min(waiting, len(r.ring))
	n := min(avail, max)
	out.Entries = append(out.Entries, r.ring[len(r.ring)-n:]...)
	out.Skipped = waiting - n
	out.Truncated = out.Skipped > 0
	return out, nil
}

// List returns the stored captures, newest first.
func (m *Manager) List() ([]Meta, error) {
	ents, err := os.ReadDir(m.Dir)
	if err != nil {
		return nil, err
	}
	out := []Meta{}
	for _, e := range ents {
		name := e.Name()
		if filepath.Ext(name) != ".json" || !ValidID(name[:len(name)-5]) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.Dir, name)) //nolint:gosec // validated name
		if err != nil {
			continue
		}
		var meta Meta
		if json.Unmarshal(b, &meta) == nil && meta.ID == name[:len(name)-5] {
			if st, err := os.Stat(m.path(meta.ID, ".pcap")); err == nil {
				meta.Bytes = st.Size()
			}
			out = append(out, meta)
		}
	}
	m.mu.Lock()
	if m.cur != nil {
		for i := range out {
			if out[i].ID == m.cur.meta.ID {
				out[i] = m.cur.meta
			}
		}
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}

// Get returns one capture.
func (m *Manager) Get(id string) (Meta, error) {
	if !ValidID(id) {
		return Meta{}, ErrNotFound
	}
	list, err := m.List()
	if err != nil {
		return Meta{}, err
	}
	for _, c := range list {
		if c.ID == id {
			return c, nil
		}
	}
	return Meta{}, ErrNotFound
}

// Open opens the pcap file of a finished capture.
func (m *Manager) Open(id string) (*os.File, Meta, error) {
	meta, err := m.Get(id)
	if err != nil {
		return nil, meta, err
	}
	if meta.State == "running" {
		return nil, meta, ErrBusy
	}
	f, err := os.Open(m.path(id, ".pcap"))
	return f, meta, err
}

// Delete removes a finished capture.
func (m *Manager) Delete(id string) error {
	meta, err := m.Get(id)
	if err != nil {
		return err
	}
	if meta.State == "running" {
		return ErrBusy
	}
	m.mu.Lock()
	if m.cur != nil && m.cur.meta.ID == id {
		m.cur = nil
	}
	m.mu.Unlock()
	_ = os.Remove(m.path(id, ".pcap"))
	return os.Remove(m.path(id, ".json"))
}

// DeleteAll removes every finished capture and returns the number removed.
func (m *Manager) DeleteAll() int {
	list, _ := m.List()
	n := 0
	for _, c := range list {
		if c.State != "running" && m.Delete(c.ID) == nil {
			n++
		}
	}
	return n
}

// Prune deletes captures older than retention and the oldest ones while the
// total exceeds total bytes.
func (m *Manager) Prune(retention time.Duration, total int64) int {
	list, _ := m.List()
	n := 0
	var sum int64
	cutoff := m.now().Add(-retention)
	for _, c := range list { // newest first
		if c.State == "running" {
			sum += c.Bytes
			continue
		}
		if c.Started.Before(cutoff) || sum+c.Bytes > total {
			if m.Delete(c.ID) == nil {
				n++
			}
			continue
		}
		sum += c.Bytes
	}
	return n
}
