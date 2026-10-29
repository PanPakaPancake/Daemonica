package sysinfo

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Interface is the overview view of one network interface.
type Interface struct {
	Name    string  `json:"name"`
	State   string  `json:"state"`
	MAC     string  `json:"mac"`
	RxBps   float64 `json:"rx_bps"`
	TxBps   float64 `json:"tx_bps"`
	RxBytes uint64  `json:"rx_bytes"`
	TxBytes uint64  `json:"tx_bytes"`
	Errors  uint64  `json:"errors"`
}

// Snapshot is the system overview (SPEC §7.2 "Systemübersicht").
type Snapshot struct {
	Time           time.Time   `json:"time"`
	Hostname       string      `json:"hostname"`
	OS             string      `json:"os"`
	OSID           string      `json:"os_id"`
	OSVersion      string      `json:"os_version"`
	Kernel         string      `json:"kernel"`
	UptimeSec      int64       `json:"uptime_sec"`
	CPUs           int         `json:"cpus"`
	CPUPct         float64     `json:"cpu_pct"`
	Load           [3]float64  `json:"load"`
	Memory         Memory      `json:"memory"`
	Mounts         []Mount     `json:"mounts"`
	Interfaces     []Interface `json:"interfaces"`
	Processes      int         `json:"processes"`
	Top            []Process   `json:"top"`
	RebootRequired bool        `json:"reboot_required"`
	RebootPkgs     []string    `json:"reboot_pkgs,omitempty"`
	// Extras filled by optional providers (systemd, apt, TLS); nil = unknown.
	FailedUnits *int     `json:"failed_units,omitempty"`
	CertDays    *int     `json:"cert_days_left,omitempty"`
	Updates     *Updates `json:"updates,omitempty"`
	Logins      []Login  `json:"last_logins,omitempty"`
}

// Updates summarises pending package updates.
type Updates struct {
	Total    int `json:"total"`
	Security int `json:"security"`
	// AutoSecurity: unattended-upgrades installs security updates (known
	// only from the package view, M1.7).
	AutoSecurity *bool `json:"auto_security,omitempty"`
}

// Login is one entry of the login history.
type Login struct {
	User string    `json:"user"`
	From string    `json:"from"`
	TTY  string    `json:"tty"`
	Time time.Time `json:"time"`
	End  time.Time `json:"end,omitzero"` // zero while the session is open
}

// Extras are slower or optional data sources consulted by the collector.
type Extras struct {
	FailedUnits func(ctx context.Context) (int, error)
	CertDays    func() (int, error)
	Updates     func() (Updates, error)
	Logins      func(n int) ([]Login, error)
}

// Collector samples the host periodically. All dashboard sessions read the
// same cached snapshot: one collector, no polling storm (SPEC §7.2).
type Collector struct {
	FS       FS
	Interval time.Duration
	Extras   Extras

	mu        sync.RWMutex
	snap      Snapshot
	procs     []Process
	prevCPU   CPUTimes
	prevTicks map[int]uint64
	prevNet   map[string]NetCounters
	prevTime  time.Time
	users     map[uint32]string
	usersAt   time.Time
}

// Run samples until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	if c.Interval <= 0 {
		c.Interval = 3 * time.Second
	}
	c.Sample(ctx)
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Sample(ctx)
		}
	}
}

// Sample takes one measurement and replaces the cached snapshot.
func (c *Collector) Sample(ctx context.Context) {
	now := time.Now()
	s := Snapshot{Time: now.UTC(), Hostname: c.FS.Hostname(), Kernel: c.FS.Kernel()}
	s.OS, s.OSID, s.OSVersion = c.FS.OSRelease()
	if up, err := c.FS.Uptime(); err == nil {
		s.UptimeSec = int64(up.Seconds())
	}
	cpu, n, _ := c.FS.CPUStat()
	s.CPUs = n
	if l, err := c.FS.LoadAvg(); err == nil {
		s.Load = [3]float64{l.One, l.Five, l.Fifteen}
	}
	s.Memory, _ = c.FS.MemInfo()
	s.Mounts, _ = c.FS.Mounts(nil)
	s.RebootRequired, s.RebootPkgs = c.FS.RebootRequired()

	if c.users == nil || now.Sub(c.usersAt) > time.Minute {
		c.users, c.usersAt = c.FS.Users(), now
	}

	c.mu.RLock()
	prevCPU, prevTicks, prevNet, prevTime := c.prevCPU, c.prevTicks, c.prevNet, c.prevTime
	c.mu.RUnlock()

	var delta uint64
	if prevCPU.Total() > 0 && cpu.Total() >= prevCPU.Total() {
		delta = cpu.Total() - prevCPU.Total()
		s.CPUPct = CPUPercent(prevCPU, cpu)
	}
	procs, _ := c.FS.Processes(prevTicks, delta, n, c.users)
	s.Processes = len(procs)
	s.Top = TopBy(procs, 8)

	net, _ := c.FS.NetDev()
	dt := now.Sub(prevTime).Seconds()
	for name, cur := range net {
		st, mac := c.FS.InterfaceState(name)
		ifc := Interface{Name: SanitizeText(name, 16), State: st, MAC: mac, RxBytes: cur.RxBytes, TxBytes: cur.TxBytes, Errors: cur.RxErrs + cur.TxErrs}
		if old, ok := prevNet[name]; ok && dt > 0 && cur.RxBytes >= old.RxBytes && cur.TxBytes >= old.TxBytes {
			ifc.RxBps = float64(cur.RxBytes-old.RxBytes) / dt
			ifc.TxBps = float64(cur.TxBytes-old.TxBytes) / dt
		}
		s.Interfaces = append(s.Interfaces, ifc)
	}
	sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].Name < s.Interfaces[j].Name })

	ectx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if c.Extras.FailedUnits != nil {
		if v, err := c.Extras.FailedUnits(ectx); err == nil {
			s.FailedUnits = &v
		}
	}
	if c.Extras.CertDays != nil {
		if v, err := c.Extras.CertDays(); err == nil {
			s.CertDays = &v
		}
	}
	if c.Extras.Updates != nil {
		if v, err := c.Extras.Updates(); err == nil {
			s.Updates = &v
		}
	}
	if c.Extras.Logins != nil {
		if v, err := c.Extras.Logins(5); err == nil {
			s.Logins = v
		}
	}

	c.mu.Lock()
	c.snap, c.procs = s, procs
	c.prevCPU, c.prevTicks, c.prevNet, c.prevTime = cpu, Ticks(procs), net, now
	c.mu.Unlock()
}

// Snapshot returns the latest overview.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

// Processes returns the latest full process table (copy).
func (c *Collector) Processes() []Process {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Process(nil), c.procs...)
}
