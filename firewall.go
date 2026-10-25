package ollamawg

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Firewall filters UDP packets by source IP before WireGuard sees them, and
// records every source that talks to the WireGuard port (like an iptables
// LOG rule with per-source counters). Dropped packets never reach the
// handshake or decryption code.
type Firewall struct {
	obs *Observer

	rulesMu sync.RWMutex
	deny    bool // default policy
	rules   []fwRule

	srcMu   sync.Mutex
	sources map[netip.Addr]*SourceStat

	dropped atomic.Uint64
	passed  atomic.Uint64
}

type fwRule struct {
	FirewallRule
	prefix netip.Prefix
	hits   *atomic.Uint64
}

// SourceStat is what the firewall knows about one remote UDP source.
type SourceStat struct {
	IP        string    `json:"ip"`
	Port      uint16    `json:"port"`
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	Dropped   uint64    `json:"dropped"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	DeviceID  string    `json:"device_id,omitempty"`
	Device    string    `json:"device,omitempty"`
	Rule      string    `json:"rule,omitempty"` // rule that last matched

	lastDropLog time.Time
	dropsSince  uint64
}

const maxSources = 4096

// NewFirewall creates a firewall from config rules.
func NewFirewall(cfg FirewallSection, obs *Observer) (*Firewall, error) {
	f := &Firewall{obs: obs, sources: map[netip.Addr]*SourceStat{}}
	return f, f.SetRules(cfg)
}

// SetRules atomically replaces the rule set. Hit counters are kept for rules
// that still exist.
func (f *Firewall) SetRules(cfg FirewallSection) error {
	old := map[string]uint64{}
	f.rulesMu.RLock()
	for i := range f.rules {
		old[f.rules[i].Action+" "+f.rules[i].prefix.String()] = f.rules[i].hits.Load()
	}
	f.rulesMu.RUnlock()

	rules := make([]fwRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		p, err := parseCIDR(r.CIDR)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r.CIDR, err)
		}
		fr := fwRule{FirewallRule: r, prefix: p, hits: new(atomic.Uint64)}
		fr.hits.Store(old[r.Action+" "+p.String()])
		rules = append(rules, fr)
	}
	// Most specific prefix first, block before allow on ties.
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].prefix.Bits() != rules[j].prefix.Bits() {
			return rules[i].prefix.Bits() > rules[j].prefix.Bits()
		}
		return rules[i].Action == "block" && rules[j].Action != "block"
	})
	f.rulesMu.Lock()
	f.rules = rules
	f.deny = cfg.Default == "deny"
	f.rulesMu.Unlock()
	return nil
}

// verdict returns whether a packet from ip may pass, and the matching rule.
func (f *Firewall) verdict(ip netip.Addr) (bool, string) {
	f.rulesMu.RLock()
	defer f.rulesMu.RUnlock()
	for i := range f.rules {
		r := &f.rules[i]
		if r.prefix.Contains(ip) {
			r.hits.Add(1)
			return r.Action == "allow", r.Action + " " + r.prefix.String()
		}
	}
	if f.deny {
		return false, "default deny"
	}
	return true, ""
}

// Allowed reports whether ip would currently pass the firewall.
func (f *Firewall) Allowed(ip netip.Addr) bool {
	ok, _ := f.verdict(ip.Unmap())
	return ok
}

func (f *Firewall) observe(ap netip.AddrPort, size int) bool {
	ip := ap.Addr().Unmap()
	ok, rule := f.verdict(ip)
	now := time.Now()

	f.srcMu.Lock()
	s := f.sources[ip]
	if s == nil {
		if len(f.sources) >= maxSources {
			f.evictLocked()
		}
		s = &SourceStat{IP: ip.String(), FirstSeen: now}
		f.sources[ip] = s
	}
	s.Port = ap.Port()
	s.LastSeen = now
	s.Packets++
	s.Bytes += uint64(size)
	if rule != "" {
		s.Rule = rule
	}
	var logDrop uint64
	if !ok {
		s.Dropped++
		s.dropsSince++
		// Rate-limit drop logging to one event per source per minute.
		if now.Sub(s.lastDropLog) >= time.Minute {
			logDrop = s.dropsSince
			s.dropsSince = 0
			s.lastDropLog = now
		}
	}
	dev := s.Device
	f.srcMu.Unlock()

	if ok {
		f.passed.Add(1)
		return true
	}
	f.dropped.Add(1)
	if f.obs != nil {
		f.obs.recordDrop()
		if logDrop > 0 {
			msg := fmt.Sprintf("DROP udp from %s (%s), %d packet(s)", ap, rule, logDrop)
			if dev != "" {
				msg += ", last seen as device " + dev
			}
			f.obs.Event("firewall", "block", msg, ip.String(), "")
		}
	}
	return false
}

func (f *Firewall) evictLocked() {
	var oldest netip.Addr
	var t time.Time
	for ip, s := range f.sources {
		if t.IsZero() || s.LastSeen.Before(t) {
			oldest, t = ip, s.LastSeen
		}
	}
	delete(f.sources, oldest)
}

// tagSource links a source IP to the device whose WireGuard endpoint it is.
func (f *Firewall) tagSource(ap netip.AddrPort, deviceID, name string) {
	ip := ap.Addr().Unmap()
	f.srcMu.Lock()
	if s := f.sources[ip]; s != nil {
		s.DeviceID, s.Device = deviceID, name
	}
	f.srcMu.Unlock()
}

// Sources returns a snapshot of observed UDP sources, most recent first.
func (f *Firewall) Sources() []SourceStat {
	f.srcMu.Lock()
	out := make([]SourceStat, 0, len(f.sources))
	for _, s := range f.sources {
		out = append(out, *s)
	}
	f.srcMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// RuleStat is a rule plus its hit counter.
type RuleStat struct {
	FirewallRule
	Hits uint64 `json:"hits"`
}

// Rules returns the active rules with hit counts and the default policy.
func (f *Firewall) Rules() ([]RuleStat, string) {
	f.rulesMu.RLock()
	defer f.rulesMu.RUnlock()
	out := make([]RuleStat, len(f.rules))
	for i := range f.rules {
		out[i] = RuleStat{FirewallRule: f.rules[i].FirewallRule, Hits: f.rules[i].hits.Load()}
		out[i].CIDR = f.rules[i].prefix.String()
	}
	def := "allow"
	if f.deny {
		def = "deny"
	}
	return out, def
}

// Counters returns total passed and dropped packets.
func (f *Firewall) Counters() (passed, dropped uint64) {
	return f.passed.Load(), f.dropped.Load()
}

// Bind wraps a WireGuard conn.Bind so every received datagram is checked
// against the firewall first.
func (f *Firewall) Bind(inner conn.Bind) conn.Bind { return &filterBind{Bind: inner, fw: f} }

type filterBind struct {
	conn.Bind
	fw *Firewall
}

func (b *filterBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrap(fn)
	}
	return wrapped, actual, nil
}

func (b *filterBind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil || n == 0 {
				return n, err
			}
			kept := 0
			for i := 0; i < n; i++ {
				ap, perr := netip.ParseAddrPort(eps[i].DstToString())
				if perr != nil {
					ap = netip.AddrPortFrom(eps[i].DstIP(), 0)
				}
				if !b.fw.observe(ap, sizes[i]) {
					continue
				}
				if kept != i {
					// The device reads packet i from its own buffer i, so
					// move the bytes rather than the slice headers.
					copy(bufs[kept][:sizes[i]], bufs[i][:sizes[i]])
					sizes[kept] = sizes[i]
					eps[kept] = eps[i]
				}
				kept++
			}
			if kept > 0 {
				return kept, nil
			}
			// Everything in this batch was dropped; wait for more.
		}
	}
}
