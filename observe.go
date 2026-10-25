package ollamawg

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// AccessEntry is one proxied (or denied) request.
type AccessEntry struct {
	Time             time.Time `json:"time"`
	DeviceID         string    `json:"device_id"`
	Device           string    `json:"device"`
	TunnelIP         string    `json:"tunnel_ip"`
	RemoteIP         string    `json:"remote_ip,omitempty"` // device's public endpoint
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	Model            string    `json:"model,omitempty"`
	Status           int       `json:"status"`
	DurationMs       int64     `json:"duration_ms"`
	BytesOut         int64     `json:"bytes_out"`
	PromptTokens     int       `json:"prompt_tokens,omitempty"`
	CompletionTokens int       `json:"completion_tokens,omitempty"`
	Denied           string    `json:"denied,omitempty"`
}

// Event is a security or lifecycle event (firewall drop, device connect,
// policy denial, admin action...).
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`  // firewall | device | policy | admin | system
	Level    string    `json:"level"` // info | warn | block
	Message  string    `json:"message"`
	IP       string    `json:"ip,omitempty"`
	DeviceID string    `json:"device_id,omitempty"`
}

type ring[T any] struct {
	buf  []T
	next int
	full bool
}

func newRing[T any](n int) *ring[T] { return &ring[T]{buf: make([]T, n)} }

func (r *ring[T]) add(v T) {
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// newest returns up to limit items, newest first, that satisfy keep.
func (r *ring[T]) newest(limit int, keep func(*T) bool) []T {
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	out := make([]T, 0, min(limit, n))
	for i := 0; i < n && len(out) < limit; i++ {
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		if keep == nil || keep(&r.buf[idx]) {
			out = append(out, r.buf[idx])
		}
	}
	return out
}

const seriesMinutes = 24 * 60

type bucket struct {
	minute           int64
	Requests         int64
	Errors           int64
	Denied           int64
	PromptTokens     int64
	CompletionTokens int64
	BytesOut         int64
}

type deviceSeries [seriesMinutes]bucket

// ModelStat aggregates usage per model since the server started.
type ModelStat struct {
	Model            string `json:"model"`
	Requests         int64  `json:"requests"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
}

// Observer keeps the in-memory access log, events, per-minute series for
// the last 24 hours and cumulative counters for /metrics.
type Observer struct {
	mu      sync.Mutex
	access  *ring[AccessEntry]
	events  *ring[Event]
	series  map[string]*deviceSeries // deviceID -> per-minute buckets
	drops   [seriesMinutes]struct{ minute, n int64 }
	models  map[string]*ModelStat
	totals  map[string]*deviceTotals
	logFile *os.File
	onEvent func(Event)

	requests atomic.Int64
}

type deviceTotals struct {
	Requests, Errors, Denied, PromptTokens, CompletionTokens, BytesOut int64
	byStatus                                                           map[int]int64
}

// NewObserver creates an observer keeping size recent log entries. If
// logPath is set, access entries are also appended there as JSON lines.
func NewObserver(size int, logPath string) (*Observer, error) {
	if size <= 0 {
		size = 2000
	}
	o := &Observer{
		access: newRing[AccessEntry](size),
		events: newRing[Event](size),
		series: map[string]*deviceSeries{},
		models: map[string]*ModelStat{},
		totals: map[string]*deviceTotals{},
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		o.logFile = f
	}
	return o, nil
}

// Close flushes and closes the access log file.
func (o *Observer) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.logFile != nil {
		err := o.logFile.Close()
		o.logFile = nil
		return err
	}
	return nil
}

func nowMinute(t time.Time) int64 { return t.Unix() / 60 }

// Record adds an access entry.
func (o *Observer) Record(e AccessEntry) {
	o.requests.Add(1)
	m := nowMinute(e.Time)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.access.add(e)
	s := o.series[e.DeviceID]
	if s == nil {
		s = new(deviceSeries)
		o.series[e.DeviceID] = s
	}
	b := &s[m%seriesMinutes]
	if b.minute != m {
		*b = bucket{minute: m}
	}
	t := o.totals[e.DeviceID]
	if t == nil {
		t = &deviceTotals{byStatus: map[int]int64{}}
		o.totals[e.DeviceID] = t
	}
	b.Requests++
	t.Requests++
	t.byStatus[e.Status]++
	if e.Denied != "" {
		b.Denied++
		t.Denied++
	} else if e.Status >= 400 {
		b.Errors++
		t.Errors++
	}
	b.PromptTokens += int64(e.PromptTokens)
	b.CompletionTokens += int64(e.CompletionTokens)
	b.BytesOut += e.BytesOut
	t.PromptTokens += int64(e.PromptTokens)
	t.CompletionTokens += int64(e.CompletionTokens)
	t.BytesOut += e.BytesOut
	if e.Model != "" && e.Denied == "" {
		ms := o.models[e.Model]
		if ms == nil {
			ms = &ModelStat{Model: e.Model}
			o.models[e.Model] = ms
		}
		ms.Requests++
		ms.PromptTokens += int64(e.PromptTokens)
		ms.CompletionTokens += int64(e.CompletionTokens)
	}
	if o.logFile != nil {
		if b, err := json.Marshal(e); err == nil {
			o.logFile.Write(append(b, '\n'))
		}
	}
}

func (o *Observer) recordDrop() {
	m := nowMinute(time.Now())
	o.mu.Lock()
	d := &o.drops[m%seriesMinutes]
	if d.minute != m {
		d.minute, d.n = m, 0
	}
	d.n++
	o.mu.Unlock()
}

// Event records a security or lifecycle event.
func (o *Observer) Event(kind, level, msg, ip, deviceID string) {
	e := Event{Time: time.Now().UTC(), Kind: kind, Level: level, Message: msg, IP: ip, DeviceID: deviceID}
	o.mu.Lock()
	o.events.add(e)
	cb := o.onEvent
	o.mu.Unlock()
	if cb != nil {
		cb(e)
	}
}

// Access returns recent access entries, newest first, optionally filtered.
func (o *Observer) Access(limit int, deviceID string, deniedOnly bool) []AccessEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.access.newest(limit, func(e *AccessEntry) bool {
		return (deviceID == "" || e.DeviceID == deviceID) && (!deniedOnly || e.Denied != "")
	})
}

// Events returns recent events, newest first, optionally by kind.
func (o *Observer) Events(limit int, kind string) []Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.events.newest(limit, func(e *Event) bool { return kind == "" || e.Kind == kind })
}

// SeriesPoint is one time step of a device series.
type SeriesPoint struct {
	Requests         int64 `json:"requests"`
	Errors           int64 `json:"errors"`
	Denied           int64 `json:"denied"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	BytesOut         int64 `json:"bytes_out"`
}

// Series is the time series payload served to the dashboard.
type Series struct {
	Step    int                      `json:"step_seconds"`
	Start   time.Time                `json:"start"`
	Times   []time.Time              `json:"times"`
	Devices map[string][]SeriesPoint `json:"devices"`
	Drops   []int64                  `json:"drops"`
}

// Series aggregates the last window into steps of step minutes.
func (o *Observer) Series(window time.Duration, stepMin int) Series {
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	if stepMin < 1 {
		stepMin = 1
	}
	now := nowMinute(time.Now())
	// Align steps so the last step ends at the current minute.
	steps := int(window.Minutes()) / stepMin
	first := now - int64(steps*stepMin) + 1
	out := Series{Step: stepMin * 60, Devices: map[string][]SeriesPoint{}, Drops: make([]int64, steps)}
	for i := 0; i < steps; i++ {
		out.Times = append(out.Times, time.Unix((first+int64(i*stepMin))*60, 0).UTC())
	}
	out.Start = time.Unix(first*60, 0).UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	for id, s := range o.series {
		pts := make([]SeriesPoint, steps)
		any := false
		for m := first; m <= now; m++ {
			b := &s[m%seriesMinutes]
			if b.minute != m || b.Requests == 0 {
				continue
			}
			p := &pts[int(m-first)/stepMin]
			p.Requests += b.Requests
			p.Errors += b.Errors
			p.Denied += b.Denied
			p.PromptTokens += b.PromptTokens
			p.CompletionTokens += b.CompletionTokens
			p.BytesOut += b.BytesOut
			any = true
		}
		if any {
			out.Devices[id] = pts
		}
	}
	for m := first; m <= now; m++ {
		d := o.drops[m%seriesMinutes]
		if d.minute == m {
			out.Drops[int(m-first)/stepMin] += d.n
		}
	}
	return out
}

// Models returns per-model usage, busiest first.
func (o *Observer) Models() []ModelStat {
	o.mu.Lock()
	out := make([]ModelStat, 0, len(o.models))
	for _, m := range o.models {
		out = append(out, *m)
	}
	o.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].PromptTokens+out[i].CompletionTokens, out[j].PromptTokens+out[j].CompletionTokens
		if ti != tj {
			return ti > tj
		}
		return out[i].Requests > out[j].Requests
	})
	return out
}

// window24h sums the last 24h for one device (or all, with id "").
func (o *Observer) window24h(id string) SeriesPoint {
	now := nowMinute(time.Now())
	var p SeriesPoint
	o.mu.Lock()
	defer o.mu.Unlock()
	for dev, s := range o.series {
		if id != "" && dev != id {
			continue
		}
		for i := range s {
			b := &s[i]
			if b.minute > now-seriesMinutes && b.minute <= now {
				p.Requests += b.Requests
				p.Errors += b.Errors
				p.Denied += b.Denied
				p.PromptTokens += b.PromptTokens
				p.CompletionTokens += b.CompletionTokens
				p.BytesOut += b.BytesOut
			}
		}
	}
	return p
}

func (o *Observer) drops24h() int64 {
	now := nowMinute(time.Now())
	var n int64
	o.mu.Lock()
	for _, d := range o.drops {
		if d.minute > now-seriesMinutes && d.minute <= now {
			n += d.n
		}
	}
	o.mu.Unlock()
	return n
}
