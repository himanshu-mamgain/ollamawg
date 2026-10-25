package ollamawg

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Version of ollamawg.
var Version = "0.2.0"

// onlineWindow is how recent a handshake must be for a device to count as
// connected. WireGuard rejects sessions older than 180 s, and clients with a
// keepalive rekey every 120 s.
const onlineWindow = 185 * time.Second

// ServerOptions tunes a Server. All fields are optional.
type ServerOptions struct {
	// ConfigPath enables persistence: dashboard changes (blocks, firewall
	// rules, new devices) are saved to it, and edits made to the file while
	// the server runs (e.g. `ollamawg add-peer`) are picked up automatically.
	ConfigPath string
	Logger     *slog.Logger
	// Bind overrides the UDP socket layer (mainly for tests).
	Bind conn.Bind
}

// Server terminates WireGuard in user space (no root, no kernel module, no
// TUN device) and exposes Ollama inside the tunnel through an
// access-controlled, logged reverse proxy. Nothing outside the tunnel can
// reach Ollama through it.
type Server struct {
	opts ServerOptions
	log  *slog.Logger

	mu    sync.RWMutex
	cfg   *ServerConfig
	peers map[netip.Addr]*peerState // by tunnel IP
	byKey map[Key]*peerState

	editMu  sync.Mutex // serializes config edits
	cfgMod  time.Time
	devKeys map[Key]bool // peers currently loaded into the WireGuard device

	dev      *device.Device
	tnet     *netstack.Net
	fw       *Firewall
	obs      *Observer
	proxy    *httputil.ReverseProxy
	upstream *url.URL
	started  time.Time
	port     uint16
	admin    string

	lastPoll  atomic.Int64
	upOK      atomic.Bool
	upChecked atomic.Bool
	upVersion atomic.Value // string
	ready     chan struct{}
}

type peerState struct {
	cfg     PeerConfig
	id      string
	addr    netip.Addr
	limiter *rate.Limiter

	endpoint      netip.AddrPort
	lastHandshake time.Time
	rx, tx        uint64
	online        bool
	info          ClientInfo
}

// ClientInfo is what a client reports about itself when it connects. It is
// informational (self-reported); identity comes from the WireGuard key.
type ClientInfo struct {
	Hostname string    `json:"hostname,omitempty"`
	OS       string    `json:"os,omitempty"`
	Arch     string    `json:"arch,omitempty"`
	Version  string    `json:"version,omitempty"`
	At       time.Time `json:"at,omitempty"`
}

// NewServer validates cfg and prepares a server. Call Run to start it.
func NewServer(cfg *ServerConfig, opts ServerOptions) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	up, err := url.Parse(cfg.Server.Upstream)
	if err != nil {
		return nil, err
	}
	obs, err := NewObserver(cfg.Admin.LogBuffer, cfg.Admin.AccessLogFile)
	if err != nil {
		return nil, fmt.Errorf("access log: %w", err)
	}
	fw, err := NewFirewall(cfg.Firewall, obs)
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts: opts, log: opts.Logger, cfg: cfg, fw: fw, obs: obs, upstream: up,
		devKeys: map[Key]bool{}, ready: make(chan struct{}),
	}
	s.upVersion.Store("")
	if opts.ConfigPath != "" {
		if st, err := os.Stat(opts.ConfigPath); err == nil {
			s.cfgMod = st.ModTime()
		}
	}
	s.indexPeers(cfg)
	srvPfx, _ := cfg.ServerPrefix()
	tunnelOrigin := fmt.Sprintf("http://%s:%d", srvPfx.Addr(), cfg.Server.ProxyPort)
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(up)
			r.Out.Header.Del("Authorization") // never leak client creds upstream
			// The built-in chat page (/chat) is served from the tunnel address,
			// an origin Ollama's CORS check doesn't know. Its requests are
			// same-origin, so drop Origin for them only. Matching the literal
			// tunnel IP, not any Host, keeps DNS-rebinding pages (whose Origin
			// and Host carry their own domain) subject to Ollama's check.
			if o := r.In.Header.Get("Origin"); o == tunnelOrigin && "http://"+r.In.Host == tunnelOrigin {
				r.Out.Header.Del("Origin")
			}
		},
		Transport: &http.Transport{
			Proxy:               nil, // never send Ollama traffic through an env proxy
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     90 * time.Second,
		},
		FlushInterval: -1, // stream tokens as soon as Ollama produces them
		ModifyResponse: func(resp *http.Response) error {
			if e, ok := resp.Request.Context().Value(entryKey{}).(*AccessEntry); ok && resp.Body != nil {
				resp.Body = &usageSniffer{ReadCloser: resp.Body, onClose: func(p, c int, n int64) {
					e.PromptTokens, e.CompletionTokens = p, c
				}}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("upstream error", "path", r.URL.Path, "err", err)
			writeJSONError(w, http.StatusBadGateway, "ollama upstream unavailable")
		},
	}
	return s, nil
}

// Observer exposes the server's logs and metrics (for embedding).
func (s *Server) Observer() *Observer { return s.obs }

// Firewall exposes the packet filter (for embedding).
func (s *Server) Firewall() *Firewall { return s.fw }

// Ready is closed once the tunnel and proxy are up.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// ListenPort returns the UDP port WireGuard is bound to (after Ready).
func (s *Server) ListenPort() uint16 { return s.port }

// AdminAddr returns the dashboard's listen address (after Ready), or "" if
// the dashboard is disabled.
func (s *Server) AdminAddr() string { return s.admin }

func (s *Server) indexPeers(cfg *ServerConfig) {
	peers := map[netip.Addr]*peerState{}
	byKey := map[Key]*peerState{}
	for _, pc := range cfg.Peers {
		addr, _ := netip.ParseAddr(pc.Address)
		ps := &peerState{cfg: pc, id: pc.PublicKey.DeviceID(), addr: addr}
		if old := s.byKey[pc.PublicKey]; old != nil {
			ps.endpoint, ps.lastHandshake, ps.rx, ps.tx = old.endpoint, old.lastHandshake, old.rx, old.tx
			ps.online, ps.info = old.online, old.info
			if old.cfg.RPM == pc.RPM {
				ps.limiter = old.limiter
			}
		}
		if pc.RPM > 0 && ps.limiter == nil {
			ps.limiter = rate.NewLimiter(rate.Limit(float64(pc.RPM)/60), max(1, pc.RPM/2))
		}
		peers[addr] = ps
		byKey[pc.PublicKey] = ps
	}
	s.peers, s.byKey = peers, byKey
}

// Run starts the tunnel, proxy and (if configured) the admin dashboard, and
// blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	pfx, _ := cfg.ServerPrefix()

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{pfx.Addr()}, nil, cfg.Server.MTU)
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	s.tnet = tnet
	bind := s.opts.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	s.dev = device.NewDevice(tun, s.fw.Bind(bind), &device.Logger{
		Verbosef: func(f string, a ...any) { s.log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { s.log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
	})
	defer s.dev.Close()

	if err := s.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", cfg.Server.PrivateKey.Hex(), cfg.Server.ListenPort)); err != nil {
		return fmt.Errorf("wireguard config: %w", err)
	}
	if err := s.syncPeers(cfg); err != nil {
		return err
	}
	if err := s.dev.Up(); err != nil {
		return fmt.Errorf("wireguard up: %w", err)
	}
	s.port = uint16(cfg.Server.ListenPort)
	if p := s.readListenPort(); p != 0 {
		s.port = p
	}

	ln, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(pfx.Addr(), uint16(cfg.Server.ProxyPort)))
	if err != nil {
		return fmt.Errorf("tunnel listener: %w", err)
	}
	proxySrv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 2)
	go func() { errc <- proxySrv.Serve(ln) }()

	var adminSrv *http.Server
	if cfg.Admin.Password != "" {
		aln, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			return fmt.Errorf("admin listener: %w", err)
		}
		s.admin = aln.Addr().String()
		adminSrv = &http.Server{Handler: s.adminHandler(), ReadHeaderTimeout: 10 * time.Second}
		go func() { errc <- adminSrv.Serve(aln) }()
		s.log.Info("dashboard listening", "url", "http://"+aln.Addr().String(), "user", "admin")
	}

	s.started = time.Now()
	s.obs.Event("system", "info", fmt.Sprintf("server started: wireguard udp/%d, ollama at %s:%d inside the tunnel", s.port, pfx.Addr(), cfg.Server.ProxyPort), "", "")
	s.log.Info("wireguard listening", "udp_port", s.port, "public_key", cfg.Server.PrivateKey.PublicKey().String(), "tunnel", fmt.Sprintf("%s:%d", pfx.Addr(), cfg.Server.ProxyPort), "upstream", cfg.Server.Upstream, "peers", len(cfg.Peers))
	s.checkUpstream(ctx)
	close(s.ready)

	go s.loop(ctx)

	select {
	case <-ctx.Done():
	case err = <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxySrv.Shutdown(sctx)
	if adminSrv != nil {
		_ = adminSrv.Shutdown(sctx)
	}
	_ = s.obs.Close()
	return err
}

func (s *Server) loop(ctx context.Context) {
	stats := time.NewTicker(3 * time.Second)
	health := time.NewTicker(15 * time.Second)
	watch := time.NewTicker(2 * time.Second)
	defer stats.Stop()
	defer health.Stop()
	defer watch.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stats.C:
			s.lastPoll.Store(time.Now().UnixMilli())
			s.pollStats()
		case <-health.C:
			s.checkUpstream(ctx)
		case <-watch.C:
			s.watchConfig()
		}
	}
}

func (s *Server) readListenPort() uint16 {
	st, _ := s.dev.IpcGet()
	for _, line := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			p, _ := strconv.Atoi(v)
			return uint16(p)
		}
	}
	return 0
}

// syncPeers makes the WireGuard device match cfg: blocked or deleted peers
// are removed (their sessions die immediately), others added or updated in
// place without dropping live sessions.
func (s *Server) syncPeers(cfg *ServerConfig) error {
	var b strings.Builder
	want := map[Key]bool{}
	for _, p := range cfg.Peers {
		if p.Blocked {
			continue
		}
		want[p.PublicKey] = true
		fmt.Fprintf(&b, "public_key=%s\npreshared_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n",
			p.PublicKey.Hex(), p.PresharedKey.Hex(), p.Address)
	}
	for k := range s.devKeys {
		if !want[k] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k.Hex())
		}
	}
	if b.Len() > 0 {
		if err := s.dev.IpcSet(b.String()); err != nil {
			return fmt.Errorf("wireguard peers: %w", err)
		}
	}
	s.devKeys = want
	return nil
}

// pollStatsSoon runs pollStats unless it ran in the last 500 ms.
func (s *Server) pollStatsSoon() {
	now := time.Now().UnixMilli()
	if last := s.lastPoll.Load(); now-last < 500 || !s.lastPoll.CompareAndSwap(last, now) {
		return
	}
	s.pollStats()
}

// pollStats reads per-peer handshake/endpoint/traffic counters from
// WireGuard and emits connect/disconnect/roam events.
func (s *Server) pollStats() {
	raw, err := s.dev.IpcGet()
	if err != nil {
		return
	}
	type st struct {
		ep     netip.AddrPort
		hs     time.Time
		rx, tx uint64
	}
	stats := map[Key]*st{}
	var cur *st
	sc := bufio.NewScanner(strings.NewReader(raw))
	var hsSec int64
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "public_key":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 32 {
				cur = nil
				continue
			}
			var key Key
			copy(key[:], b)
			cur = &st{}
			stats[key] = cur
		case "endpoint":
			if cur != nil {
				cur.ep, _ = netip.ParseAddrPort(v)
			}
		case "last_handshake_time_sec":
			hsSec, _ = strconv.ParseInt(v, 10, 64)
			if cur != nil && hsSec > 0 {
				cur.hs = time.Unix(hsSec, 0)
			}
		case "rx_bytes":
			if cur != nil {
				cur.rx, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.tx, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	now := time.Now()
	type ev struct{ level, msg, ip, id string }
	var evs []ev
	s.mu.Lock()
	for key, ps := range s.byKey {
		x := stats[key]
		if x == nil {
			if ps.online {
				ps.online = false
				evs = append(evs, ev{"info", fmt.Sprintf("device %s disconnected (blocked or removed)", ps.cfg.Name), "", ps.id})
			}
			continue
		}
		online := !x.hs.IsZero() && now.Sub(x.hs) < onlineWindow
		if x.ep.IsValid() {
			if ps.endpoint.IsValid() && ps.endpoint.Addr() != x.ep.Addr() && online {
				evs = append(evs, ev{"warn", fmt.Sprintf("device %s roamed %s -> %s", ps.cfg.Name, ps.endpoint, x.ep), x.ep.Addr().String(), ps.id})
			}
			ps.endpoint = x.ep
			s.fw.tagSource(x.ep, ps.id, ps.cfg.Name)
		}
		if online && !ps.online {
			evs = append(evs, ev{"info", fmt.Sprintf("device %s connected from %s", ps.cfg.Name, x.ep), x.ep.Addr().String(), ps.id})
		} else if !online && ps.online {
			evs = append(evs, ev{"info", fmt.Sprintf("device %s went offline (no handshake for %s)", ps.cfg.Name, onlineWindow.Round(time.Second)), "", ps.id})
		}
		ps.online, ps.lastHandshake, ps.rx, ps.tx = online, x.hs, x.rx, x.tx
	}
	s.mu.Unlock()
	for _, e := range evs {
		s.obs.Event("device", e.level, e.msg, e.ip, e.id)
	}
}

func (s *Server) checkUpstream(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.upstream.String(), "/")+"/api/version", nil)
	resp, err := s.proxy.Transport.RoundTrip(req)
	ok := err == nil && resp.StatusCode == http.StatusOK
	if err == nil {
		var v struct{ Version string }
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v)
		resp.Body.Close()
		s.upVersion.Store(v.Version)
	}
	if was := s.upOK.Swap(ok); was != ok || !s.upChecked.Swap(true) {
		if ok {
			s.obs.Event("system", "info", "ollama upstream reachable at "+s.upstream.String(), "", "")
		} else {
			s.obs.Event("system", "warn", "ollama upstream unreachable at "+s.upstream.String(), "", "")
		}
	}
}

// watchConfig reloads the config file if something else changed it.
func (s *Server) watchConfig() {
	if s.opts.ConfigPath == "" {
		return
	}
	st, err := os.Stat(s.opts.ConfigPath)
	if err != nil {
		return
	}
	s.editMu.Lock()
	changed := !st.ModTime().Equal(s.cfgMod)
	s.editMu.Unlock()
	if changed {
		if err := s.Reload(); err != nil {
			s.log.Error("config reload failed; keeping previous config", "err", err)
			s.obs.Event("system", "warn", "config reload failed: "+err.Error(), "", "")
		}
	}
}

// Reload re-reads the config file and applies peers, roles and firewall
// rules without dropping live sessions. Listener settings need a restart.
func (s *Server) Reload() error {
	if s.opts.ConfigPath == "" {
		return errors.New("no config path")
	}
	s.editMu.Lock()
	defer s.editMu.Unlock()
	if st, err := os.Stat(s.opts.ConfigPath); err == nil {
		s.cfgMod = st.ModTime()
	}
	cfg, err := LoadServerConfig(s.opts.ConfigPath)
	if err != nil {
		return err
	}
	if err := s.applyLocked(cfg); err != nil {
		return err
	}
	s.obs.Event("system", "info", fmt.Sprintf("config reloaded: %d device(s), %d firewall rule(s)", len(cfg.Peers), len(cfg.Firewall.Rules)), "", "")
	s.log.Info("config reloaded", "peers", len(cfg.Peers))
	return nil
}

// applyLocked swaps in a new config. Caller holds editMu.
func (s *Server) applyLocked(cfg *ServerConfig) error {
	if err := s.fw.SetRules(cfg.Firewall); err != nil {
		return err
	}
	s.mu.Lock()
	old := s.cfg
	s.cfg = cfg
	s.indexPeers(cfg)
	s.mu.Unlock()
	if s.dev != nil {
		if err := s.syncPeers(cfg); err != nil {
			return err
		}
	}
	if old.Server.Upstream != cfg.Server.Upstream || old.Server.ListenPort != cfg.Server.ListenPort ||
		old.Server.Address != cfg.Server.Address || old.Server.PrivateKey != cfg.Server.PrivateKey {
		s.log.Warn("server section changed; restart ollamawg to apply it")
	}
	return nil
}

// edit applies fn to a copy of the config, validates, persists and applies it.
func (s *Server) edit(fn func(c *ServerConfig) error) error {
	s.editMu.Lock()
	defer s.editMu.Unlock()
	s.mu.RLock()
	cp, err := cloneConfig(s.cfg)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if err := fn(cp); err != nil {
		return err
	}
	if err := cp.Validate(); err != nil {
		return err
	}
	if s.opts.ConfigPath != "" {
		if err := cp.Save(s.opts.ConfigPath); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		if st, err := os.Stat(s.opts.ConfigPath); err == nil {
			s.cfgMod = st.ModTime()
		}
	}
	return s.applyLocked(cp)
}

func cloneConfig(c *ServerConfig) (*ServerConfig, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var out ServerConfig
	return &out, json.Unmarshal(b, &out)
}

type entryKey struct{}

// ServeHTTP is the in-tunnel proxy. The caller is identified by its tunnel
// source IP, which WireGuard binds cryptographically to its key.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "unknown peer")
		return
	}
	s.mu.RLock()
	ps := s.peers[ap.Addr().Unmap()]
	var (
		p      PeerConfig
		id     string
		ep     netip.AddrPort
		lim    *rate.Limiter
		role   RoleConfig
		roleOK bool
	)
	if ps != nil {
		p, id, ep, lim = ps.cfg, ps.id, ps.endpoint, ps.limiter
		role, roleOK = s.cfg.Role(p.Role)
	}
	maxBody := int64(s.cfg.Server.MaxBodyMB) << 20
	s.mu.RUnlock()
	if ps == nil {
		writeJSONError(w, http.StatusForbidden, "unknown peer")
		return
	}

	if !ep.IsValid() {
		// First request right after a handshake: learn the device's public
		// endpoint now instead of waiting for the next stats poll.
		s.pollStatsSoon()
		s.mu.RLock()
		ep = ps.endpoint
		s.mu.RUnlock()
	}
	if strings.HasPrefix(r.URL.Path, "/_ollamawg/") {
		s.serveInternal(w, r, ps)
		return
	}
	if isChatPath(r.URL.Path) && canonicalPath(r.URL) {
		serveChat(w, r)
		return
	}

	e := &AccessEntry{
		Time: start.UTC(), DeviceID: id, Device: p.Name, TunnelIP: p.Address,
		Method: r.Method, Path: r.URL.Path,
	}
	if ep.IsValid() {
		e.RemoteIP = ep.Addr().String()
	}
	deny := func(code int, reason string) {
		e.Status, e.Denied = code, reason
		e.DurationMs = time.Since(start).Milliseconds()
		s.obs.Record(*e)
		s.obs.Event("policy", "warn", fmt.Sprintf("DENY %s %s %s: %s", p.Name, r.Method, r.URL.Path, reason), e.RemoteIP, id)
		writeJSONError(w, code, reason)
	}

	switch {
	case p.Blocked:
		deny(http.StatusForbidden, "device is blocked")
		return
	case !canonicalPath(r.URL):
		// "/v1/../api/pull" or %2F tricks must not slip past prefix rules.
		deny(http.StatusBadRequest, "non-canonical request path")
		return
	case !roleOK || !pathAllowed(role, r.URL.Path):
		deny(http.StatusForbidden, fmt.Sprintf("role %q may not call %s", p.Role, r.URL.Path))
		return
	}
	hasBody := r.Body != nil && r.Body != http.NoBody
	var merr error
	e.Model, merr = readModel(r, len(p.Models) > 0, maxBody)
	switch {
	case errors.Is(merr, errBodyTooLarge):
		deny(http.StatusRequestEntityTooLarge, fmt.Sprintf("request body over %d MB", maxBody>>20))
		return
	case merr != nil:
		writeJSONError(w, http.StatusBadRequest, "could not read request body")
		return
	case len(p.Models) > 0 && hasBody && e.Model == "":
		deny(http.StatusForbidden, "this device has a model allowlist and the request names no model")
		return
	case len(p.Models) > 0 && hasBody && !modelAllowed(p.Models, e.Model):
		deny(http.StatusForbidden, fmt.Sprintf("model %q is not allowed for this device", e.Model))
		return
	}
	if lim != nil && !lim.Allow() {
		deny(http.StatusTooManyRequests, fmt.Sprintf("rate limit of %d requests/minute exceeded", p.RPM))
		return
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	s.proxy.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), entryKey{}, e)))
	e.Status = rw.status
	e.BytesOut = rw.n
	e.DurationMs = time.Since(start).Milliseconds()
	s.obs.Record(*e)
}

func (s *Server) serveInternal(w http.ResponseWriter, r *http.Request, ps *peerState) {
	switch r.URL.Path {
	case "/_ollamawg/hello":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		var info ClientInfo
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&info); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad hello")
			return
		}
		info.Hostname = clip(info.Hostname, 64)
		info.OS, info.Arch, info.Version = clip(info.OS, 16), clip(info.Arch, 16), clip(info.Version, 32)
		info.At = time.Now().UTC()
		s.mu.Lock()
		ps.info = info
		name, id, ep := ps.cfg.Name, ps.id, ps.endpoint
		s.mu.Unlock()
		ip := ""
		if ep.IsValid() {
			ip = ep.Addr().String()
		}
		s.obs.Event("device", "info", fmt.Sprintf("device %s checked in: host %q %s/%s, client %s", name, info.Hostname, info.OS, info.Arch, info.Version), ip, id)
		fallthrough
	case "/_ollamawg/whoami":
		s.mu.RLock()
		out := map[string]any{
			"device": ps.cfg.Name, "device_id": ps.id, "role": ps.cfg.Role, "address": ps.cfg.Address,
			"models": ps.cfg.Models, "rpm": ps.cfg.RPM, "blocked": ps.cfg.Blocked, "server_version": Version,
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, out)
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

func canonicalPath(u *url.URL) bool {
	p := u.Path
	if p == "" || p[0] != '/' || u.RawPath != "" || strings.Contains(p, "//") {
		return false
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c == p
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	n           int64
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
