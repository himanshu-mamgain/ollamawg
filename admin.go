package ollamawg

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

//go:embed ui
var uiFS embed.FS

// DeviceView is a device as shown by the dashboard and admin API.
type DeviceView struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	PublicKey     string      `json:"public_key"`
	Address       string      `json:"address"`
	Role          string      `json:"role"`
	Models        []string    `json:"models"`
	RPM           int         `json:"rpm"`
	Blocked       bool        `json:"blocked"`
	Created       time.Time   `json:"created"`
	Online        bool        `json:"online"`
	Endpoint      string      `json:"endpoint,omitempty"`
	LastHandshake *time.Time  `json:"last_handshake,omitempty"`
	RxBytes       uint64      `json:"rx_bytes"`
	TxBytes       uint64      `json:"tx_bytes"`
	Client        ClientInfo  `json:"client"`
	Last24h       SeriesPoint `json:"last24h"`
}

// Devices returns all devices with live tunnel stats.
func (s *Server) Devices() []DeviceView {
	s.mu.RLock()
	out := make([]DeviceView, 0, len(s.cfg.Peers))
	for _, pc := range s.cfg.Peers {
		ps := s.byKey[pc.PublicKey]
		v := DeviceView{
			ID: pc.PublicKey.DeviceID(), Name: pc.Name, PublicKey: pc.PublicKey.String(), Address: pc.Address,
			Role: pc.Role, Models: pc.Models, RPM: pc.RPM, Blocked: pc.Blocked, Created: pc.Created,
		}
		if v.Models == nil {
			v.Models = []string{}
		}
		if ps != nil {
			v.Online = ps.online
			if ps.endpoint.IsValid() {
				v.Endpoint = ps.endpoint.String()
			}
			if !ps.lastHandshake.IsZero() {
				t := ps.lastHandshake.UTC()
				v.LastHandshake = &t
			}
			v.RxBytes, v.TxBytes, v.Client = ps.rx, ps.tx, ps.info
		}
		out = append(out, v)
	}
	s.mu.RUnlock()
	for i := range out {
		out[i].Last24h = s.obs.window24h(out[i].ID)
	}
	return out
}

// BlockDevice removes a device from the tunnel (its session dies at once)
// and persists the block. ref is a name, device ID or public key.
func (s *Server) BlockDevice(ref string, blocked bool) (string, error) {
	var name, id string
	err := s.edit(func(c *ServerConfig) error {
		i := c.FindPeer(ref)
		if i < 0 {
			return fmt.Errorf("no device %q", ref)
		}
		c.Peers[i].Blocked = blocked
		name, id = c.Peers[i].Name, c.Peers[i].PublicKey.DeviceID()
		return nil
	})
	if err == nil {
		verb := "unblocked"
		if blocked {
			verb = "blocked"
		}
		s.obs.Event("admin", map[bool]string{true: "block", false: "info"}[blocked], fmt.Sprintf("device %s (%s) %s by admin", name, id, verb), "", id)
	}
	return name, err
}

// AddDevice creates a device and returns its client config (the only copy
// of its private key).
func (s *Server) AddDevice(name, role string) (*ClientConfig, error) {
	var cc *ClientConfig
	err := s.edit(func(c *ServerConfig) error {
		var err error
		cc, err = c.AddPeer(name, role)
		return err
	})
	if err == nil {
		s.obs.Event("admin", "info", fmt.Sprintf("device %s added (role %s, %s)", name, cc.Client.Address, roleOr(role)), "", cc.Client.PrivateKey.PublicKey().DeviceID())
	}
	return cc, err
}

// ReissueDevice gives a device a new key and returns its new client config.
// Its old key is dropped from WireGuard immediately.
func (s *Server) ReissueDevice(ref string) (*ClientConfig, error) {
	var cc *ClientConfig
	err := s.edit(func(c *ServerConfig) error {
		var err error
		cc, err = c.ReissuePeer(ref)
		return err
	})
	if err == nil {
		s.obs.Event("admin", "warn", fmt.Sprintf("device %s re-issued: new key, the old config no longer works", cc.Client.Name), "", cc.Client.PrivateKey.PublicKey().DeviceID())
	}
	return cc, err
}

func roleOr(r string) string {
	if r == "" {
		return "user"
	}
	return r
}

// BlockIP adds a firewall rule ("block" or "allow") for an IP or CIDR.
func (s *Server) BlockIP(action, cidr, note string) error {
	p, err := parseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR %q", cidr)
	}
	if action == "" {
		action = "block"
	}
	err = s.edit(func(c *ServerConfig) error {
		for _, r := range c.Firewall.Rules {
			if q, _ := parseCIDR(r.CIDR); q == p && r.Action == action {
				return fmt.Errorf("rule already exists")
			}
		}
		c.Firewall.Rules = append(c.Firewall.Rules, FirewallRule{Action: action, CIDR: p.String(), Note: clip(note, 120), Added: time.Now().UTC().Truncate(time.Second)})
		return nil
	})
	if err == nil {
		s.obs.Event("admin", map[bool]string{true: "block", false: "info"}[action == "block"], fmt.Sprintf("firewall: %s %s added by admin", action, p), p.Addr().String(), "")
	}
	return err
}

func (s *Server) handleAdminRemoveRule(cidr, action string) error {
	p, err := parseCIDR(cidr)
	if err != nil {
		return err
	}
	found := false
	err = s.edit(func(c *ServerConfig) error {
		rules := c.Firewall.Rules[:0]
		for _, r := range c.Firewall.Rules {
			if q, _ := parseCIDR(r.CIDR); q == p && (action == "" || r.Action == action) {
				found = true
				continue
			}
			rules = append(rules, r)
		}
		c.Firewall.Rules = rules
		if !found {
			return fmt.Errorf("no rule for %s", p)
		}
		return nil
	})
	if err == nil {
		s.obs.Event("admin", "info", fmt.Sprintf("firewall: rule for %s removed by admin", p), p.Addr().String(), "")
	}
	return err
}

type adminCtx struct {
	s        *Server
	loopback bool
	failLim  *rate.Limiter
	auth     *adminAuth
}

func (s *Server) adminHandler() http.Handler {
	s.mu.RLock()
	listen := s.cfg.Admin.Listen
	s.mu.RUnlock()
	host, _, _ := net.SplitHostPort(listen)
	ip, err := netip.ParseAddr(host)
	a := &adminCtx{s: s, loopback: host == "localhost" || (err == nil && ip.IsLoopback()), failLim: rate.NewLimiter(rate.Every(6*time.Second), 3), auth: newAdminAuth()}

	mux := http.NewServeMux()
	static, _ := fs.Sub(uiFS, "ui")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/overview", a.overview)
	mux.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.Devices()) })
	mux.HandleFunc("POST /api/devices", a.addDevice)
	mux.HandleFunc("PATCH /api/devices/{id}", a.patchDevice)
	mux.HandleFunc("POST /api/devices/{id}/block", func(w http.ResponseWriter, r *http.Request) { a.block(w, r, true) })
	mux.HandleFunc("POST /api/devices/{id}/unblock", func(w http.ResponseWriter, r *http.Request) { a.block(w, r, false) })
	mux.HandleFunc("POST /api/devices/{id}/reissue", a.reissueDevice)
	mux.HandleFunc("DELETE /api/devices/{id}", a.deleteDevice)
	mux.HandleFunc("GET /api/sources", func(w http.ResponseWriter, r *http.Request) { a.sources(w, r) })
	mux.HandleFunc("GET /api/firewall", a.firewall)
	mux.HandleFunc("POST /api/firewall", a.addRule)
	mux.HandleFunc("DELETE /api/firewall", a.removeRule)
	mux.HandleFunc("PUT /api/firewall/default", a.setDefault)
	mux.HandleFunc("GET /api/logs", a.logs)
	mux.HandleFunc("GET /api/events", a.events)
	mux.HandleFunc("GET /api/series", a.series)
	mux.HandleFunc("GET /api/models", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.obs.Models()) })
	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("GET /api/session", a.sessionInfo)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)
	mux.HandleFunc("GET /api/2fa", a.twoFactorStatus)
	mux.HandleFunc("POST /api/2fa/setup", a.twoFactorSetup)
	mux.HandleFunc("POST /api/2fa/enable", a.twoFactorEnable)
	mux.HandleFunc("POST /api/2fa/disable", a.twoFactorDisable)
	return a.guard(mux)
}

// guard enforces authentication (see admin_auth.go), DNS-rebinding and CSRF
// protection.
func (a *adminCtx) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

		if a.loopback {
			host := r.Host
			if hh, _, err := net.SplitHostPort(host); err == nil {
				host = hh
			}
			host = strings.Trim(host, "[]")
			if ip, err := netip.ParseAddr(host); !(host == "localhost" || (err == nil && ip.IsLoopback())) {
				http.Error(w, "forbidden host", http.StatusForbidden)
				return
			}
		}

		c := a.creds()
		ok, badBasic := a.authenticated(r, c)
		// With 2FA on, the page itself and the login endpoints must load
		// before there is a session. They hold no secrets.
		public := r.URL.Path == "/api/session" || r.URL.Path == "/api/login" || r.URL.Path == "/api/logout" ||
			(c.totpSecret != "" && r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/metrics")
		if !c.enabled() || (!ok && !public) {
			if badBasic && a.failLim.Allow() {
				a.s.obs.Event("admin", "warn", "dashboard login failed from "+r.RemoteAddr, hostOnly(r.RemoteAddr), "")
			}
			if badBasic {
				time.Sleep(300 * time.Millisecond)
			}
			if c.totpSecret == "" {
				h.Set("WWW-Authenticate", `Basic realm="ollamawg", charset="UTF-8"`)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Ollamawg") != "1" {
				http.Error(w, "missing X-Ollamawg header", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host && o != "https://"+r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func (a *adminCtx) overview(w http.ResponseWriter, r *http.Request) {
	s := a.s
	s.mu.RLock()
	cfg := s.cfg
	pfx, _ := cfg.ServerPrefix()
	total, online, blocked := len(cfg.Peers), 0, 0
	for _, p := range cfg.Peers {
		if p.Blocked {
			blocked++
		}
		if ps := s.byKey[p.PublicKey]; ps != nil && ps.online {
			online++
		}
	}
	out := map[string]any{
		"version":           Version,
		"server_public_key": cfg.Server.PrivateKey.PublicKey().String(),
		"public_endpoint":   cfg.Server.PublicEndpoint,
		"listen_port":       s.port,
		"tunnel":            fmt.Sprintf("%s:%d", pfx.Addr(), cfg.Server.ProxyPort),
		"subnet":            pfx.Masked().String(),
		"upstream":          cfg.Server.Upstream,
		"roles":             cfg.RoleNames(),
		"devices_total":     total,
		"devices_online":    online,
		"devices_blocked":   blocked,
	}
	s.mu.RUnlock()
	passed, dropped := s.fw.Counters()
	rules, def := s.fw.Rules()
	last := s.obs.window24h("")
	out["upstream_ok"] = s.upOK.Load()
	out["upstream_version"] = s.upVersion.Load()
	out["started"] = s.started.UTC()
	out["uptime_seconds"] = int64(time.Since(s.started).Seconds())
	out["packets_passed"] = passed
	out["packets_dropped"] = dropped
	out["firewall_default"] = def
	out["firewall_rules"] = len(rules)
	out["last24h"] = map[string]any{
		"requests": last.Requests, "errors": last.Errors, "denied": last.Denied,
		"prompt_tokens": last.PromptTokens, "completion_tokens": last.CompletionTokens,
		"bytes_out": last.BytesOut, "dropped_packets": s.obs.drops24h(),
	}
	writeJSON(w, 200, out)
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && err != io.EOF {
		return fmt.Errorf("bad JSON: %w", err)
	}
	return nil
}

func (a *adminCtx) addDevice(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Role string }
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	cc, err := a.s.AddDevice(strings.TrimSpace(req.Name), req.Role)
	if err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, configResponse(cc))
}

// POST /api/devices/{id}/reissue: a new key and config for an existing device.
func (a *adminCtx) reissueDevice(w http.ResponseWriter, r *http.Request) {
	cc, err := a.s.ReissueDevice(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, configResponse(cc))
}

// configResponse is a device's config in every form the dashboard offers:
// YAML for `ollamawg connect`, and wg-quick text plus QR for the WireGuard app.
func configResponse(cc *ClientConfig) map[string]any {
	y, _ := cc.Marshal()
	qr, _ := QRSVG(cc.WireGuardQRText())
	return map[string]any{
		"device_id": cc.Client.PrivateKey.PublicKey().DeviceID(), "name": cc.Client.Name,
		"address": cc.Client.Address, "filename": cc.Client.Name + ".yaml", "config": string(y),
		"wg_filename": cc.Client.Name + ".conf", "wg_config": cc.WireGuardConf(), "wg_qr_svg": qr,
		"chat_url": fmt.Sprintf("http://%s:%d/chat", cc.Client.ServerAddress, cc.Client.ServerPort),
	}
}

func (a *adminCtx) patchDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role   *string   `json:"role"`
		Models *[]string `json:"models"`
		RPM    *int      `json:"rpm"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	ref := r.PathValue("id")
	var name string
	err := a.s.edit(func(c *ServerConfig) error {
		i := c.FindPeer(ref)
		if i < 0 {
			return fmt.Errorf("no device %q", ref)
		}
		p := &c.Peers[i]
		name = p.Name
		if req.Role != nil {
			p.Role = *req.Role
		}
		if req.Models != nil {
			ms := []string{}
			for _, m := range *req.Models {
				if m = strings.TrimSpace(m); m != "" {
					ms = append(ms, clip(m, 120))
				}
			}
			p.Models = ms
		}
		if req.RPM != nil {
			if *req.RPM < 0 {
				return fmt.Errorf("rpm must be >= 0")
			}
			p.RPM = *req.RPM
		}
		return nil
	})
	if err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	a.s.obs.Event("admin", "info", fmt.Sprintf("device %s policy updated by admin", name), "", "")
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *adminCtx) block(w http.ResponseWriter, r *http.Request, b bool) {
	if _, err := a.s.BlockDevice(r.PathValue("id"), b); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *adminCtx) deleteDevice(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("id")
	var name, id string
	err := a.s.edit(func(c *ServerConfig) error {
		i := c.FindPeer(ref)
		if i < 0 {
			return fmt.Errorf("no device %q", ref)
		}
		name, id = c.Peers[i].Name, c.Peers[i].PublicKey.DeviceID()
		c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
		return nil
	})
	if err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	a.s.obs.Event("admin", "block", fmt.Sprintf("device %s (%s) deleted by admin; its key can no longer connect", name, id), "", id)
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *adminCtx) sources(w http.ResponseWriter, r *http.Request) {
	src := a.s.fw.Sources()
	limit := intParam(r, "limit", 500, 4096)
	if len(src) > limit {
		src = src[:limit]
	}
	type view struct {
		SourceStat
		Blocked bool `json:"blocked"`
	}
	out := make([]view, len(src))
	for i, s := range src {
		ip, _ := netip.ParseAddr(s.IP)
		out[i] = view{SourceStat: s, Blocked: !a.s.fw.Allowed(ip)}
	}
	writeJSON(w, 200, out)
}

func (a *adminCtx) firewall(w http.ResponseWriter, r *http.Request) {
	rules, def := a.s.fw.Rules()
	passed, dropped := a.s.fw.Counters()
	writeJSON(w, 200, map[string]any{"default": def, "rules": rules, "packets_passed": passed, "packets_dropped": dropped})
}

func (a *adminCtx) addRule(w http.ResponseWriter, r *http.Request) {
	var req struct{ Action, CIDR, Note string }
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	if req.Action != "" && req.Action != "block" && req.Action != "allow" {
		writeJSONError(w, 400, "action must be block or allow")
		return
	}
	if err := a.s.BlockIP(req.Action, req.CIDR, req.Note); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, map[string]string{"status": "ok"})
}

func (a *adminCtx) removeRule(w http.ResponseWriter, r *http.Request) {
	if err := a.s.handleAdminRemoveRule(r.URL.Query().Get("cidr"), r.URL.Query().Get("action")); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *adminCtx) setDefault(w http.ResponseWriter, r *http.Request) {
	var req struct{ Default string }
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	err := a.s.edit(func(c *ServerConfig) error {
		c.Firewall.Default = req.Default
		return nil
	})
	if err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	a.s.obs.Event("admin", "warn", "firewall default policy set to "+req.Default+" by admin", "", "")
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func intParam(r *http.Request, name string, def, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v <= 0 {
		return def
	}
	return min(v, max)
}

func (a *adminCtx) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	writeJSON(w, 200, a.s.obs.Access(intParam(r, "limit", 200, 5000), q.Get("device"), q.Get("denied") == "1"))
}

func (a *adminCtx) events(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.s.obs.Events(intParam(r, "limit", 200, 5000), r.URL.Query().Get("kind")))
}

func (a *adminCtx) series(w http.ResponseWriter, r *http.Request) {
	window, step := time.Hour, 1
	switch r.URL.Query().Get("window") {
	case "6h":
		window, step = 6*time.Hour, 5
	case "24h":
		window, step = 24*time.Hour, 15
	}
	writeJSON(w, 200, a.s.obs.Series(window, step))
}

// metrics serves Prometheus text exposition format.
func (a *adminCtx) metrics(w http.ResponseWriter, r *http.Request) {
	s := a.s
	var b strings.Builder
	esc := func(v string) string {
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
	}
	head := func(name, typ, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ) }
	b2i := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	names := map[string]string{}
	devs := s.Devices()
	for _, d := range devs {
		names[d.ID] = d.Name
	}

	head("ollamawg_up", "gauge", "Ollama upstream reachable (1) or not (0).")
	fmt.Fprintf(&b, "ollamawg_up %d\n", b2i(s.upOK.Load()))

	head("ollamawg_device_online", "gauge", "Device has a live WireGuard session.")
	for _, d := range devs {
		fmt.Fprintf(&b, "ollamawg_device_online{device=\"%s\",device_id=\"%s\"} %d\n", esc(d.Name), d.ID, b2i(d.Online))
	}
	head("ollamawg_device_blocked", "gauge", "Device is blocked by an admin.")
	for _, d := range devs {
		fmt.Fprintf(&b, "ollamawg_device_blocked{device=\"%s\",device_id=\"%s\"} %d\n", esc(d.Name), d.ID, b2i(d.Blocked))
	}
	head("ollamawg_device_tunnel_bytes_total", "counter", "Encrypted tunnel traffic per device.")
	for _, d := range devs {
		fmt.Fprintf(&b, "ollamawg_device_tunnel_bytes_total{device=\"%s\",device_id=\"%s\",direction=\"rx\"} %d\n", esc(d.Name), d.ID, d.RxBytes)
		fmt.Fprintf(&b, "ollamawg_device_tunnel_bytes_total{device=\"%s\",device_id=\"%s\",direction=\"tx\"} %d\n", esc(d.Name), d.ID, d.TxBytes)
	}
	head("ollamawg_device_last_handshake_seconds", "gauge", "Unix time of the last WireGuard handshake.")
	for _, d := range devs {
		var t int64
		if d.LastHandshake != nil {
			t = d.LastHandshake.Unix()
		}
		fmt.Fprintf(&b, "ollamawg_device_last_handshake_seconds{device=\"%s\",device_id=\"%s\"} %d\n", esc(d.Name), d.ID, t)
	}

	s.obs.mu.Lock()
	type tot struct {
		id string
		t  deviceTotals
		st map[int]int64
	}
	var tots []tot
	for id, t := range s.obs.totals {
		st := make(map[int]int64, len(t.byStatus))
		for k, v := range t.byStatus {
			st[k] = v
		}
		tots = append(tots, tot{id, *t, st})
	}
	s.obs.mu.Unlock()
	sort.Slice(tots, func(i, j int) bool { return tots[i].id < tots[j].id })

	head("ollamawg_requests_total", "counter", "Requests through the tunnel proxy by device and HTTP status.")
	for _, t := range tots {
		codes := make([]int, 0, len(t.st))
		for c := range t.st {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Fprintf(&b, "ollamawg_requests_total{device=\"%s\",device_id=\"%s\",status=\"%d\"} %d\n", esc(names[t.id]), t.id, c, t.st[c])
		}
	}
	head("ollamawg_denied_total", "counter", "Requests denied by policy (role, model allowlist, rate limit, block).")
	for _, t := range tots {
		fmt.Fprintf(&b, "ollamawg_denied_total{device=\"%s\",device_id=\"%s\"} %d\n", esc(names[t.id]), t.id, t.t.Denied)
	}
	head("ollamawg_tokens_total", "counter", "Tokens processed by device.")
	for _, t := range tots {
		fmt.Fprintf(&b, "ollamawg_tokens_total{device=\"%s\",device_id=\"%s\",kind=\"prompt\"} %d\n", esc(names[t.id]), t.id, t.t.PromptTokens)
		fmt.Fprintf(&b, "ollamawg_tokens_total{device=\"%s\",device_id=\"%s\",kind=\"completion\"} %d\n", esc(names[t.id]), t.id, t.t.CompletionTokens)
	}
	head("ollamawg_model_tokens_total", "counter", "Tokens processed by model.")
	for _, m := range s.obs.Models() {
		fmt.Fprintf(&b, "ollamawg_model_tokens_total{model=\"%s\",kind=\"prompt\"} %d\n", esc(m.Model), m.PromptTokens)
		fmt.Fprintf(&b, "ollamawg_model_tokens_total{model=\"%s\",kind=\"completion\"} %d\n", esc(m.Model), m.CompletionTokens)
	}

	passed, dropped := s.fw.Counters()
	head("ollamawg_firewall_packets_total", "counter", "UDP packets seen on the WireGuard port by firewall verdict.")
	fmt.Fprintf(&b, "ollamawg_firewall_packets_total{verdict=\"pass\"} %d\nollamawg_firewall_packets_total{verdict=\"drop\"} %d\n", passed, dropped)
	rules, _ := s.fw.Rules()
	head("ollamawg_firewall_rule_hits_total", "counter", "Packets matched per firewall rule.")
	for _, r := range rules {
		fmt.Fprintf(&b, "ollamawg_firewall_rule_hits_total{action=\"%s\",cidr=\"%s\"} %d\n", r.Action, r.CIDR, r.Hits)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}
