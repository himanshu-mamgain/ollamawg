package ollamawg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOllama mimics the parts of the Ollama API the proxy cares about.
func fakeOllama(t *testing.T, hostSeen *atomic.Value) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"version":"0.9.9"}`)
	})
	mux.HandleFunc("GET /api/tags", func(w http.ResponseWriter, r *http.Request) {
		hostSeen.Store(r.Host)
		io.WriteString(w, `{"models":[{"name":"llama3.2:latest"}]}`)
	})
	mux.HandleFunc("POST /api/chat", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Model string }
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, tok := range []string{"Hel", "lo", "!"} {
			fmt.Fprintf(w, `{"model":%q,"message":{"role":"assistant","content":%q},"done":false}`+"\n", req.Model, tok)
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
		fmt.Fprintf(w, `{"model":%q,"done":true,"prompt_eval_count":11,"eval_count":7}`+"\n", req.Model)
	})
	mux.HandleFunc("DELETE /api/delete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func freeUDPPort(t *testing.T) int {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

type harness struct {
	t       *testing.T
	srv     *Server
	cfgPath string
	clients map[string]*ClientConfig
	admin   string
	pass    string
}

func (h *harness) connect(name string) (*Client, string) {
	h.t.Helper()
	c, err := NewClient(h.clients[name], ClientOptions{Logger: quietLogger()})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.WaitHandshake(ctx); err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	fctx, fcancel := context.WithCancel(context.Background())
	h.t.Cleanup(fcancel)
	go c.Serve(fctx, ln)
	return c, "http://" + ln.Addr().String()
}

func (h *harness) adminReq(method, path string, body any, csrf bool) (int, []byte) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://"+h.admin+path, rd)
	req.SetBasicAuth("admin", h.pass)
	if csrf {
		req.Header.Set("X-Ollamawg", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func quietLogger() *slog.Logger {
	lvl := slog.LevelWarn
	if os.Getenv("OLLAMAWG_TEST_DEBUG") != "" {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func newHarness(t *testing.T) *harness {
	var host atomic.Value
	up := fakeOllama(t, &host)
	t.Cleanup(up.Close)

	port := freeUDPPort(t)
	cfg, err := NewServerConfig(fmt.Sprintf("127.0.0.1:%d", port), "", port)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.Upstream = up.URL
	cfg.Admin.Listen = "127.0.0.1:0"
	h := &harness{t: t, clients: map[string]*ClientConfig{}, pass: cfg.Admin.Password}
	for _, p := range []struct{ name, role string }{{"alice", "user"}, {"bob", "admin"}, {"carol", "user"}} {
		cc, err := cfg.AddPeer(p.name, p.role)
		if err != nil {
			t.Fatal(err)
		}
		cc.Client.Keepalive = 1
		h.clients[p.name] = cc
	}
	cfg.Peers[2].Models = []string{"llama3.2"}
	h.cfgPath = filepath.Join(t.TempDir(), "server.yaml")
	if err := cfg.Save(h.cfgPath); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadServerConfig(h.cfgPath) // round-trip through YAML
	if err != nil {
		t.Fatal(err)
	}
	h.srv, err = NewServer(cfg, ServerOptions{ConfigPath: h.cfgPath, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-h.srv.Ready():
	case err := <-done:
		t.Fatalf("server exited: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server not ready")
	}
	h.admin = h.srv.AdminAddr()
	t.Run("upstream host header rewritten", func(t *testing.T) {
		_, base := h.connect("alice")
		resp, err := http.Get(base + "/api/tags")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got, want := host.Load(), strings.TrimPrefix(up.URL, "http://"); got != want {
			t.Fatalf("upstream saw Host %v, want %v (Ollama rejects foreign hosts)", got, want)
		}
	})
	return h
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)

	_, alice := h.connect("alice")

	t.Run("streaming chat through tunnel", func(t *testing.T) {
		resp, err := http.Post(alice+"/api/chat", "application/json", strings.NewReader(`{"model":"llama3.2","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		sc := bufio.NewScanner(resp.Body)
		var text strings.Builder
		lines := 0
		for sc.Scan() {
			lines++
			var m struct{ Message struct{ Content string } }
			json.Unmarshal(sc.Bytes(), &m)
			text.WriteString(m.Message.Content)
		}
		if lines != 4 || text.String() != "Hello!" {
			t.Fatalf("got %d lines %q", lines, text.String())
		}
	})

	t.Run("role user cannot delete models", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, alice+"/api/delete", strings.NewReader(`{"model":"llama3.2"}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("want 403, got %d", resp.StatusCode)
		}
	})

	t.Run("path traversal cannot escape role prefixes", func(t *testing.T) {
		for _, pth := range []string{"/v1/models/../../api/delete", "/v1/models/%2e%2e/%2e%2e/api/delete", "/api//delete"} {
			req, _ := http.NewRequest(http.MethodDelete, alice+pth, strings.NewReader(`{"model":"llama3.2"}`))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s: want 400/403, got %d", pth, resp.StatusCode)
			}
		}
	})

	t.Run("role admin can delete models", func(t *testing.T) {
		_, bob := h.connect("bob")
		req, _ := http.NewRequest(http.MethodDelete, bob+"/api/delete", strings.NewReader(`{"model":"llama3.2"}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("want 200, got %d", resp.StatusCode)
		}
	})

	t.Run("model allowlist", func(t *testing.T) {
		_, carol := h.connect("carol")
		for body, want := range map[string]int{
			`{"model":"llama3.2","messages":[]}`:        200,
			`{"model":"llama3.2:latest","messages":[]}`: 200,
			`{"model":"qwen3:8b","messages":[]}`:        403,
			// Bypass attempts: Ollama uses the top-level, last, case-insensitive key.
			`{"messages":[{"role":"user","content":"x","model":"llama3.2"}],"model":"qwen3:8b"}`: 403,
			`{"model":"llama3.2","MODEL":"qwen3:8b"}`:                                            403,
			`{"name":"llama3.2","model":"qwen3:8b"}`:                                             403,
			`{"messages":[]}`:                                                                    403,
			`{"pad":"` + strings.Repeat("x", 70000) + `","model":"qwen3:8b"}`:                    403,
		} {
			resp, err := http.Post(carol+"/api/chat", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatalf("body %.80s: want %d, got %d", body, want, resp.StatusCode)
			}
		}
	})

	t.Run("allowlisted device can still list models", func(t *testing.T) {
		_, carol := h.connect("carol")
		resp, err := http.Get(carol + "/api/tags")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("want 200, got %d", resp.StatusCode)
		}
	})

	t.Run("unknown key cannot handshake", func(t *testing.T) {
		rogue := *h.clients["alice"]
		priv, _ := GeneratePrivateKey()
		rogue.Client.PrivateKey = priv
		c, err := NewClient(&rogue, ClientOptions{Logger: quietLogger(), DisableHello: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := c.WaitHandshake(ctx); err == nil {
			t.Fatal("rogue key completed a handshake")
		}
	})

	t.Run("token accounting and access log", func(t *testing.T) {
		var entry *AccessEntry
		for _, e := range h.srv.Observer().Access(100, "", false) {
			if e.Device == "alice" && e.Path == "/api/chat" {
				entry = &e
				break
			}
		}
		if entry == nil || entry.Model != "llama3.2" || entry.PromptTokens != 11 || entry.CompletionTokens != 7 || entry.RemoteIP != "127.0.0.1" {
			t.Fatalf("bad access entry: %+v", entry)
		}
	})

	t.Run("admin API requires auth and CSRF header", func(t *testing.T) {
		resp, err := http.Get("http://" + h.admin + "/api/devices")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("unauthenticated: want 401, got %d", resp.StatusCode)
		}
		if code, _ := h.adminReq("POST", "/api/devices/alice/block", nil, false); code != 403 {
			t.Fatalf("no CSRF header: want 403, got %d", code)
		}
	})

	t.Run("dashboard shows devices with client info", func(t *testing.T) {
		deadline := time.Now().Add(8 * time.Second)
		for {
			_, b := h.adminReq("GET", "/api/devices", nil, false)
			var devs []DeviceView
			json.Unmarshal(b, &devs)
			var a *DeviceView
			for i := range devs {
				if devs[i].Name == "alice" {
					a = &devs[i]
				}
			}
			if a != nil && a.Online && a.Client.Hostname != "" && a.Endpoint != "" && a.Last24h.PromptTokens == 11 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("alice not reported correctly: %s", b)
			}
			time.Sleep(300 * time.Millisecond)
		}
	})

	t.Run("block device by id kills its access", func(t *testing.T) {
		id := h.clients["alice"].Client.PrivateKey.PublicKey().DeviceID()
		if code, b := h.adminReq("POST", "/api/devices/"+id+"/block", nil, true); code != 200 {
			t.Fatalf("block: %d %s", code, b)
		}
		hc := &http.Client{Timeout: 3 * time.Second}
		if resp, err := hc.Get(alice + "/api/tags"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				t.Fatal("blocked device still got through")
			}
		}
		saved, err := LoadServerConfig(h.cfgPath)
		if err != nil || !saved.Peers[saved.FindPeer("alice")].Blocked {
			t.Fatalf("block not persisted: %v", err)
		}
		if code, b := h.adminReq("POST", "/api/devices/alice/unblock", nil, true); code != 200 {
			t.Fatalf("unblock: %d %s", code, b)
		}
		_, again := h.connect("alice")
		resp, err := http.Get(again + "/api/tags")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("unblocked device should work: %v", err)
		}
		resp.Body.Close()
	})

	t.Run("block IP drops packets before WireGuard", func(t *testing.T) {
		_, before := h.srv.Firewall().Counters()
		if code, b := h.adminReq("POST", "/api/firewall", map[string]string{"action": "block", "cidr": "127.0.0.1", "note": "test"}, true); code != 201 {
			t.Fatalf("add rule: %d %s", code, b)
		}
		c, err := NewClient(h.clients["bob"], ClientOptions{Logger: quietLogger(), DisableHello: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := c.WaitHandshake(ctx); err == nil {
			t.Fatal("handshake succeeded from a blocked IP")
		}
		if _, after := h.srv.Firewall().Counters(); after <= before {
			t.Fatal("no packets counted as dropped")
		}
		_, b := h.adminReq("GET", "/api/sources", nil, false)
		if !strings.Contains(string(b), `"blocked":true`) {
			t.Fatalf("source not marked blocked: %s", b)
		}
		if code, b := h.adminReq("DELETE", "/api/firewall?cidr=127.0.0.1/32", nil, true); code != 200 {
			t.Fatalf("remove rule: %d %s", code, b)
		}
		h.connect("bob")
	})

	t.Run("config edits on disk are hot-reloaded", func(t *testing.T) {
		cfg, err := LoadServerConfig(h.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		dave, err := cfg.AddPeer("dave", "readonly")
		if err != nil {
			t.Fatal(err)
		}
		dave.Client.Keepalive = 1
		time.Sleep(20 * time.Millisecond) // ensure a new mtime
		if err := cfg.Save(h.cfgPath); err != nil {
			t.Fatal(err)
		}
		h.clients["dave"] = dave
		deadline := time.Now().Add(6 * time.Second)
		for !hasDevice(h.srv, "dave") {
			if time.Now().After(deadline) {
				t.Fatal("dave was not picked up")
			}
			time.Sleep(200 * time.Millisecond)
		}
		_, d := h.connect("dave")
		resp, err := http.Post(d+"/api/chat", "application/json", strings.NewReader(`{"model":"llama3.2"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("readonly role must not chat, got %d", resp.StatusCode)
		}
	})

	t.Run("prometheus metrics", func(t *testing.T) {
		code, b := h.adminReq("GET", "/metrics", nil, false)
		m := string(b)
		for _, want := range []string{
			`ollamawg_up 1`,
			`ollamawg_tokens_total{device="alice"`,
			`ollamawg_denied_total{device="alice"`,
			`ollamawg_firewall_packets_total{verdict="drop"}`,
			`ollamawg_device_online{device="bob"`,
		} {
			if code != 200 || !strings.Contains(m, want) {
				t.Fatalf("metrics missing %q:\n%s", want, m)
			}
		}
	})

	t.Run("dashboard page is served", func(t *testing.T) {
		code, b := h.adminReq("GET", "/", nil, false)
		if code != 200 || !bytes.Contains(b, []byte("<html")) {
			t.Fatalf("dashboard: %d", code)
		}
	})
}

func hasDevice(s *Server, name string) bool {
	for _, d := range s.Devices() {
		if d.Name == name {
			return true
		}
	}
	return false
}

func TestKeysX25519Vector(t *testing.T) {
	// RFC 7748 section 6.1 test vector (Alice).
	priv, err := ParseKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	if err != nil {
		t.Fatal(err)
	}
	if got := priv.PublicKey().Hex(); got != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("public key %s", got)
	}
	k, _ := GeneratePrivateKey()
	back, err := ParseKey(k.String())
	if err != nil || back != k || k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatal("generated key not clamped or does not round-trip")
	}
}

func TestPolicyMatching(t *testing.T) {
	user, _ := (&ServerConfig{}).Role("user")
	for path, want := range map[string]bool{
		"/api/chat": true, "/v1/chat/completions": true, "/v1/models/llama3": true,
		"/api/pull": false, "/api/delete": false, "/api/create": false, "/api/chatty": false,
	} {
		if got := pathAllowed(user, path); got != want {
			t.Errorf("%s: got %v", path, got)
		}
	}
	allow := []string{"llama3.2", "qwen3:*"}
	for m, want := range map[string]bool{"llama3.2": true, "LLAMA3.2:latest": true, "llama3.2:1b": false, "qwen3:8b": true, "": false} {
		if got := modelAllowed(allow, m); got != want {
			t.Errorf("model %q: got %v", m, got)
		}
	}
}
