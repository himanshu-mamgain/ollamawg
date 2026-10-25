package ollamawg

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayPackets(t *testing.T) {
	token := []byte("0123456789abcdef0123")
	addr := netip.MustParseAddrPort("203.0.113.7:51820")
	got, payload, ok := relayDecap(relayEncap(nil, addr, []byte{1, 0, 0, 0, 9}))
	if !ok || got != addr || !bytes.Equal(payload, []byte{1, 0, 0, 0, 9}) {
		t.Fatalf("IPv4 round trip: %v %v %v", got, payload, ok)
	}
	addr6 := netip.MustParseAddrPort("[2001:db8::1]:4500")
	if got, _, ok := relayDecap(relayEncap(nil, addr6, []byte{4})); !ok || got != addr6 {
		t.Fatalf("IPv6 round trip: %v %v", got, ok)
	}
	for _, bad := range [][]byte{nil, {relayMagic}, {relayMagic, relayData4, 1, 2}, {1, 0, 0, 0}} {
		if _, _, ok := relayDecap(bad); ok {
			t.Errorf("accepted malformed packet %v", bad)
		}
	}
	reg := relayRegisterPacket(token, time.Now())
	if len(reg) != relayRegLen || reg[0] != relayMagic || reg[1] != relayRegister {
		t.Fatal("bad register packet")
	}
}

func TestRelayEndToEnd(t *testing.T) {
	var host atomic.Value
	up := fakeOllama(t, &host)
	t.Cleanup(up.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	token := NewRelayToken()
	relay, err := ListenRelay("127.0.0.1:0", token, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	go relay.Serve(ctx)

	// The server never accepts inbound traffic from devices here: its config
	// hands out the relay's address, as it would behind CGNAT.
	port := freeUDPPort(t)
	cfg, err := NewServerConfig(relay.Addr().String(), "", port)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.Upstream = up.URL
	cfg.Server.Relay = relay.Addr().String()
	cfg.Server.RelayToken = token
	cfg.Server.MTU = RelayMTU
	cfg.Admin.Listen = "127.0.0.1:0"
	cc, err := cfg.AddPeer("phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	cc.Client.Keepalive = 1
	if cc.Client.Endpoint != relay.Addr().String() {
		t.Fatalf("device config should point at the relay, got %s", cc.Client.Endpoint)
	}
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(cfg, ServerOptions{ConfigPath: path, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-srv.Ready():
	case err := <-done:
		t.Fatalf("server exited: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server not ready")
	}

	deadline := time.Now().Add(5 * time.Second)
	for !relay.Status().ServerConnected || !srv.relay.Connected() {
		if time.Now().After(deadline) {
			t.Fatalf("server never registered: relay %+v, server connected %v", relay.Status(), srv.relay.Connected())
		}
		time.Sleep(50 * time.Millisecond)
	}

	c, err := NewClient(cc, ClientOptions{Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	defer hcancel()
	if err := c.WaitHandshake(hctx); err != nil {
		t.Fatalf("handshake through the relay: %v", err)
	}
	resp, err := c.HTTPClient().Post(c.BaseURL()+"/api/chat", "application/json", strings.NewReader(`{"model":"llama3.2","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"Hel"`) {
		t.Fatalf("chat through the relay: %d %s", resp.StatusCode, body)
	}

	// The firewall and dashboard see the device's own address, not the relay's.
	var seen bool
	for _, s := range srv.Firewall().Sources() {
		if s.IP == "127.0.0.1" && s.Port != relay.Addr().Port() && s.Packets > 0 {
			seen = true
		}
		if s.Port == relay.Addr().Port() {
			t.Errorf("relay itself listed as a source: %+v", s)
		}
	}
	if !seen {
		t.Errorf("device not listed under its own address: %+v", srv.Firewall().Sources())
	}
	if st := relay.Status(); st.Devices != 1 {
		t.Errorf("relay should know one device, got %+v", st)
	}
}

func TestRelayRejectsWrongToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, err := ListenRelay("127.0.0.1:0", NewRelayToken(), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	go relay.Serve(ctx)
	relay.handle(relayRegisterPacket([]byte("not-the-right-token-xx"), time.Now()), netip.MustParseAddrPort("127.0.0.1:9"), make([]byte, 2048))
	if relay.Status().ServerConnected {
		t.Fatal("registration with a wrong token was accepted")
	}
	stale := relayRegisterPacket(relay.token, time.Now().Add(-time.Hour))
	relay.handle(stale, netip.MustParseAddrPort("127.0.0.1:9"), make([]byte, 2048))
	if relay.Status().ServerConnected {
		t.Fatal("stale registration was accepted")
	}
	fresh := relayRegisterPacket(relay.token, time.Now())
	relay.handle(fresh, netip.MustParseAddrPort("127.0.0.1:9"), make([]byte, 2048))
	if !relay.Status().ServerConnected {
		t.Fatal("valid registration was rejected")
	}
	// Replaying the same packet from another address must not move the server.
	relay.handle(fresh, netip.MustParseAddrPort("127.0.0.1:10"), make([]byte, 2048))
	if st := relay.Status(); st.ServerAddr != "127.0.0.1:9" {
		t.Fatalf("replayed registration moved the server to %s", st.ServerAddr)
	}
}
