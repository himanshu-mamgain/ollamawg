package ollamawg

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReissueDevice(t *testing.T) {
	h := newHarness(t)
	old := h.clients["carol"]

	code, b := h.adminReq("POST", "/api/devices/carol/reissue", nil, true)
	var r struct {
		Name, Address, Config string
		DeviceID              string `json:"device_id"`
		WGConfig              string `json:"wg_config"`
		WGQRSVG               string `json:"wg_qr_svg"`
	}
	if err := json.Unmarshal(b, &r); err != nil || code != 200 {
		t.Fatalf("reissue: %d %s", code, b)
	}
	if r.Name != "carol" || r.Address != old.Client.Address || !strings.HasPrefix(r.WGQRSVG, "<svg") || r.WGConfig == "" {
		t.Fatalf("bad reissue response: %+v", r)
	}
	if r.DeviceID == old.Client.PrivateKey.PublicKey().DeviceID() {
		t.Fatal("device key did not change")
	}

	saved, _ := LoadServerConfig(h.cfgPath)
	p := saved.Peers[saved.FindPeer("carol")]
	if p.PublicKey == old.Client.PrivateKey.PublicKey() || p.Address != old.Client.Address || len(p.Models) != 1 || p.Models[0] != "llama3.2" {
		t.Fatalf("peer after reissue: %+v", p)
	}

	// The new config connects through the running server, policy intact.
	var cc ClientConfig
	if err := yaml.Unmarshal([]byte(r.Config), &cc); err != nil {
		t.Fatal(err)
	}
	cc.Client.Keepalive = 1
	h.clients["carol"] = &cc
	_, base := h.connect("carol")
	resp, err := http.Post(base+"/api/chat", "application/json", strings.NewReader(`{"model":"qwen3","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("carol's model allowlist should survive reissue: got %d", resp.StatusCode)
	}

	if code, _ := h.adminReq("POST", "/api/devices/nobody/reissue", nil, true); code != 400 {
		t.Fatalf("unknown device: want 400, got %d", code)
	}
}
