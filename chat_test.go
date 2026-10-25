package ollamawg

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestChatPage(t *testing.T) {
	h := newHarness(t)
	c, base := h.connect("alice")

	get := func(t *testing.T, cl *http.Client, url string, hdr map[string]string, host string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", url, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	t.Run("served inside the tunnel", func(t *testing.T) {
		if resp, _ := get(t, noRedirect, base+"/chat", nil, ""); resp.StatusCode != 302 || resp.Header.Get("Location") != "/chat/" {
			t.Fatalf("/chat: want redirect to /chat/, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		resp, body := get(t, http.DefaultClient, base+"/chat/", nil, "")
		if resp.StatusCode != 200 || !strings.Contains(body, "chat.js") || resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("/chat/: %d, CSP %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
		}
		if resp, _ := get(t, http.DefaultClient, base+"/chat/manifest.webmanifest", nil, ""); resp.Header.Get("Content-Type") != "application/manifest+json" {
			t.Fatalf("manifest content type %q", resp.Header.Get("Content-Type"))
		}
		if resp, _ := get(t, http.DefaultClient, base+"/chat/chat.js", nil, ""); resp.StatusCode != 200 {
			t.Fatalf("chat.js: %d", resp.StatusCode)
		}
	})

	t.Run("chat page origin reaches Ollama, rebinding origins do not", func(t *testing.T) {
		tun := c.HTTPClient()
		origin := c.BaseURL()
		if resp, body := get(t, tun, origin+"/api/tags", map[string]string{"Origin": origin}, ""); resp.StatusCode != 200 {
			t.Fatalf("same-origin request from the chat page: %d %s", resp.StatusCode, body)
		}
		evil := "evil.example:" + origin[strings.LastIndex(origin, ":")+1:]
		if resp, _ := get(t, tun, origin+"/api/tags", map[string]string{"Origin": "http://" + evil}, evil); resp.StatusCode != 403 {
			t.Fatalf("DNS-rebinding origin: want Ollama's 403, got %d", resp.StatusCode)
		}
	})

	t.Run("WireGuard app config", func(t *testing.T) {
		cc := h.clients["alice"]
		conf := cc.WireGuardConf()
		for _, want := range []string{
			"[Interface]", "PrivateKey = " + cc.Client.PrivateKey.String(), "Address = " + cc.Client.Address + "/32",
			"[Peer]", "PublicKey = " + cc.Client.ServerPublicKey.String(), "Endpoint = " + cc.Client.Endpoint,
			"AllowedIPs = " + cc.Client.ServerAddress + "/32", "PersistentKeepalive = ",
		} {
			if !strings.Contains(conf, want) {
				t.Errorf("config lacks %q:\n%s", want, conf)
			}
		}
		if strings.Contains(cc.WireGuardQRText(), "#") {
			t.Error("QR text still has comments")
		}
	})
}
