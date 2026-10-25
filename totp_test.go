package ollamawg

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTOTPVectors(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 key "12345678901234567890", last 6 digits.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := TOTPCode(secret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %q, want %q (%v)", unix, got, want, err)
		}
	}
	now := time.Unix(1111111109, 0)
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if _, ok := VerifyTOTP(secret, "081804", now.Add(d)); !ok {
			t.Errorf("drift %v rejected", d)
		}
	}
	if _, ok := VerifyTOTP(secret, "081804", now.Add(90*time.Second)); ok {
		t.Error("code accepted three steps late")
	}
	if !strings.HasPrefix(TOTPURI(secret, "admin@box"), "otpauth://totp/ollamawg:admin@box?") {
		t.Error("bad otpauth URI")
	}
	if svg, err := QRSVG(TOTPURI(secret, "admin@box")); err != nil || !strings.HasPrefix(svg, "<svg") {
		t.Errorf("QR: %v", err)
	}
}

func TestTwoFactorLogin(t *testing.T) {
	h := newHarness(t)
	base := "http://" + h.admin
	do := func(c *http.Client, method, path string, body any, hdr map[string]string) (int, []byte, http.Header) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, base+path, rd)
		if method != "GET" {
			req.Header.Set("X-Ollamawg", "1")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, resp.Header
	}
	code := func(secret string, d time.Duration) string {
		c, err := TOTPCode(secret, time.Now().Add(d))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	_, b := h.adminReq("POST", "/api/2fa/setup", nil, true)
	var setup struct {
		Secret string `json:"secret"`
		QRSVG  string `json:"qr_svg"`
	}
	if err := json.Unmarshal(b, &setup); err != nil || setup.Secret == "" || !strings.HasPrefix(setup.QRSVG, "<svg") {
		t.Fatalf("setup: %s", b)
	}
	if c, _ := h.adminReq("POST", "/api/2fa/enable", map[string]string{"code": "000000"}, true); c != 400 {
		t.Fatalf("wrong code at enable: want 400, got %d", c)
	}
	// Each step below uses a later time step than the one before, because a
	// code is accepted only once.
	c, b := h.adminReq("POST", "/api/2fa/enable", map[string]string{"code": code(setup.Secret, -30*time.Second)}, true)
	var en struct {
		APIToken string `json:"api_token"`
	}
	if json.Unmarshal(b, &en); c != 200 || en.APIToken == "" {
		t.Fatalf("enable: %d %s", c, b)
	}
	saved, _ := LoadServerConfig(h.cfgPath)
	if saved.Admin.TOTPSecret != setup.Secret || saved.Admin.APIToken != en.APIToken {
		t.Fatal("2FA settings not saved to server.yaml")
	}

	plain := &http.Client{}
	if c, _ := h.adminReq("GET", "/api/devices", nil, false); c != 401 {
		t.Fatalf("basic auth with 2FA on: want 401, got %d", c)
	}
	if c, _, hdr := do(plain, "GET", "/api/devices", nil, nil); c != 401 || hdr.Get("WWW-Authenticate") != "" {
		t.Fatalf("want 401 without a basic-auth prompt, got %d %q", c, hdr.Get("WWW-Authenticate"))
	}
	if c, _, _ := do(plain, "GET", "/", nil, nil); c != 200 {
		t.Fatalf("login page: want 200, got %d", c)
	}
	if c, _, _ := do(plain, "GET", "/metrics", nil, map[string]string{"Authorization": "Bearer " + en.APIToken}); c != 200 {
		t.Fatalf("bearer token: want 200, got %d", c)
	}
	if c, _, _ := do(plain, "GET", "/metrics", nil, map[string]string{"Authorization": "Bearer nope"}); c != 401 {
		t.Fatalf("wrong bearer token: want 401, got %d", c)
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	if c, _, _ := do(browser, "POST", "/api/login", map[string]string{"password": h.pass, "code": "000000"}, nil); c != 401 {
		t.Fatalf("wrong code: want 401, got %d", c)
	}
	now := code(setup.Secret, 0)
	if c, b, _ := do(browser, "POST", "/api/login", map[string]string{"password": h.pass, "code": now}, nil); c != 200 {
		t.Fatalf("login: %d %s", c, b)
	}
	if c, _, _ := do(&http.Client{}, "POST", "/api/login", map[string]string{"password": h.pass, "code": now}, nil); c != 401 {
		t.Fatalf("replayed code: want 401, got %d", c)
	}
	if c, b, _ := do(browser, "GET", "/api/devices", nil, nil); c != 200 {
		t.Fatalf("session cookie: %d %s", c, b)
	}
	if c, b, _ := do(browser, "GET", "/api/session", nil, nil); c != 200 || !strings.Contains(string(b), `"authenticated":true`) {
		t.Fatalf("session info: %d %s", c, b)
	}

	if c, b, _ := do(browser, "POST", "/api/2fa/disable", map[string]string{"password": h.pass, "code": code(setup.Secret, 30*time.Second)}, nil); c != 200 {
		t.Fatalf("disable: %d %s", c, b)
	}
	if c, _ := h.adminReq("GET", "/api/devices", nil, false); c != 200 {
		t.Fatalf("basic auth after disabling 2FA: want 200, got %d", c)
	}
	if b, _ := os.ReadFile(h.cfgPath); strings.Contains(string(b), "totp_secret") {
		t.Fatal("totp_secret still in server.yaml after disabling")
	}
}
