package ollamawg

import (
	"net/http"
	"strings"
	"testing"
)

func TestCustomLogin(t *testing.T) {
	h := newHarness(t)
	err := h.srv.edit(func(c *ServerConfig) error {
		c.Admin.User = "himanshu"
		return c.Admin.SetPassword("correct horse battery")
	})
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := LoadServerConfig(h.cfgPath)
	if saved.Admin.Password != "" || !strings.HasPrefix(saved.Admin.PasswordHash, "$2") || saved.Admin.Username() != "himanshu" {
		t.Fatalf("saved admin section: user %q, password %q, hash %q", saved.Admin.User, saved.Admin.Password, saved.Admin.PasswordHash)
	}

	try := func(user, pass string) int {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+h.admin+"/api/devices", nil)
		req.SetBasicAuth(user, pass)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, c := range []struct {
		user, pass string
		want       int
	}{
		{"himanshu", "correct horse battery", 200},
		{"himanshu", "correct horse battery", 200}, // served from the cache
		{"himanshu", "wrong password here", 401},
		{"admin", "correct horse battery", 401},
		{"admin", h.pass, 401}, // the old generated password no longer works
	} {
		if got := try(c.user, c.pass); got != c.want {
			t.Errorf("%s / %q: got %d, want %d", c.user, c.pass, got, c.want)
		}
	}

	var a AdminSection
	if a.SetPassword("short") == nil {
		t.Error("short password accepted")
	}
	if ValidUser("bad:name") || ValidUser("") || !ValidUser("me@home") {
		t.Error("username validation")
	}
}
