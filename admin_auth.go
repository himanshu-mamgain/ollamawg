package ollamawg

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// Dashboard authentication. Without 2FA the dashboard uses HTTP basic auth.
// With 2FA (admin.totp_secret set) basic auth is refused: the browser logs in
// with password + code and gets a session cookie, and scripts use the API
// token as a bearer token.

const (
	sessionCookie = "ollamawg_session"
	sessionTTL    = 12 * time.Hour
)

type session struct {
	expires time.Time
	secret  string // the TOTP secret it was issued under; re-enrolling ends it
}

type adminAuth struct {
	mu       sync.Mutex
	sessions map[string]session
	pending  string // TOTP secret shown during dashboard setup, not yet confirmed
	lastStep int64  // last accepted TOTP step for usedFor, against replays
	usedFor  string
	// loginLim throttles failed password/code attempts across all clients.
	loginLim *rate.Limiter
	// okDigest remembers the last password that matched passwordHash, so the
	// dashboard's polling doesn't pay for a bcrypt comparison every request.
	okDigest [32]byte
	okHash   string
}

func newAdminAuth() *adminAuth {
	return &adminAuth{sessions: map[string]session{}, loginLim: rate.NewLimiter(rate.Every(10*time.Second), 10)}
}

type authCreds struct{ user, password, passwordHash, totpSecret, apiToken string }

func (c authCreds) enabled() bool { return c.password != "" || c.passwordHash != "" }

func (a *adminCtx) creds() authCreds {
	a.s.mu.RLock()
	defer a.s.mu.RUnlock()
	c := a.s.cfg.Admin
	return authCreds{c.Username(), c.Password, c.PasswordHash, c.TOTPSecret, c.APIToken}
}

// checkLogin verifies a username and password against the config.
func (a *adminCtx) checkLogin(c authCreds, user, pw string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(c.user)) == 1
	if c.passwordHash == "" {
		passOK := subtle.ConstantTimeCompare([]byte(pw), []byte(c.password)) == 1
		return userOK && passOK && c.password != ""
	}
	d := sha256.Sum256([]byte(c.passwordHash + "\x00" + pw))
	a.auth.mu.Lock()
	cached := a.auth.okHash == c.passwordHash && subtle.ConstantTimeCompare(d[:], a.auth.okDigest[:]) == 1
	a.auth.mu.Unlock()
	if !cached {
		if bcrypt.CompareHashAndPassword([]byte(c.passwordHash), []byte(pw)) != nil {
			return false
		}
		a.auth.mu.Lock()
		a.auth.okDigest, a.auth.okHash = d, c.passwordHash
		a.auth.mu.Unlock()
	}
	return userOK
}

// authenticated reports whether r carries valid credentials, and whether it
// presented basic-auth credentials that were wrong (for logging).
func (a *adminCtx) authenticated(r *http.Request, c authCreds) (ok, badBasic bool) {
	if c.apiToken != "" {
		if t, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found {
			return subtle.ConstantTimeCompare([]byte(t), []byte(c.apiToken)) == 1, false
		}
	}
	if c.totpSecret != "" {
		ck, err := r.Cookie(sessionCookie)
		if err != nil {
			return false, false
		}
		a.auth.mu.Lock()
		defer a.auth.mu.Unlock()
		s, found := a.auth.sessions[ck.Value]
		if !found || time.Now().After(s.expires) || s.secret != c.totpSecret {
			delete(a.auth.sessions, ck.Value)
			return false, false
		}
		return true, false
	}
	u, p, hasBasic := r.BasicAuth()
	ok = hasBasic && a.checkLogin(c, u, p)
	return ok, hasBasic && !ok
}

// checkCode verifies a TOTP code and refuses one that was already used.
func (a *adminCtx) checkCode(secret, code string) bool {
	step, ok := VerifyTOTP(secret, code, time.Now())
	if !ok {
		return false
	}
	a.auth.mu.Lock()
	defer a.auth.mu.Unlock()
	if a.auth.usedFor == secret && step <= a.auth.lastStep {
		return false
	}
	a.auth.usedFor, a.auth.lastStep = secret, step
	return true
}

// throttled reports whether too many logins failed recently; failed records one.
func (a *adminCtx) throttled() bool { return a.auth.loginLim.Tokens() < 1 }
func (a *adminCtx) failed(r *http.Request, what string) {
	a.auth.loginLim.Allow()
	a.s.obs.Event("admin", "warn", what+" from "+r.RemoteAddr, hostOnly(r.RemoteAddr), "")
	time.Sleep(300 * time.Millisecond)
}

func (a *adminCtx) startSession(w http.ResponseWriter, r *http.Request, secret string) {
	tok := randomToken(32)
	now := time.Now()
	a.auth.mu.Lock()
	for k, s := range a.auth.sessions {
		if now.After(s.expires) {
			delete(a.auth.sessions, k)
		}
	}
	a.auth.sessions[tok] = session{expires: now.Add(sessionTTL), secret: secret}
	a.auth.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func (a *adminCtx) endSession(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		a.auth.mu.Lock()
		delete(a.auth.sessions, ck.Value)
		a.auth.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// GET /api/session (public): tells the dashboard whether to show the login form.
func (a *adminCtx) sessionInfo(w http.ResponseWriter, r *http.Request) {
	c := a.creds()
	ok, _ := a.authenticated(r, c)
	writeJSON(w, 200, map[string]bool{"authenticated": ok, "two_factor": c.totpSecret != ""})
}

// POST /api/login (public): username, password and code; sets the session cookie.
func (a *adminCtx) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Password, Code string }
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	c := a.creds()
	if c.totpSecret == "" {
		writeJSONError(w, 400, "two-factor login is not enabled")
		return
	}
	if a.throttled() {
		writeJSONError(w, 429, "too many failed logins; wait a minute")
		return
	}
	if !a.checkLogin(c, req.User, req.Password) || !a.checkCode(c.totpSecret, req.Code) {
		a.failed(r, "dashboard login failed")
		writeJSONError(w, 401, "wrong username, password or code")
		return
	}
	a.startSession(w, r, c.totpSecret)
	a.s.obs.Event("admin", "info", "dashboard login from "+r.RemoteAddr, hostOnly(r.RemoteAddr), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/logout (public)
func (a *adminCtx) logout(w http.ResponseWriter, r *http.Request) {
	a.endSession(w, r)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET /api/2fa
func (a *adminCtx) twoFactorStatus(w http.ResponseWriter, r *http.Request) {
	c := a.creds()
	writeJSON(w, 200, map[string]any{"enabled": c.totpSecret != "", "api_token": c.apiToken})
}

// POST /api/2fa/setup: a new secret and its QR code, kept until confirmed.
func (a *adminCtx) twoFactorSetup(w http.ResponseWriter, r *http.Request) {
	if a.creds().totpSecret != "" {
		writeJSONError(w, 409, "two-factor login is already enabled; disable it first")
		return
	}
	secret := NewTOTPSecret()
	uri := TOTPURI(secret, TOTPAccount())
	svg, err := QRSVG(uri)
	if err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}
	a.auth.mu.Lock()
	a.auth.pending = secret
	a.auth.mu.Unlock()
	writeJSON(w, 200, map[string]string{"secret": secret, "uri": uri, "qr_svg": svg})
}

// POST /api/2fa/enable {code}: confirms the pending secret and turns 2FA on.
// The caller gets a session, so enabling does not log them out.
func (a *adminCtx) twoFactorEnable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	a.auth.mu.Lock()
	secret := a.auth.pending
	a.auth.mu.Unlock()
	if secret == "" {
		writeJSONError(w, 400, "start the setup first")
		return
	}
	if a.throttled() {
		writeJSONError(w, 429, "too many wrong codes; wait a minute")
		return
	}
	if !a.checkCode(secret, req.Code) {
		a.failed(r, "2FA setup: wrong code")
		writeJSONError(w, 400, "wrong code; check the time on your phone and try again")
		return
	}
	var token string
	err := a.s.edit(func(c *ServerConfig) error {
		c.Admin.TOTPSecret = secret
		if c.Admin.APIToken == "" {
			c.Admin.APIToken = NewAPIToken()
		}
		token = c.Admin.APIToken
		return nil
	})
	if err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}
	a.auth.mu.Lock()
	a.auth.pending = ""
	a.auth.mu.Unlock()
	a.startSession(w, r, secret)
	a.s.obs.Event("admin", "info", "two-factor login enabled from the dashboard", hostOnly(r.RemoteAddr), "")
	writeJSON(w, 200, map[string]string{"api_token": token})
}

// POST /api/2fa/disable {password, code}
func (a *adminCtx) twoFactorDisable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password, Code string }
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, 400, err.Error())
		return
	}
	c := a.creds()
	if c.totpSecret == "" {
		writeJSONError(w, 400, "two-factor login is not enabled")
		return
	}
	if a.throttled() {
		writeJSONError(w, 429, "too many failed attempts; wait a minute")
		return
	}
	if !a.checkLogin(c, c.user, req.Password) || !a.checkCode(c.totpSecret, req.Code) {
		a.failed(r, "2FA disable: wrong password or code")
		writeJSONError(w, 401, "wrong password or code")
		return
	}
	if err := a.s.edit(func(c *ServerConfig) error { c.Admin.TOTPSecret = ""; return nil }); err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}
	a.endSession(w, r)
	a.s.obs.Event("admin", "warn", "two-factor login disabled from the dashboard", hostOnly(r.RemoteAddr), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// NewAPIToken returns a random token for admin.api_token.
func NewAPIToken() string { return randomToken(24) }

// TOTPAccount names this server inside the authenticator app.
func TOTPAccount() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "admin"
	}
	return "admin@" + h
}
