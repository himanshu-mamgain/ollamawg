package ollamawg

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// Time-based one-time passwords (RFC 6238) for the dashboard's two-factor
// login: HMAC-SHA1, 30-second steps, 6 digits. Every authenticator app
// (Google Authenticator, Authy, 1Password, Microsoft Authenticator, ...)
// uses these defaults.

const totpPeriod = 30

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret in base32, the form
// authenticator apps accept for manual entry.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return totpEncoding.EncodeToString(b)
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	k, err := totpEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(k) < 10 {
		return nil, fmt.Errorf("invalid TOTP secret")
	}
	return k, nil
}

func totpCode(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// TOTPCode returns the code for secret at time t.
func TOTPCode(secret string, t time.Time) (string, error) {
	k, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return totpCode(k, t.Unix()/totpPeriod), nil
}

// VerifyTOTP checks code against secret at time t, allowing one step of clock
// drift either way. It returns the matching time step, so callers can refuse
// a code that was already used.
func VerifyTOTP(secret, code string, t time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	k, err := decodeTOTPSecret(secret)
	if err != nil {
		return 0, false
	}
	now := t.Unix() / totpPeriod
	for _, step := range []int64{now, now - 1, now + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(k, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// TOTPURI returns the otpauth:// URI that authenticator apps read from a QR
// code. account names the login inside the app, e.g. "admin@myhost".
func TOTPURI(secret, account string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", "ollamawg")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + url.PathEscape("ollamawg:"+account) + "?" + v.Encode()
}

// QRSVG renders text as a QR code in SVG, dark modules on white with the
// standard four-module quiet zone.
func QRSVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	n := c.Size + 8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.Black(x, y) {
				continue
			}
			run := 1
			for x+run < c.Size && c.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+4, y+4, run, run)
			x += run - 1
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// QRTerminal renders text as a QR code with Unicode half blocks, two module
// rows per line. Light modules are drawn as blocks, so it reads correctly on
// the dark background most terminals use.
func QRTerminal(text string) (string, error) {
	c, err := qr.Encode(text, qr.L)
	if err != nil {
		return "", err
	}
	const quiet = 2
	light := func(x, y int) bool {
		if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
			return true
		}
		return !c.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < c.Size+quiet; y += 2 {
		for x := -quiet; x < c.Size+quiet; x++ {
			top, bot := light(x, y), light(x, y+1)
			switch {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
