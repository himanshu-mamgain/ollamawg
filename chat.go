package ollamawg

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"strings"
)

// The chat page is a small web app served by the tunnel proxy at /chat, so
// phones (through the WireGuard app) and computers (through `ollamawg
// connect`) get a ChatGPT-style interface to Ollama. It calls the same
// policy-checked API as any other client; the device's WireGuard key is its
// login.

//go:embed chat
var chatFS embed.FS

var chatFiles = func() http.Handler {
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
	sub, _ := fs.Sub(chatFS, "chat")
	return http.StripPrefix("/chat", http.FileServerFS(sub))
}()

func isChatPath(p string) bool { return p == "/chat" || strings.HasPrefix(p, "/chat/") }

func serveChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	if r.URL.Path == "/chat" {
		http.Redirect(w, r, "/chat/", http.StatusFound)
		return
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("Cache-Control", "no-cache")
	chatFiles.ServeHTTP(w, r)
}
