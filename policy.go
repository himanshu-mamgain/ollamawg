package ollamawg

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// pathAllowed reports whether path matches one of the role's patterns.
// Patterns are exact paths, prefixes ending in "*", or "*" for everything.
func pathAllowed(role RoleConfig, path string) bool {
	for _, p := range role.Allow {
		switch {
		case p == "*":
			return true
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
				return true
			}
		case p == path:
			return true
		}
	}
	return false
}

// modelAllowed reports whether model is in the allowlist. "llama3" matches
// "llama3" and "llama3:latest"; "llama3:*" matches every tag of llama3.
func modelAllowed(allow []string, model string) bool {
	if len(allow) == 0 {
		return true
	}
	if model == "" {
		return false
	}
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if !strings.Contains(s, ":") {
			s += ":latest"
		}
		return s
	}
	m := norm(model)
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "*" {
			return true
		}
		if strings.HasSuffix(a, ":*") && strings.HasPrefix(m, strings.TrimSuffix(a, "*")) {
			return true
		}
		if norm(a) == m {
			return true
		}
	}
	return false
}

var modelRe = regexp.MustCompile(`"(model|name)"\s*:\s*"([^"\\]{1,200})"`)

// modelFields decodes the fields Ollama reads the model from. Using
// encoding/json gives exactly Ollama's semantics: top-level keys only,
// case-insensitive matching, last duplicate wins.
type modelFields struct {
	Model string `json:"model"`
	Name  string `json:"name"`
}

func (m modelFields) pick() string {
	if m.Model != "" {
		return m.Model
	}
	return m.Name
}

var errBodyTooLarge = errors.New("request body too large")

// readModel returns the model a request targets and leaves r.Body intact
// for the upstream.
//
// With enforce set (the device has a model allowlist) the whole body, up to
// limit bytes, is buffered and decoded exactly as Ollama will decode it, so
// the policy cannot be dodged with nested or duplicate "model" keys. Without
// it, only the first 64 KB are inspected for logging and large bodies keep
// streaming.
func readModel(r *http.Request, enforce bool, limit int64) (string, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", nil
	}
	if enforce {
		b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		r.Body.Close()
		if err != nil {
			return "", err
		}
		if int64(len(b)) > limit {
			return "", errBodyTooLarge
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		var m modelFields
		if json.Unmarshal(b, &m) != nil {
			return "", nil
		}
		return m.pick(), nil
	}

	const max = 64 << 10
	buf := make([]byte, max)
	n, err := io.ReadFull(r.Body, buf)
	buf = buf[:n]
	complete := err == io.EOF || err == io.ErrUnexpectedEOF
	if complete {
		r.Body = io.NopCloser(bytes.NewReader(buf))
	} else {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	}
	if complete {
		var m modelFields
		if json.Unmarshal(buf, &m) == nil {
			return m.pick(), nil
		}
	}
	// Truncated body: best effort, for the access log only.
	var name string
	for _, m := range modelRe.FindAllSubmatch(buf, -1) {
		if string(m[1]) == "model" {
			return string(m[2]), nil
		}
		if name == "" {
			name = string(m[2])
		}
	}
	return name, nil
}

// usageSniffer wraps an upstream response body and keeps its last few KB so
// token counts can be read from the final JSON object (Ollama's
// prompt_eval_count/eval_count, or OpenAI-style usage) once streaming ends.
type usageSniffer struct {
	io.ReadCloser
	tail    []byte
	n       int64
	onClose func(promptTok, complTok int, bytes int64)
	closed  bool
}

const sniffTail = 8 << 10

func (s *usageSniffer) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	if n > 0 {
		s.n += int64(n)
		s.tail = append(s.tail, p[:n]...)
		if len(s.tail) > 2*sniffTail {
			s.tail = append(s.tail[:0], s.tail[len(s.tail)-sniffTail:]...)
		}
	}
	return n, err
}

var (
	promptTokRe = regexp.MustCompile(`"(?:prompt_eval_count|prompt_tokens)"\s*:\s*(\d+)`)
	complTokRe  = regexp.MustCompile(`"(?:eval_count|completion_tokens)"\s*:\s*(\d+)`)
)

func lastInt(re *regexp.Regexp, b []byte) int {
	all := re.FindAllSubmatch(b, -1)
	if len(all) == 0 {
		return 0
	}
	v := 0
	for _, c := range all[len(all)-1][1] {
		v = v*10 + int(c-'0')
		if v > 1<<30 {
			return 0
		}
	}
	return v
}

func (s *usageSniffer) Close() error {
	err := s.ReadCloser.Close()
	if !s.closed {
		s.closed = true
		if s.onClose != nil {
			s.onClose(lastInt(promptTokRe, s.tail), lastInt(complTokRe, s.tail), s.n)
		}
	}
	return err
}
