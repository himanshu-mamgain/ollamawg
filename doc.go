// Package ollamawg exposes an Ollama server to remote devices through a
// userspace WireGuard tunnel, with per-device access control, a packet-level
// IP firewall, request/token logging and a host-only admin dashboard.
//
// A [Server] runs next to Ollama. It terminates WireGuard inside the process
// (wireguard-go on gVisor's netstack: no root, kernel module or TUN device),
// and serves an access-controlled reverse proxy to Ollama on a single address
// inside the tunnel. Devices are identified by their WireGuard public key;
// each gets a role ([RoleConfig]), an optional model allowlist and an
// optional rate limit ([PeerConfig]).
//
// A [Client] is a device's end of the tunnel. Use [Client.HTTPClient] and
// [Client.BaseURL] to call Ollama from Go code, or [Client.Forward] to expose
// it on a local port for any application.
//
// Configs are YAML ([ServerConfig], [ClientConfig]); keys use WireGuard's
// base64 format ([Key]). The ollamawg command in cmd/ollamawg wraps all of
// this in a CLI.
package ollamawg
