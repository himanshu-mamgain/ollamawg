# Security model

This page covers what `ollamawg` protects against, how it does it, and where its protection stops.

## What it protects

Ollama has no authentication. Anyone who can reach its port can do the following:

- Run any model on your hardware.
- Pull models until your disk fills.
- Delete models.
- Read the names of everything you have.

Ollama servers left open on the internet are routinely found and abused.

`ollamawg` keeps Ollama on loopback and makes the only remote path go through four checks. Each layer is independent.

| Layer | Stops | How |
|---|---|---|
| Packet firewall | Known-bad networks, or everyone outside your allowlist | Source-IP rules checked on every UDP datagram before WireGuard parses it |
| WireGuard | Anyone without a registered key | Noise IK handshake with Curve25519, ChaCha20-Poly1305 and BLAKE2s, plus a per-device preshared key. Unknown keys get no response at all, so the port looks closed to scanners. |
| Identity | Spoofing another device | WireGuard's cryptokey routing: a peer can only send from its own tunnel IP. The proxy identifies devices by that IP. |
| Proxy policy | A device doing more than it should | Role path rules, model allowlist, rate limit and body size cap, checked per request |

## Design decisions

**Userspace WireGuard.** The tunnel ends inside the `ollamawg` process, in gVisor's TCP/IP stack. No interface is added to the host. That has three consequences:

- Devices can reach exactly one thing, the proxy on `10.77.0.1:11434`. They cannot reach the host's other ports, its LAN, or each other.
- No root is needed, and there are no routing or iptables changes to get wrong.
- `ollamawg` cannot accidentally become a VPN into your network.

**Identity is the key, not anything the client says.** The device ID is derived from the WireGuard public key. The hostname and OS a client reports are labelled as self-reported and are never used for decisions.

**Fail closed.** Unknown tunnel IPs get `403`. A device with a model allowlist whose request names no model gets `403`. Non-canonical paths get `400`. Requests over `max_body_mb` get `413`.

**Model checks decode JSON exactly like Ollama.** For allowlisted devices the whole body is decoded with Go's `encoding/json`, the same decoder Ollama's API uses. A nested `"model"`, a duplicate key or a different capitalisation cannot point Ollama at a model the policy didn't check. These cases are covered by the test suite.

**No client credentials go upstream.** The proxy strips `Authorization` headers and rewrites `Host`, so Ollama's own host checks keep working.

**Blocking is immediate.** Blocking a device removes its peer from WireGuard, which discards its session keys. Blocking an IP drops its packets before decryption. Both are written to `server.yaml`, so they survive restarts.

## The dashboard

The dashboard can create devices and lift blocks, so it is treated as privileged:

- It listens on `127.0.0.1:8088` by default. Reach it remotely through SSH (`ssh -L 8088:127.0.0.1:8088 host`) or over the tunnel host's own admin access. Don't expose it publicly.
- It uses HTTP basic auth with a random 24-character password generated at `init`, compared in constant time. Failed logins are slowed and logged as security events.
- **Two-factor login** is optional: turn it on from the dashboard's **2FA** button or with `ollamawg 2fa enable`. The dashboard then needs the password plus a code from an authenticator app (standard TOTP, RFC 6238), and basic auth is refused.
  - A successful login sets an `HttpOnly`, `SameSite=Strict` session cookie that lasts 12 hours. Sessions live in memory, so they end when the server restarts or the authenticator is re-enrolled.
  - Codes are accepted one step either side of now, for clock drift, and each code works once.
  - Failed logins are throttled globally: after 10 failures, one attempt every 10 seconds.
  - Scripts and Prometheus use `admin.api_token` as a bearer token instead of the password.
  - If you lose the phone, run `ollamawg 2fa disable` on the server. Anyone who can do that can already read `server.yaml`, so this is no weaker than the password.
- When bound to loopback, it refuses requests whose `Host` header isn't a loopback name. This blocks DNS-rebinding attacks from web pages you visit.
- Every state-changing request must carry an `X-Ollamawg: 1` header, and cross-origin `Origin`s are refused. A malicious page cannot forge clicks even if your browser has cached the password.
- It sends a strict Content-Security-Policy: no inline scripts and no third-party origins. It also sends `X-Frame-Options: DENY`.
- New device configs, which contain the private key, are shown once and never stored on the server.

Basic auth or a session cookie over plain HTTP is fine on loopback or an SSH tunnel. If you bind the dashboard to a LAN address, put it behind TLS, for example a reverse proxy, or keep it on a management network.

## Keys and files

- `server.yaml` (server private key, dashboard password, 2FA secret, API token) and each `<device>.yaml` (device private key) are written with mode 0600, atomically.
- `serve` warns if `server.yaml` is readable by other users (on Unix; on Windows, files in your user folder are protected by its ACLs).
- The server only stores device **public** keys and preshared keys. Losing `server.yaml` means re-issuing configs. Leaking it means rotating everything: run `init --force` and add the devices again.
- To revoke a device, run `remove-peer`, or press **Delete** in the dashboard. A leaked device config is useless once its peer is removed.

## Startup checks

`ollamawg serve` warns when:

- **Ollama answers on a non-loopback address of the machine.** That means `OLLAMA_HOST=0.0.0.0` and the tunnel can be bypassed. Fix it as shown in [Getting started](getting-started.md#1-keep-ollama-on-loopback).
- **The config file is group- or world-readable.**

## Limits worth knowing

- **Source IPs can be spoofed for UDP.** IP block rules stop junk and scanners cheaply, but they are not authentication. The WireGuard key is. A spoofed packet still can't complete a handshake.
- **Default-deny firewall mode depends on clients' public IPs.** Phones and laptops roam, so prefer `allow` plus keys unless your clients have fixed addresses.
- **Rate limits are per device and in memory.** They reset on restart and are not a quota system.
- **Token counts are read from Ollama's responses.** Prompts and outputs are never logged. The access log records metadata only: device, IP, path, model, status, timing and token counts.
- **`connect --listen 0.0.0.0:...` shares the device's tunnel with its LAN,** and everyone there then acts as that device. The default is loopback only.
- **The dashboard is not multi-user.** There is one admin password. Put a reverse proxy with SSO in front if several people need it.
- **This project has not had an independent security audit.** The cryptography comes from wireguard-go and gVisor, which are widely deployed. The policy layer is small, covered by end-to-end tests, and worth reading before you rely on it.

## Reporting issues

Please report vulnerabilities privately to the maintainer rather than in a public issue.
