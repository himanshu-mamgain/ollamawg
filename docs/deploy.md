# Running as a service

## Server on Linux (systemd)

Create a user to run the server and a directory for its config:

```sh
sudo useradd --system --home /etc/ollamawg --shell /usr/sbin/nologin ollamawg
sudo install -d -o ollamawg -g ollamawg -m 700 /etc/ollamawg
sudo install -m 755 ollamawg /usr/local/bin/ollamawg
cd /etc/ollamawg
sudo -u ollamawg ollamawg init --config /etc/ollamawg/server.yaml --endpoint vpn.example.com:51820
```

Save the unit below as `/etc/systemd/system/ollamawg.service`:

```ini
[Unit]
Description=ollamawg - WireGuard front door for Ollama
After=network-online.target ollama.service
Wants=network-online.target

[Service]
User=ollamawg
ExecStart=/usr/local/bin/ollamawg serve --config /etc/ollamawg/server.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2

# Hardening: it only needs a UDP socket, loopback, and its config dir.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/ollamawg -/var/log/ollamawg
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

Then start it:

```sh
sudo install -d -o ollamawg -m 700 /var/log/ollamawg   # only if you set admin.access_log_file
sudo systemctl daemon-reload
sudo systemctl enable --now ollamawg
journalctl -u ollamawg -f
```

Add devices as the service user. The running server picks them up without a restart:

```sh
sudo -u ollamawg ollamawg add-peer --config /etc/ollamawg/server.yaml --name laptop --out /tmp/laptop.yaml
```

To use a port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` and drop the empty `CapabilityBoundingSet=`. The default port 51820 doesn't need either.

## Client on Linux (systemd user unit)

Save this as `~/.config/systemd/user/ollamawg.service`:

```ini
[Unit]
Description=ollamawg tunnel to Ollama
After=network-online.target

[Service]
ExecStart=%h/.local/bin/ollamawg connect --config %h/.config/ollamawg/laptop.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
```

Then enable it:

```sh
systemctl --user enable --now ollamawg
loginctl enable-linger $USER     # keep it running when logged out
```

## Client on macOS (launchd)

Save this as `~/Library/LaunchAgents/dev.ollamawg.connect.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.ollamawg.connect</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/ollamawg</string>
    <string>connect</string>
    <string>--config</string>
    <string>/Users/YOU/.config/ollamawg/laptop.yaml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/tmp/ollamawg.log</string>
</dict>
</plist>
```

Then load it:

```sh
launchctl load ~/Library/LaunchAgents/dev.ollamawg.connect.plist
```

The same pattern runs the server on a Mac. Use `serve --config ...` instead of `connect`, and make it a LaunchDaemon if it should run before login.

## Windows

The binary runs as a normal console program; no driver or admin rights are needed. To start it at logon, use Task Scheduler. Create a task "At log on" running:

```
C:\Tools\ollamawg.exe connect --config C:\Users\you\ollamawg\laptop.yaml
```

To run the server as a real Windows service, wrap it with a service manager such as [NSSM](https://nssm.cc) or WinSW.

## Docker

A `Dockerfile` is included in the repository.

```sh
docker build -t ollamawg .
docker run -d --name ollamawg --network host \
  -v /etc/ollamawg:/etc/ollamawg \
  ollamawg serve --config /etc/ollamawg/server.yaml
```

The image runs as the distroless `nonroot` user (uid 65532), so give it the config directory first: `sudo chown -R 65532 /etc/ollamawg`. Build from a checkout that has `go.sum` committed; run `go mod tidy` once if it doesn't.

`--network host` lets the container reach Ollama on the host's loopback and keeps the dashboard on loopback. If you run Ollama in Docker too, put both on one user-defined network instead. Set `server.upstream: http://ollama:11434`, don't publish Ollama's port, publish only `51820/udp`, and set `admin.listen: 0.0.0.0:8088` with `-p 127.0.0.1:8088:8088`.

## Network setup

- **Port forward.** On your router, forward **UDP** 51820 to the server. TCP is not used.
- **CGNAT.** If your ISP gives you no public IPv4 address, run `ollamawg` on a small VPS. Point `upstream` at your home machine over another tunnel, or run Ollama on the VPS itself.
- **Dynamic IP.** Use a DDNS name as `--endpoint`. Clients re-resolve it every 5 minutes and follow address changes without reconnecting.
- **Mobile networks or hotel Wi-Fi.** If handshakes work but large responses stall, lower `mtu` to 1280 on both sides.
- **Firewall default deny.** Only use `firewall.default: deny` if your devices connect from fixed addresses. Otherwise keep `allow`, because keys already keep strangers out, and block abusive networks individually.

## Upgrading

Replace the binary and restart. Config files are forward-compatible within a major version. Devices reconnect on their own within seconds.
