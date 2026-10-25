# Getting started

This guide takes you from nothing to a laptop chatting with a remote Ollama through an encrypted tunnel, in about ten minutes.

You need:

- A machine running Ollama, which this guide calls **the server**. It can be a home PC, a GPU box or a VPS.
- A way for devices to reach the server over UDP: a public IP, a router port forward, or a cloud firewall rule.
- Go 1.24 or newer to build `ollamawg`, or a prebuilt binary.

## 1. Keep Ollama on loopback

The tunnel only protects Ollama if Ollama is not also listening on the network. Ollama binds to `127.0.0.1:11434` by default. If you changed that, change it back:

```sh
# Linux (systemd)
sudo systemctl edit ollama        # add the two lines below
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
sudo systemctl restart ollama

# macOS
launchctl setenv OLLAMA_HOST 127.0.0.1:11434   # then restart the Ollama app
```

`ollamawg serve` checks this at startup. It warns if Ollama answers on any non-loopback address of the machine.

## 2. Install

```sh
go install github.com/himanshu-mamgain/ollamawg/cmd/ollamawg@latest
```

Or build from a checkout with `go build -o ollamawg ./cmd/ollamawg`. The same binary is used on the server and on every device.

## 3. Create the server config

```sh
mkdir -p ~/ollamawg && cd ~/ollamawg
ollamawg init --endpoint vpn.example.com:51820
```

`--endpoint` is the address devices will dial: your public IP or a DNS name, plus the UDP port. Dynamic DNS names work, because clients re-resolve them every 5 minutes.

`init` writes `server.yaml` with mode 0600 and prints the following:

- **The server's public key.** You never need to copy it by hand, because generated client configs include it.
- **The dashboard address and password.** The username is `admin`.

Useful flags:

| Flag | Default | Meaning |
|---|---|---|
| `--port` | `51820` | UDP port WireGuard listens on |
| `--subnet` | `10.77.0.0/24` | Tunnel address pool. Pick one that doesn't clash with your LAN or another VPN. |
| `--upstream` | `http://127.0.0.1:11434` | Where Ollama is |
| `--admin` | `127.0.0.1:8088` | Dashboard address. Keep it on loopback. |

## 4. Open the UDP port

Forward or allow **UDP 51820** (or your `--port`) to the server:

- **Home router:** port forward UDP 51820 to the server's LAN IP.
- **Cloud VM:** add an inbound UDP 51820 rule to the security group or firewall.
- **Host firewall:** `sudo ufw allow 51820/udp`, or `sudo firewall-cmd --add-port=51820/udp --permanent`.

You do **not** open 11434 or 8088. Those never leave the machine.

## 5. Add devices

```sh
ollamawg add-peer --name laptop
ollamawg add-peer --name phone --qr --models llama3.2,gemma3:* --rpm 30
ollamawg add-peer --name workstation --role admin
```

`--qr` is for phones: instead of writing a file, it prints a QR code to scan in the WireGuard app. See [Connect a phone](#connect-a-phone).

Each command does the following:

1. Generates a key pair and a preshared key for the device.
2. Assigns the next free tunnel IP.
3. Writes `<name>.yaml`. This is the only copy of the device's private key.
4. Registers the device in `server.yaml`.

A running server picks the change up within 2 seconds.

Roles:

| Role | Can call |
|---|---|
| `user` (default) | chat, generate, embeddings, model list and details, running models, and the OpenAI-compatible `/v1` endpoints |
| `readonly` | model list and details only |
| `admin` | everything, including pull, push, create, copy and delete |

You can also add devices from the dashboard with **Add device**. It shows the config once, with Copy and Download buttons: as YAML under **Computer**, or as a WireGuard QR code and `.conf` file under **Phone**.

## 6. Start the server

```sh
ollamawg serve
```

The output looks like this:

```
level=INFO msg="dashboard listening" url=http://127.0.0.1:8088 user=admin
level=INFO msg="wireguard listening" udp_port=51820 public_key=... tunnel=10.77.0.1:11434 peers=3
```

To keep it running after logout and across reboots, see [Running as a service](deploy.md).

## 7. Connect a device

Move `laptop.yaml` to the laptop over a channel you trust, such as `scp`, AirDrop or a password manager. Then delete it from the server, which doesn't need it.

On the laptop:

```sh
ollamawg connect --config laptop.yaml
```

The output looks like this:

```
level=INFO msg="forwarding Ollama" listen=http://127.0.0.1:11434 via=http://10.77.0.1:11434
level=INFO msg="tunnel up" server=vpn.example.com:51820 device=laptop
```

Now everything that talks to Ollama on `127.0.0.1:11434` goes through the tunnel:

```sh
curl http://127.0.0.1:11434/api/tags
ollama run llama3.2              # the ollama CLI uses OLLAMA_HOST, which defaults to 127.0.0.1:11434
```

Open WebUI, LangChain, LlamaIndex, Continue, and any OpenAI-compatible client pointed at `http://127.0.0.1:11434/v1` also work unchanged.

If a local Ollama already uses port 11434 on the device, pick another port and point your tools at it:

```sh
ollamawg connect --config laptop.yaml --listen 127.0.0.1:11435
export OLLAMA_HOST=127.0.0.1:11435
```

The built-in chat page also works here: open `http://127.0.0.1:11434/chat`.

### Connect a phone

Phones use the official **WireGuard** app (App Store, Google Play) instead of `ollamawg connect`. The server is a standard WireGuard peer, so nothing else is needed.

1. Add the device with `ollamawg add-peer --name phone --qr`, or in the dashboard with **Add device** then **Phone**.
2. In the WireGuard app, tap **+**, then **Create from QR code**, and scan it. The QR code is the only copy of the phone's private key.
3. Turn the tunnel on. Only the server's tunnel address is routed through it, so the rest of the phone's traffic is unaffected.
4. Open **`http://10.77.0.1:11434/chat`** in the phone's browser. This is a ChatGPT-style chat page served by ollamawg. Use **Share → Add to Home Screen** to open it like an app.

The chat page has no login. The phone's WireGuard key identifies it, and its role, model allowlist and rate limit apply exactly as for any other device. Chats are stored in the phone's browser only.

Mobile Ollama apps such as Enchanted (iOS) or Reins (Android) also work: point them at `http://10.77.0.1:11434`.

## 8. Check it

```sh
ollamawg status --config laptop.yaml
```

The output looks like this:

```
handshake ok in 48ms with vpn.example.com:51820
device laptop (b17c4b14)  role user  address 10.77.0.2  models all  rate unlimited
ollama reachable through the tunnel: 200 OK
```

The device appears as **Connected** on the dashboard within a few seconds. Its hostname and OS appear as soon as it checks in.

## Troubleshooting

**`no handshake with server`**

- **The UDP port isn't reachable.** This is the most common cause. Test from outside your network, for example over a phone hotspot.
- **Your ISP uses CGNAT.** Port forwarding can't work then. To check:
  - Look at the WAN address on your router's status page. If it's private (`10.x`, `100.64.x` to `100.127.x`, `172.16.x` to `172.31.x`, `192.168.x`) and differs from what `curl https://api.ipify.org` shows, you're behind CGNAT.
  - Or run `tracert -d 8.8.8.8` (`traceroute -n` on Linux and macOS). A private address on the hop right after your router points the same way.

  Your options:
  - Use the server's LAN IP as `server.public_endpoint` for devices on the same network.
  - Ask your ISP for a public IP.
  - Rent a small VPS that forwards UDP 51820 to the server.

  After changing the endpoint, re-add devices, because their configs contain the old one.
- **The endpoint in the client config is wrong.**
- **The device was blocked or removed.** Check the dashboard.
- **The device's IP matches a firewall block rule,** or `firewall.default` is `deny`. The dashboard's "Who is knocking" table shows the device's IP with a dropped count.

**`403 role "user" may not call /api/pull`**: the device's role doesn't allow that endpoint. Change the role in the dashboard (**Policy**) or in `server.yaml`.

**`403 model "x" is not allowed for this device`**: the device has a model allowlist. Edit it under **Policy**.

**`429 rate limit`**: the device has an `rpm` limit.

**`502 ollama upstream unavailable`**: Ollama isn't running on the server, or `server.upstream` is wrong. The dashboard header shows whether Ollama is reachable.

**A device was unblocked but still can't connect**: WireGuard clients retry the handshake on their own within about 15 seconds. Restarting `ollamawg connect` reconnects immediately.
