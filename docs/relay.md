# Relay: connect from anywhere, even behind CGNAT

Devices normally reach your server directly on its WireGuard port. That needs a public address and a forwarded UDP port. Many home and mobile connections have neither, because they sit behind carrier-grade NAT (CGNAT). Then nothing on the internet can start a connection to your server.

A **relay** gets around this. It runs on any machine with a public IP, for example a small cloud VM, and passes packets between your devices and your server:

```
 phone (5G, anywhere) ──► relay (public VM) ◄── server (home, behind CGNAT)
                           forwards packets      dials out and keeps the line open
```

1. Your server dials **out** to the relay from its WireGuard port, and repeats every 15 seconds. Outgoing traffic gets through CGNAT, and the repeats keep the NAT mapping open.
2. Devices send their WireGuard packets to the relay's address.
3. The relay passes each packet down the server's open mapping, tagged with the device's address, and sends replies back the same way.

You don't need port forwarding, a router change, or a Windows Firewall rule on the server.

## Is the relay trusted?

Barely. It is a dumb forwarder:

- **It can't read your traffic.** WireGuard encrypts everything end to end between each device and your server. The relay has no WireGuard keys.
- **It can't impersonate anyone.** Without the server's private key it can't pose as your server, and without a device's key it can't pose as a device.
- **It knows** which IP addresses talk to your server, when, and how much. It can also stop forwarding. Run it on a machine you control.
- **A shared token** (`relay.yaml`) proves which server may register. Registrations are signed with HMAC-SHA256, timestamped and never accepted twice, so a captured one can't be replayed to hijack the relay.
- **Replies go only to devices that recently sent something.** The relay can't be used to send traffic to arbitrary hosts.

Your server's firewall rules, blocking, **Who is knocking** list and access log keep working with each device's real address, because the server unwraps relayed packets before its firewall sees them.

## Setup

### 1. Get a machine with a public IP

Any small Linux VM works; the relay uses very little CPU and memory. Options include the always-free tier of Oracle Cloud, or a $4–6/month VM from Hetzner, DigitalOcean, Vultr and similar. A Raspberry Pi at a friend's place with a public IP and port forwarding works too.

Open **UDP 51820** to it in the provider's firewall or security group.

### 2. Run the relay

On the VM:

```sh
curl -fsSL https://himanshu-mamgain.github.io/ollamawg/install.sh 
Or with Docker, using the image published with every release:

```sh
docker run --rm -v /etc/ollamawg:/etc/ollamawg ghcr.io/himanshu-mamgain/ollamawg relay init --config /etc/ollamawg/relay.yaml
docker run -d --name ollamawg-relay --restart unless-stopped -p 51820:51820/udp \n  -v /etc/ollamawg:/etc/ollamawg ghcr.io/himanshu-mamgain/ollamawg relay --config /etc/ollamawg/relay.yaml
```
| sh
ollamawg relay init      # writes relay.yaml and prints its token
ollamawg relay           # runs the relay
```

To keep it running across reboots, use systemd:

```ini
# /etc/systemd/system/ollamawg-relay.service
[Unit]
Description=ollamawg relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ollamawg relay --config /etc/ollamawg/relay.yaml
DynamicUser=yes
ConfigurationDirectory=ollamawg
Restart=always

[Install]
WantedBy=multi-user.target
```

```sh
sudo mkdir -p /etc/ollamawg && sudo mv relay.yaml /etc/ollamawg/
sudo systemctl enable --now ollamawg-relay
journalctl -u ollamawg-relay -f      # shows "relay: server registered" once the server connects
```

### 3. Point your server at it

On the machine running Ollama, with an existing setup:

```sh
ollamawg relay use --relay relay.example.com:51820 --token <token from relay init>
```

For a new setup:

```sh
ollamawg init --relay relay.example.com:51820 --relay-token <token>
```

Either way, the following is set in `server.yaml`:

```yaml
server:
  public_endpoint: relay.example.com:51820   # devices dial the relay
  relay: relay.example.com:51820
  relay_token: <token>
  mtu: 1380                                  # leaves room for the relay's header
```

Restart `ollamawg serve`. Its log shows `relay: connected`, and the dashboard header shows **via relay … ●**, with a green dot.

### 4. Update existing devices

Devices added before this still dial the old address. Give each one a new config:

```sh
ollamawg reissue --name laptop          # writes a new laptop.yaml
ollamawg reissue --name phone --qr      # new QR code for the WireGuard app
```

Or, in the WireGuard app on a phone, edit the tunnel and change **Endpoint** to the relay's address. Devices added from now on get the relay address automatically.

## Switching back

If you later get a public IP:

```sh
ollamawg relay use --off --endpoint your-public-ip:51820
```

Then restart `serve` and re-issue the devices as above.

## Troubleshooting

**The dashboard says "via relay … (not connected)".**
- Is `ollamawg relay` running?
- Is UDP 51820 open in the VM's cloud firewall?
- Does `relay_token` match the token in `relay.yaml`?

The relay logs `rejected a registration with a wrong token` for a mismatch. It logs `rejected a stale registration` if the server's clock is more than 2 minutes off.

**The relay is connected, but devices time out.** Check that the device's endpoint is the relay's address. Watch the relay's log while the device connects: if nothing arrives, the VM's firewall is blocking UDP.

**It works for a while, then stops.** Some networks expire idle UDP mappings faster than 15 seconds. That's rare. Open an issue with your ISP and router model.

**Large responses stall.** Lower `mtu` in `server.yaml`, for example to 1280, then restart and re-issue devices.

## Limits

- **One server per relay.** Run a second relay, on another port or VM, for a second server.
- **All traffic passes through the relay,** including from devices on your home Wi-Fi. That adds the round trip to the VM, usually 10–50 ms.
- **The relay sees metadata,** meaning device IPs, timing and volume, but never content.
