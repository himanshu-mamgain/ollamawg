package ollamawg

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// A relay lets devices reach a server that can't accept inbound connections
// (CGNAT, no port forwarding). It runs on a machine with a public address.
// The server dials out to it from its WireGuard port and keeps that UDP
// mapping alive; devices send WireGuard packets to the relay, which passes
// them down the mapping with the device's address attached, and sends the
// replies back. The relay holds no WireGuard keys: it forwards ciphertext it
// can't read, and can't impersonate the server or a device. A shared token
// only proves which server may register.
//
// Wire format, relay <-> server only (devices speak plain WireGuard):
//
//	register    F7 01 | unix time (8) | nonce (16) | HMAC-SHA256(token, "register"|time|nonce)
//	registered  F7 02 | nonce (16) | HMAC-SHA256(token, "registered"|nonce)
//	data, IPv4  F7 03 | device IPv4 (4)  | port (2) | WireGuard packet
//	data, IPv6  F7 04 | device IPv6 (16) | port (2) | WireGuard packet
//
// WireGuard packets start with a message type of 1 to 4, so 0xF7 never
// collides with them.

const (
	relayMagic      = 0xF7
	relayRegister   = 0x01
	relayRegistered = 0x02
	relayData4      = 0x03
	relayData6      = 0x04

	relayNonceLen  = 16
	relayMACLen    = sha256.Size
	relayRegLen    = 2 + 8 + relayNonceLen + relayMACLen
	relayAckLen    = 2 + relayNonceLen + relayMACLen
	relayHeaderMax = 2 + 16 + 2

	// RelayKeepalive is how often the server re-registers. NAT mappings for
	// UDP commonly expire after 30 to 120 seconds without traffic.
	RelayKeepalive = 15 * time.Second
	relayServerTTL = 4 * RelayKeepalive
	relayClockSkew = 2 * time.Minute
	relayClientTTL = 5 * time.Minute
	relayMaxClient = 4096
)

// NewRelayToken returns a random token for a relay and its server.
func NewRelayToken() string { return randomToken(24) }

func relayMAC(token []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, token)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func relayRegisterPacket(token []byte, now time.Time) []byte {
	p := make([]byte, relayRegLen)
	p[0], p[1] = relayMagic, relayRegister
	binary.BigEndian.PutUint64(p[2:10], uint64(now.Unix()))
	if _, err := rand.Read(p[10 : 10+relayNonceLen]); err != nil {
		panic(err)
	}
	copy(p[10+relayNonceLen:], relayMAC(token, []byte("register"), p[2:10+relayNonceLen]))
	return p
}

func relayAckPacket(token, nonce []byte) []byte {
	p := make([]byte, 0, relayAckLen)
	p = append(p, relayMagic, relayRegistered)
	p = append(p, nonce...)
	return append(p, relayMAC(token, []byte("registered"), nonce)...)
}

// relayEncap writes the data header for addr followed by payload into dst
// (which needs relayHeaderMax extra bytes) and returns the packet.
func relayEncap(dst []byte, addr netip.AddrPort, payload []byte) []byte {
	dst = dst[:0]
	if a := addr.Addr().Unmap(); a.Is4() {
		b := a.As4()
		dst = append(dst, relayMagic, relayData4)
		dst = append(dst, b[:]...)
	} else {
		b := a.As16()
		dst = append(dst, relayMagic, relayData6)
		dst = append(dst, b[:]...)
	}
	dst = binary.BigEndian.AppendUint16(dst, addr.Port())
	return append(dst, payload...)
}

// relayDecap splits a data packet into the device address and the WireGuard
// packet. ok is false if p is not a well-formed data packet.
func relayDecap(p []byte) (addr netip.AddrPort, payload []byte, ok bool) {
	if len(p) < 2 || p[0] != relayMagic {
		return netip.AddrPort{}, nil, false
	}
	var n int
	switch p[1] {
	case relayData4:
		n = 4
	case relayData6:
		n = 16
	default:
		return netip.AddrPort{}, nil, false
	}
	if len(p) < 2+n+2+1 {
		return netip.AddrPort{}, nil, false
	}
	ip, _ := netip.AddrFromSlice(p[2 : 2+n])
	port := binary.BigEndian.Uint16(p[2+n : 4+n])
	return netip.AddrPortFrom(ip.Unmap(), port), p[4+n:], true
}

// RelayStatus is what a relay knows about the server it serves.
type RelayStatus struct {
	ServerConnected bool      `json:"server_connected"`
	ServerAddr      string    `json:"server_addr,omitempty"`
	ServerSeen      time.Time `json:"server_seen,omitempty"`
	Devices         int       `json:"devices"` // device addresses seen recently
}

// Relay forwards WireGuard traffic between devices and one server.
type Relay struct {
	token []byte
	log   *slog.Logger
	conn  *net.UDPConn

	mu         sync.Mutex
	server     netip.AddrPort
	serverSeen time.Time
	nonces     map[[relayNonceLen]byte]time.Time // recent register nonces, against replays
	clients    map[netip.AddrPort]time.Time      // devices that sent to us recently
}

// ListenRelay opens a relay on addr (e.g. ":51820").
func ListenRelay(addr, token string, log *slog.Logger) (*Relay, error) {
	if len(token) < 16 {
		return nil, errors.New("relay token must be at least 16 characters")
	}
	if log == nil {
		log = slog.Default()
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	return &Relay{
		token: []byte(token), log: log, conn: c,
		nonces: map[[relayNonceLen]byte]time.Time{}, clients: map[netip.AddrPort]time.Time{},
	}, nil
}

// Addr is the relay's listening address.
func (r *Relay) Addr() netip.AddrPort { return r.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// Status reports the registered server and recent devices.
func (r *Relay) Status() RelayStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := RelayStatus{Devices: len(r.clients)}
	if r.server.IsValid() && time.Since(r.serverSeen) < relayServerTTL {
		st.ServerConnected, st.ServerAddr, st.ServerSeen = true, r.server.String(), r.serverSeen
	}
	return st
}

// Serve forwards packets until ctx ends.
func (r *Relay) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		r.conn.Close()
	}()
	go r.sweep(ctx)
	buf := make([]byte, 65535)
	out := make([]byte, 65535+relayHeaderMax)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue // e.g. ICMP-induced errors on some platforms
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		r.handle(buf[:n], from, out)
	}
}

func (r *Relay) handle(p []byte, from netip.AddrPort, out []byte) {
	if len(p) >= 2 && p[0] == relayMagic {
		switch p[1] {
		case relayRegister:
			r.register(p, from)
		case relayData4, relayData6:
			r.fromServer(p, from)
		}
		return // other relay messages are only meaningful to the server
	}
	// A device's WireGuard packet: hand it to the server.
	r.mu.Lock()
	server, live := r.server, r.server.IsValid() && time.Since(r.serverSeen) < relayServerTTL
	if live {
		if _, known := r.clients[from]; known || len(r.clients) < relayMaxClient {
			r.clients[from] = time.Now()
		}
	}
	r.mu.Unlock()
	if !live {
		return
	}
	_, _ = r.conn.WriteToUDPAddrPort(relayEncap(out, from, p), server)
}

func (r *Relay) register(p []byte, from netip.AddrPort) {
	if len(p) != relayRegLen {
		return
	}
	body := p[2 : 10+relayNonceLen]
	if !hmac.Equal(p[10+relayNonceLen:], relayMAC(r.token, []byte("register"), body)) {
		r.log.Warn("relay: rejected a registration with a wrong token", "from", from)
		return
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(p[2:10])), 0)
	if d := time.Since(ts); d > relayClockSkew || d < -relayClockSkew {
		r.log.Warn("relay: rejected a stale registration; check the server's clock", "from", from, "skew", d.Round(time.Second))
		return
	}
	var nonce [relayNonceLen]byte
	copy(nonce[:], p[10:10+relayNonceLen])
	r.mu.Lock()
	if _, replay := r.nonces[nonce]; replay {
		r.mu.Unlock()
		return
	}
	r.nonces[nonce] = time.Now()
	changed := r.server != from
	r.server, r.serverSeen = from, time.Now()
	r.mu.Unlock()
	if changed {
		r.log.Info("relay: server registered", "from", from)
	}
	_, _ = r.conn.WriteToUDPAddrPort(relayAckPacket(r.token, nonce[:]), from)
}

// fromServer forwards a server's reply to the device it names. Only the
// registered server may send data, and only to devices that recently sent
// something themselves, so the relay can't be used to spray other hosts.
func (r *Relay) fromServer(p []byte, from netip.AddrPort) {
	to, payload, ok := relayDecap(p)
	if !ok {
		return
	}
	r.mu.Lock()
	allowed := from == r.server && time.Since(r.serverSeen) < relayServerTTL
	if seen, known := r.clients[to]; !known || time.Since(seen) > relayClientTTL {
		allowed = false
	}
	r.mu.Unlock()
	if allowed {
		_, _ = r.conn.WriteToUDPAddrPort(payload, to)
	}
}

func (r *Relay) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.mu.Lock()
		for n, at := range r.nonces {
			if time.Since(at) > 2*relayClockSkew {
				delete(r.nonces, n)
			}
		}
		for c, at := range r.clients {
			if time.Since(at) > relayClientTTL {
				delete(r.clients, c)
			}
		}
		r.mu.Unlock()
	}
}

// String describes the relay for logs.
func (r *Relay) String() string { return fmt.Sprintf("relay on udp %s", r.Addr()) }

// RelayConfig is relay.yaml, on the machine that runs `ollamawg relay`.
type RelayConfig struct {
	// Listen is the UDP address devices and the server send to (":51820").
	Listen string `yaml:"listen"`
	// Token authenticates the server; it goes in the server's relay_token.
	Token string `yaml:"token"`
}

// NewRelayConfig returns a relay config with a fresh token.
func NewRelayConfig(listen string) *RelayConfig {
	if listen == "" {
		listen = fmt.Sprintf(":%d", DefaultListenPort)
	}
	return &RelayConfig{Listen: listen, Token: NewRelayToken()}
}

// LoadRelayConfig reads relay.yaml.
func LoadRelayConfig(path string) (*RelayConfig, error) {
	var c RelayConfig
	if err := loadYAML(path, &c); err != nil {
		return nil, err
	}
	if len(c.Token) < 16 {
		return nil, fmt.Errorf("%s: token is missing or too short", path)
	}
	if c.Listen == "" {
		c.Listen = fmt.Sprintf(":%d", DefaultListenPort)
	}
	return &c, nil
}

// Save writes relay.yaml with mode 0600 (it holds the token).
func (c *RelayConfig) Save(path string) error {
	return saveYAML(path, c, "# ollamawg relay config. The token lets a server register: keep it secret.\n")
}
