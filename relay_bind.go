package ollamawg

import (
	"crypto/hmac"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// relayBind is the server's side of a relay. It wraps the WireGuard socket:
// it registers with the relay from that socket (keeping the NAT mapping
// open), turns relayed packets back into packets "from" the device's real
// address, and wraps replies to such devices for the relay. Devices that
// reach the server directly are untouched, so direct and relayed devices
// work side by side. It sits below the firewall, which therefore sees and
// filters real device addresses.
type relayBind struct {
	conn.Bind
	addr  string // relay host:port, re-resolved on every keepalive
	token []byte
	log   *slog.Logger

	mu      sync.Mutex
	ep      conn.Endpoint  // the relay, as the inner bind addresses it
	ap      netip.AddrPort // the relay's resolved address
	pending map[[relayNonceLen]byte]time.Time
	lastAck time.Time
	stop    chan struct{}
}

func newRelayBind(inner conn.Bind, addr, token string, log *slog.Logger) *relayBind {
	return &relayBind{Bind: inner, addr: addr, token: []byte(token), log: log, pending: map[[relayNonceLen]byte]time.Time{}}
}

// relayedEndpoint is a device that reaches the server through the relay.
// Its address is the device's real public address, as the relay saw it.
type relayedEndpoint struct{ addr netip.AddrPort }

func (e *relayedEndpoint) ClearSrc()           {}
func (e *relayedEndpoint) SrcToString() string { return "" }
func (e *relayedEndpoint) DstToString() string { return e.addr.String() }
func (e *relayedEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *relayedEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *relayedEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}

func (b *relayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	stop := make(chan struct{})
	b.mu.Lock()
	b.stop = stop
	b.mu.Unlock()
	go b.keepalive(stop)
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrap(fn)
	}
	return wrapped, actual, nil
}

func (b *relayBind) Close() error {
	b.mu.Lock()
	if b.stop != nil {
		close(b.stop)
		b.stop = nil
	}
	b.mu.Unlock()
	return b.Bind.Close()
}

// keepalive registers with the relay now and every RelayKeepalive.
func (b *relayBind) keepalive(stop chan struct{}) {
	t := time.NewTicker(RelayKeepalive)
	defer t.Stop()
	for {
		b.register()
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

func (b *relayBind) register() {
	ua, err := net.ResolveUDPAddr("udp", b.addr)
	if err != nil {
		b.log.Warn("relay: can't resolve address", "relay", b.addr, "err", err)
		return
	}
	ap := netip.AddrPortFrom(ua.AddrPort().Addr().Unmap(), ua.AddrPort().Port())
	ep, err := b.Bind.ParseEndpoint(ap.String())
	if err != nil {
		b.log.Warn("relay: bad address", "relay", b.addr, "err", err)
		return
	}
	pkt := relayRegisterPacket(b.token, time.Now())
	var nonce [relayNonceLen]byte
	copy(nonce[:], pkt[10:10+relayNonceLen])
	b.mu.Lock()
	b.ep, b.ap = ep, ap
	for n, at := range b.pending {
		if time.Since(at) > relayServerTTL {
			delete(b.pending, n)
		}
	}
	b.pending[nonce] = time.Now()
	wasUp := time.Since(b.lastAck) < relayServerTTL
	b.mu.Unlock()
	if err := b.Bind.Send([][]byte{pkt}, ep); err != nil {
		b.log.Debug("relay: register failed", "relay", b.addr, "err", err)
	}
	if wasUp && !b.Connected() {
		b.log.Warn("relay: lost contact", "relay", b.addr)
	}
}

func (b *relayBind) isRelay(ep conn.Endpoint) bool {
	b.mu.Lock()
	ap := b.ap
	b.mu.Unlock()
	if !ap.IsValid() || ep.DstIP().Unmap() != ap.Addr() {
		return false
	}
	got, err := netip.ParseAddrPort(ep.DstToString())
	return err == nil && got.Port() == ap.Port()
}

func (b *relayBind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil || n == 0 {
				return n, err
			}
			kept := 0
			for i := 0; i < n; i++ {
				p := bufs[i][:sizes[i]]
				if len(p) > 0 && p[0] == relayMagic && b.isRelay(eps[i]) {
					addr, payload, ok := relayDecap(p)
					if !ok {
						b.ack(p)
						continue
					}
					// Move the WireGuard packet to the front of buffer kept.
					sizes[kept] = copy(bufs[kept], payload)
					eps[kept] = &relayedEndpoint{addr: addr}
					kept++
					continue
				}
				if kept != i {
					copy(bufs[kept][:sizes[i]], p)
					sizes[kept] = sizes[i]
					eps[kept] = eps[i]
				}
				kept++
			}
			if kept > 0 {
				return kept, nil
			}
		}
	}
}

// ack records the relay's answer to a registration.
func (b *relayBind) ack(p []byte) {
	if len(p) != relayAckLen || p[1] != relayRegistered {
		return
	}
	nonce := p[2 : 2+relayNonceLen]
	if !hmac.Equal(p[2+relayNonceLen:], relayMAC(b.token, []byte("registered"), nonce)) {
		return
	}
	var n [relayNonceLen]byte
	copy(n[:], nonce)
	b.mu.Lock()
	_, ok := b.pending[n]
	delete(b.pending, n)
	first := time.Since(b.lastAck) >= relayServerTTL
	if ok {
		b.lastAck = time.Now()
	}
	b.mu.Unlock()
	if ok && first {
		b.log.Info("relay: connected", "relay", b.addr)
	}
}

func (b *relayBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	re, ok := ep.(*relayedEndpoint)
	if !ok {
		return b.Bind.Send(bufs, ep)
	}
	b.mu.Lock()
	relay := b.ep
	b.mu.Unlock()
	if relay == nil {
		return net.ErrClosed
	}
	out := make([][]byte, len(bufs))
	for i, p := range bufs {
		out[i] = relayEncap(make([]byte, 0, len(p)+relayHeaderMax), re.addr, p)
	}
	return b.Bind.Send(out, relay)
}

// Connected reports whether the relay answered a recent registration.
func (b *relayBind) Connected() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Since(b.lastAck) < relayServerTTL
}

// LastAck is when the relay last confirmed the registration.
func (b *relayBind) LastAck() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastAck
}
