package ollamawg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ClientOptions tunes a Client. All fields are optional.
type ClientOptions struct {
	Logger *slog.Logger
	// Bind overrides the UDP socket layer (mainly for tests).
	Bind conn.Bind
	// DisableHello stops the client from reporting hostname/OS to the server.
	DisableHello bool
}

// Client is a device's end of the tunnel, entirely in user space. Use
// HTTPClient/BaseURL from Go code, or Forward to expose the remote Ollama on
// a local port for any app (curl, Open WebUI, LangChain, the ollama CLI...).
type Client struct {
	cfg  ClientSection
	opts ClientOptions
	log  *slog.Logger

	dev    *device.Device
	tnet   *netstack.Net
	target netip.AddrPort

	mu       sync.Mutex
	endpoint netip.AddrPort
	closed   chan struct{}
	once     sync.Once
}

// NewClient brings the tunnel up. The WireGuard handshake happens lazily on
// first traffic; call WaitHandshake to block until the server answers.
func NewClient(cfg *ClientConfig, opts ClientOptions) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	cs := cfg.Client
	local, _ := netip.ParseAddr(cs.Address)
	srv, _ := netip.ParseAddr(cs.ServerAddress)

	ep, err := resolveEndpoint(cs.Endpoint)
	if err != nil {
		return nil, err
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, nil, cs.MTU)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	bind := opts.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	c := &Client{
		cfg: cs, opts: opts, log: opts.Logger, tnet: tnet,
		target: netip.AddrPortFrom(srv, uint16(cs.ServerPort)), endpoint: ep, closed: make(chan struct{}),
	}
	c.dev = device.NewDevice(tun, bind, &device.Logger{
		Verbosef: func(f string, a ...any) { c.log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { c.log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
	})
	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=%d\n",
		cs.PrivateKey.Hex(), cs.ServerPublicKey.Hex(), cs.PresharedKey.Hex(), ep, srv, cs.Keepalive)
	if err := c.dev.IpcSet(uapi); err != nil {
		c.dev.Close()
		return nil, fmt.Errorf("wireguard config: %w", err)
	}
	if err := c.dev.Up(); err != nil {
		c.dev.Close()
		return nil, fmt.Errorf("wireguard up: %w", err)
	}
	go c.reresolve()
	if !opts.DisableHello {
		go c.hello()
	}
	return c, nil
}

func resolveEndpoint(hostport string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: %w", hostport, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: bad port", hostport)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(p)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolving %s: %v", host, err)
	}
	// Prefer IPv4: it is what most home/cloud setups forward.
	best := ips[0]
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			best = ip
			break
		}
	}
	return netip.AddrPortFrom(best.Unmap(), uint16(p)), nil
}

// reresolve follows DNS changes of the server endpoint (dynamic DNS).
func (c *Client) reresolve() {
	host, _, _ := net.SplitHostPort(c.cfg.Endpoint)
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			ep, err := resolveEndpoint(c.cfg.Endpoint)
			if err != nil {
				continue
			}
			c.mu.Lock()
			changed := ep != c.endpoint
			c.endpoint = ep
			c.mu.Unlock()
			if changed {
				c.log.Info("server endpoint moved", "endpoint", ep)
				_ = c.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", c.cfg.ServerPublicKey.Hex(), ep))
			}
		}
	}
}

func (c *Client) hello() {
	host, _ := os.Hostname()
	body, _ := json.Marshal(ClientInfo{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Version: Version})
	hc := c.HTTPClient()
	hc.Timeout = 15 * time.Second
	for delay := time.Second; ; delay = min(delay*2, time.Minute) {
		resp, err := hc.Post(c.BaseURL()+"/_ollamawg/hello", "application/json", bytes.NewReader(body))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return
		}
		select {
		case <-c.closed:
			return
		case <-time.After(delay):
		}
	}
}

// DialContext opens a TCP connection to an address inside the tunnel.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.tnet.DialContext(ctx, network, addr)
}

// BaseURL is the Ollama base URL inside the tunnel, e.g. http://10.77.0.1:11434.
func (c *Client) BaseURL() string { return "http://" + c.target.String() }

// HTTPClient returns an http.Client whose connections go through the tunnel.
// Point any Ollama client library at BaseURL with it.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         c.tnet.DialContext,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}}
}

// LastHandshake reports when the last WireGuard handshake with the server
// completed (zero if never).
func (c *Client) LastHandshake() time.Time {
	st, err := c.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

// WaitHandshake triggers a handshake and waits for it to complete.
func (c *Client) WaitHandshake(ctx context.Context) error {
	// Any packet towards the server triggers a handshake.
	go func() {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if conn, err := c.tnet.DialContextTCPAddrPort(dctx, c.target); err == nil {
			conn.Close()
		}
	}()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		if !c.LastHandshake().IsZero() {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("no handshake with server: check endpoint, UDP port/firewall, keys, and that this device is not blocked")
		case <-t.C:
		}
	}
}

// WhoAmI asks the server how it sees this device (name, role, policy).
func (c *Client) WhoAmI(ctx context.Context) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+"/_ollamawg/whoami", nil)
	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("server returned %s", resp.Status)
	}
	return out, nil
}

// Forward listens on addr (e.g. 127.0.0.1:11434) and pipes every connection
// to Ollama through the tunnel. It returns when ctx is cancelled.
func (c *Client) Forward(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return c.Serve(ctx, ln)
}

// Serve is Forward on an existing listener.
func (c *Client) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		lc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go c.pipe(ctx, lc)
	}
}

func (c *Client) pipe(ctx context.Context, lc net.Conn) {
	defer lc.Close()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	rc, err := c.tnet.DialContextTCPAddrPort(dctx, c.target)
	cancel()
	if err != nil {
		c.log.Warn("tunnel dial failed", "err", err)
		return
	}
	defer rc.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(rc, lc)
		rc.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(lc, rc)
		if tc, ok := lc.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.dev.Close()
	})
	return nil
}
