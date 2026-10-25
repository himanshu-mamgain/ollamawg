package ollamawg

import (
	"net"
	"net/netip"
	"net/url"
	"time"
)

// CheckUpstreamExposure looks for the classic mistake that makes the tunnel
// pointless: Ollama listening on 0.0.0.0, so anyone on the network can skip
// the tunnel and call it directly. It returns every non-loopback address of
// this machine where the upstream port answers.
func CheckUpstreamExposure(upstream string) []string {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err != nil || !ip.IsLoopback() {
		if u.Hostname() != "localhost" {
			return nil // upstream is remote on purpose; nothing to check locally
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var open []string
	for _, a := range addrs {
		pfx, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := pfx.Addr()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			continue
		}
		target := net.JoinHostPort(ip.String(), port)
		c, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err == nil {
			c.Close()
			open = append(open, target)
		}
	}
	return open
}
