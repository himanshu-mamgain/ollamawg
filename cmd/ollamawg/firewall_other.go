//go:build !windows

package main

import "errors"

// On Linux, macOS and the BSDs ollamawg doesn't manage firewall rules:
// most desktops don't filter inbound UDP, and servers use tools (ufw,
// firewalld, nftables, pf, cloud security groups) that are better left to
// their owners. firewallManualHelp explains what to open.

func firewallCheck(int) (managed, allowed bool) { return false, true }

func firewallAllow(int) error {
	return errors.New("ollamawg manages firewall rules only on Windows")
}

const firewallManualHelp = `If this machine runs a firewall, allow inbound UDP on the WireGuard port:
  ufw allow 51820/udp                                   (Ubuntu, Debian)
  firewall-cmd --add-port=51820/udp --permanent && firewall-cmd --reload   (Fedora, RHEL)
On macOS, allow ollamawg when the system asks, or under System Settings > Network > Firewall.
On a cloud VM, also open UDP 51820 in the provider's security group or firewall.`
