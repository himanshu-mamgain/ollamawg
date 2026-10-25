package main

import "fmt"

// firewallRuleName is the Windows Firewall rule ollamawg manages for port.
func firewallRuleName(port int) string { return fmt.Sprintf("ollamawg-udp-%d", port) }
