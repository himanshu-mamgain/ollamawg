package main

import (
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
)

// Windows Defender Firewall blocks inbound UDP to new programs, so devices
// can't reach the WireGuard port until a rule allows it. ollamawg manages a
// rule under its own name; checking by name works on every display language.

// firewallCheck reports whether this OS needs a rule (Windows does) and
// whether ollamawg's rule for port exists.
func firewallCheck(port int) (managed, allowed bool) {
	err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+firewallRuleName(port)).Run()
	return true, err == nil
}

// firewallAllow adds the rule through netsh, elevated: Windows shows one UAC
// prompt. It allows only UDP on port, on private and domain networks.
func firewallAllow(port int) error {
	args := fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=allow protocol=UDP localport=%d profile=private,domain description="ollamawg: lets registered WireGuard devices reach this server"`,
		firewallRuleName(port), port)
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString("netsh.exe")
	params, _ := windows.UTF16PtrFromString(args)
	if err := windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE); err != nil {
		if err == windows.ERROR_CANCELLED {
			return fmt.Errorf("the Windows permission prompt was declined")
		}
		return err
	}
	for i := 0; i < 40; i++ { // ShellExecute doesn't wait for netsh to finish
		if _, ok := firewallCheck(port); ok {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("the rule did not appear; add it by hand: netsh %s (in an admin terminal)", args)
}

// firewallManualHelp is only shown where ollamawg does not manage the firewall.
const firewallManualHelp = ""
