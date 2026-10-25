// Command ollamawg secures remote access to Ollama with WireGuard.
//
// On the machine running Ollama:
//
//	ollamawg init --endpoint vpn.example.com:51820
//	ollamawg add-peer --name laptop
//	ollamawg serve
//
// On each device (with the generated laptop.yaml):
//
//	ollamawg connect --config laptop.yaml
//	curl http://127.0.0.1:11434/api/tags
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/himanshu-mamgain/ollamawg"
	"golang.org/x/term"
)

const usage = `ollamawg %s - secure Ollama over WireGuard (userspace, no root needed)

Server (the machine running Ollama):
  init         create server.yaml with fresh keys and a dashboard password
  add-peer     register a device and write its client config
  reissue      give a device a new key and config (or QR code), e.g. if it was lost
  remove-peer  delete a device; its key can no longer connect
  list-peers   show devices
  block        block a device (--device) or an IP/CIDR (--ip)
  unblock      undo a block
  serve        run the tunnel, the Ollama proxy and the dashboard
  passwd       set your own dashboard username and password
  2fa          enable, disable or check two-factor login for the dashboard
  firewall     let devices through the Windows Firewall (one permission prompt)

Client (each device):
  connect      bring the tunnel up and expose Ollama on 127.0.0.1:11434
  status       check the handshake and how the server sees this device

Other:
  keygen       print a WireGuard key pair
  version      print the version

Run "ollamawg <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, ollamawg.Version)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"init": cmdInit, "add-peer": cmdAddPeer, "reissue": cmdReissue, "remove-peer": cmdRemovePeer, "list-peers": cmdListPeers,
		"block": func(a []string) error { return cmdBlock(a, true) }, "unblock": func(a []string) error { return cmdBlock(a, false) },
		"serve": cmdServe, "passwd": cmdPasswd, "2fa": cmd2FA, "firewall": cmdFirewall, "connect": cmdConnect, "status": cmdStatus, "keygen": cmdKeygen,
		"version": func([]string) error { fmt.Println(ollamawg.Version); return nil },
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		fmt.Printf(usage, ollamawg.Version)
		return
	}
	fn, ok := cmds[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, name, ollamawg.Version)
		os.Exit(2)
	}
	if err := fn(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newFlags(name string) *flag.FlagSet {
	return flag.NewFlagSet("ollamawg "+name, flag.ContinueOnError)
}

func logger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func cmdInit(args []string) error {
	fs := newFlags("init")
	path := fs.String("config", "server.yaml", "server config file to create")
	endpoint := fs.String("endpoint", "", "public host:port clients will use to reach this server (required)")
	subnet := fs.String("subnet", ollamawg.DefaultSubnet, "tunnel address pool")
	port := fs.Int("port", ollamawg.DefaultListenPort, "WireGuard UDP listen port")
	upstream := fs.String("upstream", ollamawg.DefaultUpstream, "Ollama URL on this machine")
	admin := fs.String("admin", ollamawg.DefaultAdminListen, "dashboard listen address (keep it on loopback)")
	force := fs.Bool("force", false, "overwrite an existing config")
	user := fs.String("user", "admin", "dashboard username")
	setPass := fs.Bool("set-password", false, "choose the dashboard password (asked twice) instead of generating one")
	noFirewall := fs.Bool("no-firewall", false, "don't add the Windows Firewall rule for the WireGuard port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return errors.New("--endpoint is required, e.g. --endpoint vpn.example.com:51820 (or your public IP)")
	}
	if !ollamawg.ValidUser(*user) {
		return fmt.Errorf("--user %q: use letters, digits, '-', '_', '.' or '@'", *user)
	}
	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s already exists (use --force to overwrite; this rotates all keys)", *path)
	}
	cfg, err := ollamawg.NewServerConfig(*endpoint, *subnet, *port)
	if err != nil {
		return err
	}
	cfg.Server.Upstream = *upstream
	cfg.Admin.Listen = *admin
	if *user != "admin" {
		cfg.Admin.User = *user
	}
	if *setPass {
		pw, err := promptNewPassword(false)
		if err != nil {
			return err
		}
		if err := cfg.Admin.SetPassword(pw); err != nil {
			return err
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(*path); err != nil {
		return err
	}
	fw := "open this port in your firewall/router"
	if !*noFirewall {
		fw = initFirewall(cfg.Server.ListenPort)
	}
	fmt.Printf("Created %s\n\n", *path)
	fmt.Printf("  server public key  %s\n", cfg.Server.PrivateKey.PublicKey())
	fmt.Printf("  wireguard          udp/%d  (%s)\n", cfg.Server.ListenPort, fw)
	fmt.Printf("  tunnel address     %s\n", cfg.Server.Address)
	if *setPass {
		fmt.Printf("  dashboard          http://%s  user: %s  password: the one you chose\n\n", cfg.Admin.Listen, cfg.Admin.Username())
	} else {
		fmt.Printf("  dashboard          http://%s  user: %s  password: %s\n", cfg.Admin.Listen, cfg.Admin.Username(), cfg.Admin.Password)
		fmt.Printf("                     (choose your own with: ollamawg passwd --config %s)\n\n", *path)
	}
	fmt.Printf("Next: ollamawg add-peer --config %s --name <device>\n", *path)
	return nil
}

func cmdAddPeer(args []string) error {
	fs := newFlags("add-peer")
	path := fs.String("config", "server.yaml", "server config file")
	name := fs.String("name", "", "device name, e.g. laptop (required)")
	role := fs.String("role", "user", "user (inference), readonly, admin (can pull/delete models), or a custom role")
	models := fs.String("models", "", "comma-separated model allowlist, e.g. llama3.2,qwen3:* (empty = all)")
	rpm := fs.Int("rpm", 0, "requests per minute limit (0 = unlimited)")
	out := fs.String("out", "", "client config to write (default <name>.yaml)")
	qr := fs.Bool("qr", false, "for phones: print a QR code to scan in the WireGuard app instead of writing a config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	if *qr && *out != "" {
		return errors.New("--qr prints the config instead of writing it; drop --out")
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	cc, err := cfg.AddPeer(*name, *role)
	if err != nil {
		return err
	}
	p := &cfg.Peers[len(cfg.Peers)-1]
	p.RPM = *rpm
	for _, m := range strings.Split(*models, ",") {
		if m = strings.TrimSpace(m); m != "" {
			p.Models = append(p.Models, m)
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return deliverConfig(cfg, *path, cc, *p, "Added", *qr, *out, false)
}

func cmdReissue(args []string) error {
	fs := newFlags("reissue")
	path := fs.String("config", "server.yaml", "server config file")
	name := fs.String("name", "", "device name, device id or public key (required)")
	out := fs.String("out", "", "client config to write (default <name>.yaml; an old one is replaced)")
	qr := fs.Bool("qr", false, "for phones: print a QR code to scan in the WireGuard app instead of writing a config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	if *qr && *out != "" {
		return errors.New("--qr prints the config instead of writing it; drop --out")
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	cc, err := cfg.ReissuePeer(*name)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return deliverConfig(cfg, *path, cc, cfg.Peers[cfg.FindPeer(cc.Client.Name)], "Re-issued", *qr, *out, true)
}

// deliverConfig saves the server config and hands over the device's client
// config: as a QR code for the WireGuard app, or as a YAML file for
// `ollamawg connect`. It is the only copy of the device's private key.
func deliverConfig(cfg *ollamawg.ServerConfig, path string, cc *ollamawg.ClientConfig, p ollamawg.PeerConfig, verb string, qr bool, out string, replace bool) error {
	note := ""
	if replace {
		note = " Its old config no longer works."
	}
	if qr {
		code, err := terminalQR(cc.WireGuardQRText(), 3)
		if err != nil {
			return err
		}
		if err := cfg.Save(path); err != nil {
			return err
		}
		// Text first, QR last: then the code sits at the bottom of the window
		// and isn't scrolled out of view by lines printed after it.
		fmt.Printf("%s %s: device id %s, address %s, role %s.%s A running server picks this up automatically.\n", verb, p.Name, p.PublicKey.DeviceID(), p.Address, p.Role, note)
		fmt.Printf("With the tunnel on, open http://%s:%d/chat on the phone, or point any Ollama app at http://%s:%d.\n",
			cc.Client.ServerAddress, cc.Client.ServerPort, cc.Client.ServerAddress, cc.Client.ServerPort)
		fmt.Printf("In the WireGuard app: + > Create from QR code, and scan this. Missed it? Run: ollamawg reissue --name %s --qr\n", p.Name)
		fmt.Print(code)
		return nil
	}
	if out == "" {
		out = filepath.Join(filepath.Dir(path), p.Name+".yaml")
	}
	if _, err := os.Stat(out); err == nil && !replace {
		return fmt.Errorf("%s already exists", out)
	}
	if err := cc.Save(out); err != nil {
		return err
	}
	if err := cfg.Save(path); err != nil {
		return err
	}
	fmt.Printf("%s %s: device id %s, address %s, role %s.%s\n", verb, p.Name, p.PublicKey.DeviceID(), p.Address, p.Role, note)
	fmt.Printf("Client config: %s  (contains the device's private key; copy it securely, then delete it here)\n", out)
	fmt.Println("A running server picks this up automatically.")
	return nil
}

func cmdRemovePeer(args []string) error {
	fs := newFlags("remove-peer")
	path := fs.String("config", "server.yaml", "server config file")
	name := fs.String("name", "", "device name, device id or public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	i := cfg.FindPeer(*name)
	if i < 0 {
		return fmt.Errorf("no device %q", *name)
	}
	removed := cfg.Peers[i].Name
	cfg.Peers = append(cfg.Peers[:i], cfg.Peers[i+1:]...)
	if err := cfg.Save(*path); err != nil {
		return err
	}
	fmt.Printf("Removed %s\n", removed)
	return nil
}

func cmdListPeers(args []string) error {
	fs := newFlags("list-peers")
	path := fs.String("config", "server.yaml", "server config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDEVICE ID\tADDRESS\tROLE\tMODELS\tRPM\tSTATUS")
	for _, p := range cfg.Peers {
		st := "active"
		if p.Blocked {
			st = "BLOCKED"
		}
		models := strings.Join(p.Models, ",")
		if models == "" {
			models = "all"
		}
		rpm := "-"
		if p.RPM > 0 {
			rpm = fmt.Sprint(p.RPM)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.PublicKey.DeviceID(), p.Address, p.Role, models, rpm, st)
	}
	if len(cfg.Firewall.Rules) > 0 {
		fmt.Fprintf(tw, "\nFIREWALL (default %s)\tCIDR\tNOTE\n", cfg.Firewall.Default)
		for _, r := range cfg.Firewall.Rules {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Action, r.CIDR, r.Note)
		}
	}
	return tw.Flush()
}

func cmdBlock(args []string, block bool) error {
	verb := map[bool]string{true: "block", false: "unblock"}[block]
	fs := newFlags(verb)
	path := fs.String("config", "server.yaml", "server config file")
	dev := fs.String("device", "", "device name, device id or public key")
	ip := fs.String("ip", "", "IP or CIDR (drops its UDP packets before WireGuard)")
	note := fs.String("note", "", "why (shown in the dashboard)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*dev == "") == (*ip == "") {
		return errors.New("give exactly one of --device or --ip")
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	if *dev != "" {
		i := cfg.FindPeer(*dev)
		if i < 0 {
			return fmt.Errorf("no device %q", *dev)
		}
		cfg.Peers[i].Blocked = block
		fmt.Printf("%sed device %s (%s)\n", verb, cfg.Peers[i].Name, cfg.Peers[i].PublicKey.DeviceID())
	} else {
		var rules []ollamawg.FirewallRule
		found := false
		for _, r := range cfg.Firewall.Rules {
			if r.CIDR == *ip || strings.TrimSuffix(r.CIDR, "/32") == *ip {
				found = true
				if !block && r.Action == "block" {
					continue
				}
			}
			rules = append(rules, r)
		}
		if block {
			if found {
				return fmt.Errorf("a rule for %s already exists", *ip)
			}
			rules = append(rules, ollamawg.FirewallRule{Action: "block", CIDR: *ip, Note: *note, Added: time.Now().UTC().Truncate(time.Second)})
		} else if !found {
			return fmt.Errorf("no block rule for %s", *ip)
		}
		cfg.Firewall.Rules = rules
		fmt.Printf("%sed %s\n", verb, *ip)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return cfg.Save(*path)
}

func cmdServe(args []string) error {
	fs := newFlags("serve")
	path := fs.String("config", "server.yaml", "server config file")
	level := fs.String("log-level", "info", "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := logger(*level)
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	// Windows has no Unix mode bits (Go reports every writable file as 0666);
	// files under the user profile are protected by ACLs instead.
	if st, err := os.Stat(*path); err == nil && runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		log.Warn("config file is readable by other users; run: chmod 600 " + *path)
	}
	if open := ollamawg.CheckUpstreamExposure(cfg.Server.Upstream); len(open) > 0 {
		log.Warn("Ollama is reachable WITHOUT the tunnel; set OLLAMA_HOST=127.0.0.1:11434 and restart Ollama", "exposed_on", strings.Join(open, ", "))
	}
	warnFirewall(cfg.Server.ListenPort, log)
	srv, err := ollamawg.NewServer(cfg, ollamawg.ServerOptions{ConfigPath: *path, Logger: log})
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := srv.Reload(); err != nil {
				log.Error("reload failed", "err", err)
			}
		}
	}()
	return srv.Run(ctx)
}

func cmdConnect(args []string) error {
	fs := newFlags("connect")
	path := fs.String("config", "", "client config file (required)")
	listen := fs.String("listen", "", "local address for apps (default from config, normally 127.0.0.1:11434)")
	level := fs.String("log-level", "info", "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--config is required")
	}
	log := logger(*level)
	cfg, err := ollamawg.LoadClientConfig(*path)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Client.Listen = *listen
	}
	c, err := ollamawg.NewClient(cfg, ollamawg.ClientOptions{Logger: log})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := signalContext()
	defer cancel()

	go func() {
		hctx, hcancel := context.WithTimeout(ctx, 20*time.Second)
		defer hcancel()
		if err := c.WaitHandshake(hctx); err != nil {
			if ctx.Err() == nil {
				log.Error(err.Error(), "endpoint", cfg.Client.Endpoint)
			}
			return
		}
		log.Info("tunnel up", "server", cfg.Client.Endpoint, "device", cfg.Client.Name)
	}()
	log.Info("forwarding Ollama", "listen", "http://"+cfg.Client.Listen, "via", c.BaseURL())
	if err := c.Forward(ctx, cfg.Client.Listen); err != nil {
		if strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "Only one usage") {
			return fmt.Errorf("%s is taken (is a local Ollama running?); use --listen 127.0.0.1:11435 and set OLLAMA_HOST to match", cfg.Client.Listen)
		}
		return err
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := newFlags("status")
	path := fs.String("config", "", "client config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--config is required")
	}
	cfg, err := ollamawg.LoadClientConfig(*path)
	if err != nil {
		return err
	}
	c, err := ollamawg.NewClient(cfg, ollamawg.ClientOptions{Logger: logger("error"), DisableHello: true})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	if err := c.WaitHandshake(ctx); err != nil {
		return err
	}
	fmt.Printf("handshake ok in %s with %s\n", time.Since(start).Round(time.Millisecond), cfg.Client.Endpoint)
	who, err := c.WhoAmI(ctx)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	models, rate := "all", "unlimited"
	if ms, ok := who["models"].([]any); ok && len(ms) > 0 {
		parts := make([]string, len(ms))
		for i, m := range ms {
			parts[i] = fmt.Sprint(m)
		}
		models = strings.Join(parts, ",")
	}
	if n, ok := who["rpm"].(float64); ok && n > 0 {
		rate = fmt.Sprintf("%.0f/min", n)
	}
	fmt.Printf("device %v (%v)  role %v  address %v  models %s  rate %s\n", who["device"], who["device_id"], who["role"], who["address"], models, rate)
	resp, err := c.HTTPClient().Get(c.BaseURL() + "/api/version")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("ollama reachable through the tunnel: %s\n", resp.Status)
	return nil
}

func cmdKeygen(args []string) error {
	k, err := ollamawg.GeneratePrivateKey()
	if err != nil {
		return err
	}
	fmt.Printf("private_key: %s\npublic_key:  %s\ndevice_id:   %s\n", k, k.PublicKey(), k.PublicKey().DeviceID())
	return nil
}

const usage2FA = `usage: ollamawg 2fa <enable|disable|status> [--config server.yaml]

  enable   show a QR code for your authenticator app, confirm a code, turn 2FA on
  disable  turn 2FA off (the recovery path if you lose your phone)
  status   show whether 2FA is on

With 2FA on, the dashboard asks for the password and a 6-digit code, and
scripts or Prometheus use admin.api_token as a bearer token.
`

func cmd2FA(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprint(os.Stderr, usage2FA)
		return flag.ErrHelp
	}
	sub := args[0]
	fs := newFlags("2fa " + sub)
	path := fs.String("config", "server.yaml", "server config file")
	force := fs.Bool("force", false, "enable: replace an existing authenticator (the old one stops working)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		if cfg.Admin.TOTPSecret == "" {
			fmt.Println("2FA is off. Turn it on with: ollamawg 2fa enable")
		} else {
			fmt.Println("2FA is on. The dashboard asks for the password and a code from your authenticator app.")
		}
		return nil

	case "disable":
		if cfg.Admin.TOTPSecret == "" {
			fmt.Println("2FA is already off.")
			return nil
		}
		cfg.Admin.TOTPSecret = ""
		if err := cfg.Save(*path); err != nil {
			return err
		}
		fmt.Println("2FA is off. The dashboard uses the password alone (basic auth) again.")
		fmt.Println("A running server picks this up automatically.")
		return nil

	case "enable":
		if cfg.Admin.TOTPSecret != "" && !*force {
			return errors.New("2FA is already on (use --force to enroll a new authenticator)")
		}
		secret := ollamawg.NewTOTPSecret()
		uri := ollamawg.TOTPURI(secret, ollamawg.TOTPAccount())
		qr, err := terminalQR(uri, 2)
		if err != nil {
			return err
		}
		fmt.Println("Scan this with your authenticator app (Google Authenticator, Authy, 1Password, ...):")
		fmt.Println()
		fmt.Print(qr)
		fmt.Printf("\nOr enter this key by hand: %s\n\n", secret)
		in := bufio.NewReader(os.Stdin)
		for attempt := 1; ; attempt++ {
			fmt.Print("Enter the 6-digit code from the app: ")
			line, err := in.ReadString('\n')
			if _, ok := ollamawg.VerifyTOTP(secret, line, time.Now()); ok {
				break
			}
			if err != nil {
				return errors.New("no valid code entered; 2FA was not enabled")
			}
			if attempt == 3 {
				return errors.New("wrong code three times; 2FA was not enabled (check the clock on this machine and your phone)")
			}
			fmt.Println("That code is wrong; try again.")
		}
		cfg.Admin.TOTPSecret = secret
		if cfg.Admin.APIToken == "" {
			cfg.Admin.APIToken = ollamawg.NewAPIToken()
		}
		if err := cfg.Save(*path); err != nil {
			return err
		}
		fmt.Println("\n2FA is on. The dashboard now asks for the password and a code from the app.")
		fmt.Printf("Scripts and Prometheus: send \"Authorization: Bearer %s\" (admin.api_token in %s).\n", cfg.Admin.APIToken, *path)
		fmt.Printf("Lost your phone? Run: ollamawg 2fa disable --config %s\n", *path)
		fmt.Println("A running server picks this up automatically.")
		return nil
	}
	fmt.Fprint(os.Stderr, usage2FA)
	return fmt.Errorf("unknown 2fa command %q", sub)
}

func cmdPasswd(args []string) error {
	fs := newFlags("passwd")
	path := fs.String("config", "server.yaml", "server config file")
	user := fs.String("user", "", "new dashboard username (default: keep the current one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user != "" && !ollamawg.ValidUser(*user) {
		return fmt.Errorf("--user %q: use letters, digits, '-', '_', '.' or '@'", *user)
	}
	cfg, err := ollamawg.LoadServerConfig(*path)
	if err != nil {
		return err
	}
	// With a new username, an empty password keeps the current one.
	pw, err := promptNewPassword(*user != "")
	if err != nil {
		return err
	}
	if pw != "" {
		if err := cfg.Admin.SetPassword(pw); err != nil {
			return err
		}
	}
	if *user != "" {
		cfg.Admin.User = *user
		if *user == "admin" {
			cfg.Admin.User = ""
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(*path); err != nil {
		return err
	}
	fmt.Printf("Saved. Dashboard login: user %s", cfg.Admin.Username())
	if pw != "" {
		fmt.Print(", password stored as a bcrypt hash")
	}
	fmt.Println(".")
	fmt.Println("A running server picks this up automatically; your browser will ask you to log in again.")
	return nil
}

// promptNewPassword asks for a password twice without echoing it. When stdin
// is not a terminal it reads one line, so the password can be piped in.
func promptNewPassword(allowEmpty bool) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password on stdin")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	prompt := fmt.Sprintf("New dashboard password (at least %d characters): ", ollamawg.MinPasswordLength)
	if allowEmpty {
		prompt = "New dashboard password (Enter to keep the current one): "
	}
	for attempt := 1; ; attempt++ {
		fmt.Print(prompt)
		a, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		if len(a) == 0 && allowEmpty {
			return "", nil
		}
		if len(a) < ollamawg.MinPasswordLength {
			fmt.Printf("Too short: use at least %d characters.\n", ollamawg.MinPasswordLength)
		} else {
			fmt.Print("Repeat it: ")
			b, err := term.ReadPassword(fd)
			fmt.Println()
			if err != nil {
				return "", err
			}
			if string(a) == string(b) {
				return string(a), nil
			}
			fmt.Println("The two passwords don't match.")
		}
		if attempt == 3 {
			return "", errors.New("password not changed")
		}
	}
}

// warnFirewall tells serve's user why devices would time out. It never
// prompts: init sets the rule up, and `ollamawg firewall` is the fallback.
func warnFirewall(port int, log *slog.Logger) {
	if managed, allowed := firewallCheck(port); managed && !allowed {
		log.Warn("no ollamawg rule in Windows Firewall, so devices may not reach this server; if they time out, run: ollamawg firewall", "port", port)
	}
}

// initFirewall is init's firewall step. On Windows the firewall blocks
// inbound UDP to new programs, so init adds ollamawg's rule (one permission
// prompt) and setup needs no separate step. It returns a line for init's
// summary.
func initFirewall(port int) string {
	managed, allowed := firewallCheck(port)
	switch {
	case !managed:
		return "your firewall/router (open UDP " + fmt.Sprint(port) + " if this machine filters inbound traffic)"
	case allowed:
		return "Windows Firewall already allows it"
	}
	fmt.Println("Letting devices through Windows Firewall: click Yes when Windows asks for permission...")
	if err := firewallAllow(port); err != nil {
		return fmt.Sprintf("Windows Firewall NOT updated (%v); run: ollamawg firewall", err)
	}
	return "Windows Firewall now allows it"
}

func cmdFirewall(args []string) error {
	fs := newFlags("firewall")
	path := fs.String("config", "server.yaml", "server config file (for the WireGuard port)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	port := ollamawg.DefaultListenPort
	if cfg, err := ollamawg.LoadServerConfig(*path); err == nil {
		port = cfg.Server.ListenPort
	}
	managed, allowed := firewallCheck(port)
	switch {
	case !managed:
		fmt.Println(strings.ReplaceAll(firewallManualHelp, "51820", fmt.Sprint(port)))
		return nil
	case allowed:
		fmt.Printf("Windows Firewall already lets devices reach UDP port %d (rule %q).\n", port, firewallRuleName(port))
		return nil
	}
	fmt.Println("Asking Windows for permission to add a firewall rule (click Yes)...")
	if err := firewallAllow(port); err != nil {
		return err
	}
	fmt.Printf("Done. Devices can now reach UDP port %d on private networks (rule %q).\n", port, firewallRuleName(port))
	fmt.Println("If your Wi-Fi is set as a Public network, switch it to Private in Windows settings.")
	return nil
}
