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
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/himanshu-mamgain/ollamawg"
)

const usage = `ollamawg %s - secure Ollama over WireGuard (userspace, no root needed)

Server (the machine running Ollama):
  init         create server.yaml with fresh keys and a dashboard password
  add-peer     register a device and write its client config
  remove-peer  delete a device; its key can no longer connect
  list-peers   show devices
  block        block a device (--device) or an IP/CIDR (--ip)
  unblock      undo a block
  serve        run the tunnel, the Ollama proxy and the dashboard

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
		"init": cmdInit, "add-peer": cmdAddPeer, "remove-peer": cmdRemovePeer, "list-peers": cmdListPeers,
		"block": func(a []string) error { return cmdBlock(a, true) }, "unblock": func(a []string) error { return cmdBlock(a, false) },
		"serve": cmdServe, "connect": cmdConnect, "status": cmdStatus, "keygen": cmdKeygen,
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return errors.New("--endpoint is required, e.g. --endpoint vpn.example.com:51820 (or your public IP)")
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
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(*path); err != nil {
		return err
	}
	fmt.Printf("Created %s\n\n", *path)
	fmt.Printf("  server public key  %s\n", cfg.Server.PrivateKey.PublicKey())
	fmt.Printf("  wireguard          udp/%d  (open this port in your firewall/router)\n", cfg.Server.ListenPort)
	fmt.Printf("  tunnel address     %s\n", cfg.Server.Address)
	fmt.Printf("  dashboard          http://%s  user: admin  password: %s\n\n", cfg.Admin.Listen, cfg.Admin.Password)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
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
	if *out == "" {
		*out = filepath.Join(filepath.Dir(*path), *name+".yaml")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists", *out)
	}
	if err := cc.Save(*out); err != nil {
		return err
	}
	if err := cfg.Save(*path); err != nil {
		return err
	}
	fmt.Printf("Added %s: device id %s, address %s, role %s\n", *name, p.PublicKey.DeviceID(), p.Address, p.Role)
	fmt.Printf("Client config: %s  (contains the device's private key; copy it securely, then delete it here)\n", *out)
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
	if st, err := os.Stat(*path); err == nil && st.Mode().Perm()&0o077 != 0 {
		log.Warn("config file is readable by other users; run: chmod 600 " + *path)
	}
	if open := ollamawg.CheckUpstreamExposure(cfg.Server.Upstream); len(open) > 0 {
		log.Warn("Ollama is reachable WITHOUT the tunnel; set OLLAMA_HOST=127.0.0.1:11434 and restart Ollama", "exposed_on", strings.Join(open, ", "))
	}
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
