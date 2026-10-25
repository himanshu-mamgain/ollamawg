package ollamawg

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults used when a config field is left empty.
const (
	DefaultListenPort   = 51820
	DefaultSubnet       = "10.77.0.0/24"
	DefaultUpstream     = "http://127.0.0.1:11434"
	DefaultProxyPort    = 11434
	DefaultMTU          = 1420
	DefaultAdminListen  = "127.0.0.1:8088"
	DefaultClientListen = "127.0.0.1:11434"
	DefaultKeepalive    = 25
)

// ServerConfig is the on-disk configuration of an ollamawg server
// (normally server.yaml). It holds the server's private key and the admin
// password, so it is always written with mode 0600.
type ServerConfig struct {
	Server   ServerSection         `yaml:"server"`
	Admin    AdminSection          `yaml:"admin"`
	Firewall FirewallSection       `yaml:"firewall"`
	Roles    map[string]RoleConfig `yaml:"roles,omitempty"`
	Peers    []PeerConfig          `yaml:"peers"`
}

// ServerSection configures the WireGuard listener and the upstream Ollama.
type ServerSection struct {
	PrivateKey Key `yaml:"private_key"`
	// ListenPort is the UDP port WireGuard listens on.
	ListenPort int `yaml:"listen_port"`
	// Address is the server's tunnel address in CIDR form; the prefix is the
	// pool peers get addresses from (e.g. 10.77.0.1/24).
	Address string `yaml:"address"`
	// PublicEndpoint is host:port clients use to reach this server. It is
	// written into generated client configs.
	PublicEndpoint string `yaml:"public_endpoint"`
	// Upstream is the real Ollama base URL. Keep Ollama bound to loopback.
	Upstream string `yaml:"upstream"`
	// ProxyPort is the TCP port the proxy listens on inside the tunnel.
	ProxyPort int `yaml:"proxy_port"`
	MTU       int `yaml:"mtu"`
	// MaxBodyMB caps request bodies forwarded upstream (0 = 64 MB).
	MaxBodyMB int `yaml:"max_body_mb,omitempty"`
}

// AdminSection configures the host-only dashboard and admin API.
type AdminSection struct {
	// Listen address for the dashboard. Keep it on loopback (or a management
	// network); the dashboard can block devices and issue new ones.
	Listen string `yaml:"listen"`
	// Password for HTTP basic auth (username "admin"). Empty disables the
	// dashboard entirely.
	Password string `yaml:"password"`
	// TOTPSecret turns on two-factor login: the dashboard then asks for the
	// password and a code from an authenticator app, and basic auth stops
	// working. Set it with `ollamawg 2fa enable` or from the dashboard.
	TOTPSecret string `yaml:"totp_secret,omitempty"`
	// APIToken lets scripts and Prometheus call the admin API with
	// "Authorization: Bearer <token>". Generated when 2FA is enabled, since
	// basic auth is then refused.
	APIToken string `yaml:"api_token,omitempty"`
	// AccessLogFile, if set, appends every request as a JSON line.
	AccessLogFile string `yaml:"access_log_file,omitempty"`
	// LogBuffer is how many recent access/events entries to keep in memory.
	LogBuffer int `yaml:"log_buffer,omitempty"`
}

// FirewallSection holds packet-level rules applied to UDP traffic before it
// reaches WireGuard.
type FirewallSection struct {
	// Default is "allow" (only Block rules drop) or "deny" (only sources
	// matching an allow rule get through).
	Default string         `yaml:"default"`
	Rules   []FirewallRule `yaml:"rules,omitempty"`
}

// FirewallRule matches a source IP or CIDR.
type FirewallRule struct {
	Action string    `yaml:"action" json:"action"` // "block" or "allow"
	CIDR   string    `yaml:"cidr" json:"cidr"`
	Note   string    `yaml:"note,omitempty" json:"note,omitempty"`
	Added  time.Time `yaml:"added" json:"added"`
}

// RoleConfig lists the API paths a role may call. Entries are exact paths,
// prefixes ending in "*" (e.g. "/v1/*"), or "*" for everything.
type RoleConfig struct {
	Allow []string `yaml:"allow"`
}

// PeerConfig is one client device as the server knows it. The server never
// stores a client's private key.
type PeerConfig struct {
	Name         string `yaml:"name"`
	PublicKey    Key    `yaml:"public_key"`
	PresharedKey Key    `yaml:"preshared_key,omitempty"`
	// Address is the peer's single tunnel IP. WireGuard's cryptokey routing
	// guarantees packets from this IP really come from this key.
	Address string `yaml:"address"`
	Role    string `yaml:"role"`
	// Models, if non-empty, restricts which models this device may use.
	Models []string `yaml:"models,omitempty"`
	// RPM limits requests per minute (0 = unlimited).
	RPM     int       `yaml:"rpm,omitempty"`
	Blocked bool      `yaml:"blocked,omitempty"`
	Created time.Time `yaml:"created"`
}

// ClientConfig is a device's configuration (normally <name>.yaml), produced by
// `ollamawg add-peer` or the dashboard. It contains the device's private key.
type ClientConfig struct {
	Client ClientSection `yaml:"client"`
}

// ClientSection configures the client side of the tunnel.
type ClientSection struct {
	Name            string `yaml:"name"`
	PrivateKey      Key    `yaml:"private_key"`
	Address         string `yaml:"address"`
	ServerPublicKey Key    `yaml:"server_public_key"`
	PresharedKey    Key    `yaml:"preshared_key,omitempty"`
	// Endpoint is the server's host:port (DNS names are resolved and
	// re-resolved every few minutes).
	Endpoint      string `yaml:"endpoint"`
	ServerAddress string `yaml:"server_address"`
	ServerPort    int    `yaml:"server_port"`
	// Listen is the local address apps connect to instead of Ollama.
	Listen    string `yaml:"listen"`
	Keepalive int    `yaml:"keepalive"`
	MTU       int    `yaml:"mtu"`
}

// Built-in roles. "user" can run inference and read model info; "admin" can
// also pull, push, create, copy and delete models.
var builtinRoles = map[string]RoleConfig{
	"admin": {Allow: []string{"*"}},
	"user": {Allow: []string{
		"/", "/api/version", "/api/tags", "/api/ps", "/api/show",
		"/api/chat", "/api/generate", "/api/embed", "/api/embeddings",
		"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/models", "/v1/models/*",
	}},
	"readonly": {Allow: []string{"/", "/api/version", "/api/tags", "/api/ps", "/api/show", "/v1/models", "/v1/models/*"}},
}

// NewServerConfig returns a fresh config with new keys and an admin password.
func NewServerConfig(publicEndpoint, subnet string, listenPort int) (*ServerConfig, error) {
	if subnet == "" {
		subnet = DefaultSubnet
	}
	if listenPort == 0 {
		listenPort = DefaultListenPort
	}
	pfx, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, fmt.Errorf("subnet: %w", err)
	}
	pfx = pfx.Masked()
	if !pfx.Addr().Is4() || pfx.Bits() > 30 {
		return nil, errors.New("subnet must be an IPv4 prefix of /30 or larger")
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	srvAddr := pfx.Addr().Next()
	cfg := &ServerConfig{
		Server: ServerSection{
			PrivateKey:     priv,
			ListenPort:     listenPort,
			Address:        netip.PrefixFrom(srvAddr, pfx.Bits()).String(),
			PublicEndpoint: publicEndpoint,
			Upstream:       DefaultUpstream,
			ProxyPort:      DefaultProxyPort,
			MTU:            DefaultMTU,
		},
		Admin:    AdminSection{Listen: DefaultAdminListen, Password: randomToken(18)},
		Firewall: FirewallSection{Default: "allow"},
	}
	return cfg, cfg.Validate()
}

// ServerPrefix returns the server's tunnel address and pool prefix.
func (c *ServerConfig) ServerPrefix() (netip.Prefix, error) {
	return netip.ParsePrefix(c.Server.Address)
}

// Role returns the effective role definition, letting config override the
// built-ins.
func (c *ServerConfig) Role(name string) (RoleConfig, bool) {
	if r, ok := c.Roles[name]; ok {
		return r, true
	}
	r, ok := builtinRoles[name]
	return r, ok
}

// RoleNames lists every role usable in this config.
func (c *ServerConfig) RoleNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range []string{"user", "admin", "readonly"} {
		seen[n] = true
		out = append(out, n)
	}
	for n := range c.Roles {
		if !seen[n] {
			out = append(out, n)
		}
	}
	return out
}

func (c *ServerConfig) applyDefaults() {
	s := &c.Server
	if s.ListenPort == 0 {
		s.ListenPort = DefaultListenPort
	}
	if s.Upstream == "" {
		s.Upstream = DefaultUpstream
	}
	if s.ProxyPort == 0 {
		s.ProxyPort = DefaultProxyPort
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	if s.MaxBodyMB == 0 {
		s.MaxBodyMB = 64
	}
	if c.Admin.Listen == "" {
		c.Admin.Listen = DefaultAdminListen
	}
	if c.Admin.LogBuffer == 0 {
		c.Admin.LogBuffer = 2000
	}
	if c.Firewall.Default == "" {
		c.Firewall.Default = "allow"
	}
	for i := range c.Peers {
		if c.Peers[i].Role == "" {
			c.Peers[i].Role = "user"
		}
	}
}

// Validate checks the config for mistakes that would make the tunnel insecure
// or unusable.
func (c *ServerConfig) Validate() error {
	c.applyDefaults()
	if c.Server.PrivateKey.IsZero() {
		return errors.New("server.private_key is empty")
	}
	pfx, err := c.ServerPrefix()
	if err != nil || !pfx.Addr().Is4() {
		return fmt.Errorf("server.address must be an IPv4 CIDR like 10.77.0.1/24")
	}
	u, err := url.Parse(c.Server.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("server.upstream must be an http(s) URL, got %q", c.Server.Upstream)
	}
	if c.Admin.TOTPSecret != "" {
		if _, err := decodeTOTPSecret(c.Admin.TOTPSecret); err != nil {
			return fmt.Errorf("admin.totp_secret: %w", err)
		}
	}
	switch c.Firewall.Default {
	case "allow", "deny":
	default:
		return fmt.Errorf("firewall.default must be allow or deny")
	}
	for _, r := range c.Firewall.Rules {
		if _, err := parseCIDR(r.CIDR); err != nil {
			return fmt.Errorf("firewall rule %q: %w", r.CIDR, err)
		}
		if r.Action != "block" && r.Action != "allow" {
			return fmt.Errorf("firewall rule %q: action must be block or allow", r.CIDR)
		}
	}
	names := map[string]bool{}
	keys := map[Key]bool{}
	addrs := map[netip.Addr]bool{pfx.Addr(): true}
	for _, p := range c.Peers {
		if p.Name == "" || !validName(p.Name) {
			return fmt.Errorf("peer name %q: use letters, digits, '-', '_' or '.'", p.Name)
		}
		if names[p.Name] {
			return fmt.Errorf("duplicate peer name %q", p.Name)
		}
		names[p.Name] = true
		if p.PublicKey.IsZero() || keys[p.PublicKey] {
			return fmt.Errorf("peer %q: missing or duplicate public key", p.Name)
		}
		keys[p.PublicKey] = true
		a, err := netip.ParseAddr(p.Address)
		if err != nil || !pfx.Contains(a) || addrs[a] {
			return fmt.Errorf("peer %q: address %q must be a unique IP inside %s", p.Name, p.Address, pfx.Masked())
		}
		addrs[a] = true
		if _, ok := c.Role(p.Role); !ok {
			return fmt.Errorf("peer %q: unknown role %q", p.Name, p.Role)
		}
	}
	return nil
}

func validName(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// FindPeer looks a peer up by name, device ID or public key.
func (c *ServerConfig) FindPeer(ref string) int {
	for i, p := range c.Peers {
		if p.Name == ref || p.PublicKey.DeviceID() == ref || p.PublicKey.String() == ref {
			return i
		}
	}
	return -1
}

// NextAddress returns the lowest free tunnel IP in the server's pool.
func (c *ServerConfig) NextAddress() (netip.Addr, error) {
	pfx, err := c.ServerPrefix()
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[netip.Addr]bool{pfx.Addr(): true}
	for _, p := range c.Peers {
		if a, err := netip.ParseAddr(p.Address); err == nil {
			used[a] = true
		}
	}
	m := pfx.Masked()
	for a := m.Addr().Next(); m.Contains(a); a = a.Next() {
		if !used[a] && m.Contains(a.Next()) { // skip the broadcast address
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("address pool %s is full", m)
}

// AddPeer generates a new device: a key pair, a preshared key and the next
// free address. It appends the peer to the server config and returns the
// device's client config. The private key exists only in the returned config.
func (c *ServerConfig) AddPeer(name, role string) (*ClientConfig, error) {
	if role == "" {
		role = "user"
	}
	if !validName(name) || name == "" {
		return nil, fmt.Errorf("invalid name %q: use letters, digits, '-', '_' or '.'", name)
	}
	if c.FindPeer(name) >= 0 {
		return nil, fmt.Errorf("peer %q already exists", name)
	}
	if _, ok := c.Role(role); !ok {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	if c.Server.PublicEndpoint == "" {
		return nil, errors.New("server.public_endpoint is empty; set it to the host:port clients will reach")
	}
	addr, err := c.NextAddress()
	if err != nil {
		return nil, err
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	psk, err := GeneratePresharedKey()
	if err != nil {
		return nil, err
	}
	pfx, _ := c.ServerPrefix()
	c.Peers = append(c.Peers, PeerConfig{
		Name: name, PublicKey: priv.PublicKey(), PresharedKey: psk,
		Address: addr.String(), Role: role, Created: time.Now().UTC().Truncate(time.Second),
	})
	return &ClientConfig{Client: ClientSection{
		Name:            name,
		PrivateKey:      priv,
		Address:         addr.String(),
		ServerPublicKey: c.Server.PrivateKey.PublicKey(),
		PresharedKey:    psk,
		Endpoint:        c.Server.PublicEndpoint,
		ServerAddress:   pfx.Addr().String(),
		ServerPort:      c.Server.ProxyPort,
		Listen:          DefaultClientListen,
		Keepalive:       DefaultKeepalive,
		MTU:             c.Server.MTU,
	}}, nil
}

// Validate checks a client config.
func (c *ClientConfig) Validate() error {
	s := &c.Client
	if s.Listen == "" {
		s.Listen = DefaultClientListen
	}
	if s.ServerPort == 0 {
		s.ServerPort = DefaultProxyPort
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	if s.Keepalive == 0 {
		s.Keepalive = DefaultKeepalive
	}
	if s.PrivateKey.IsZero() || s.ServerPublicKey.IsZero() {
		return errors.New("client.private_key and client.server_public_key are required")
	}
	if _, err := netip.ParseAddr(s.Address); err != nil {
		return fmt.Errorf("client.address: %w", err)
	}
	if _, err := netip.ParseAddr(s.ServerAddress); err != nil {
		return fmt.Errorf("client.server_address: %w", err)
	}
	if _, _, err := net.SplitHostPort(s.Endpoint); err != nil {
		return fmt.Errorf("client.endpoint must be host:port: %w", err)
	}
	return nil
}

// LoadServerConfig reads and validates a server config file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	var c ServerConfig
	if err := loadYAML(path, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// LoadClientConfig reads and validates a client config file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	var c ClientConfig
	if err := loadYAML(path, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Save writes the config atomically with mode 0600.
func (c *ServerConfig) Save(path string) error {
	return saveYAML(path, c, "# ollamawg server config. Contains secrets: keep it mode 0600.\n")
}

// Save writes the client config atomically with mode 0600.
func (c *ClientConfig) Save(path string) error {
	return saveYAML(path, c, "# ollamawg client config. Contains this device's private key: keep it secret.\n")
}

// Marshal returns the client config as YAML.
func (c *ClientConfig) Marshal() ([]byte, error) {
	return encodeYAML(c, "# ollamawg client config. Contains this device's private key: keep it secret.\n")
}

// WireGuardConf returns the config in wg-quick format, for the official
// WireGuard apps (iOS, Android, macOS, Windows) instead of `ollamawg
// connect`. Only the server's tunnel address is routed, so the rest of the
// device's traffic is unaffected. Apps then reach Ollama, and the chat page
// at /chat, on http://<server_address>:<server_port>.
func (c *ClientConfig) WireGuardConf() string {
	cl := c.Client
	var b strings.Builder
	fmt.Fprintf(&b, "# ollamawg device %q. Contains this device's private key: keep it secret.\n", cl.Name)
	fmt.Fprintf(&b, "# Ollama and the chat page: http://%s:%d (/chat)\n", cl.ServerAddress, cl.ServerPort)
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32\n", cl.PrivateKey, cl.Address)
	if cl.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", cl.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", cl.ServerPublicKey)
	if !cl.PresharedKey.IsZero() {
		fmt.Fprintf(&b, "PresharedKey = %s\n", cl.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\nAllowedIPs = %s/32\n", cl.Endpoint, cl.ServerAddress)
	if cl.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", cl.Keepalive)
	}
	return b.String()
}

// WireGuardQRText is WireGuardConf without comments, which keeps the QR code
// small enough to scan easily.
func (c *ClientConfig) WireGuardQRText() string {
	var out []string
	for _, l := range strings.Split(c.WireGuardConf(), "\n") {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func encodeYAML(v any, header string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func loadYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func saveYAML(path string, v any, header string) error {
	data, err := encodeYAML(v, header)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// parseCIDR accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::/32".
func parseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
