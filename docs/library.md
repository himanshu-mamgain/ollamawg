# Using ollamawg as a Go library

The `ollamawg` package exposes the same pieces the CLI uses. You can call a remote Ollama from Go code through the tunnel without opening any local port, or embed the server in your own program.

```sh
go get github.com/himanshu-mamgain/ollamawg
```

Full API documentation is on [pkg.go.dev](https://pkg.go.dev/github.com/himanshu-mamgain/ollamawg).

## Client: call Ollama through the tunnel

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/himanshu-mamgain/ollamawg"
)

func main() {
	cfg, err := ollamawg.LoadClientConfig("laptop.yaml")
	if err != nil {
		log.Fatal(err)
	}
	c, err := ollamawg.NewClient(cfg, ollamawg.ClientOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.WaitHandshake(ctx); err != nil {
		log.Fatal(err)
	}

	hc := c.HTTPClient() // every connection goes through WireGuard
	resp, err := hc.Post(c.BaseURL()+"/api/generate", "application/json",
		strings.NewReader(`{"model":"llama3.2","prompt":"Why is the sky blue?","stream":false}`))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(string(b))
}
```

### With the official Ollama Go client

```go
import "github.com/ollama/ollama/api"

u, _ := url.Parse(c.BaseURL())
client := api.NewClient(u, c.HTTPClient())
err := client.Chat(ctx, &api.ChatRequest{Model: "llama3.2", Messages: msgs}, func(r api.ChatResponse) error {
	fmt.Print(r.Message.Content)
	return nil
})
```

### Exposing a local port from your program

```go
go c.Forward(ctx, "127.0.0.1:11434") // same as `ollamawg connect`
```

| Client method | Purpose |
|---|---|
| `NewClient(cfg, opts)` | Brings the tunnel up in user space |
| `WaitHandshake(ctx)` | Blocks until the server answers |
| `HTTPClient()` | An `*http.Client` whose connections go through the tunnel |
| `BaseURL()` | Ollama's address inside the tunnel, e.g. `http://10.77.0.1:11434` |
| `DialContext(ctx, network, addr)` | Opens a raw TCP connection inside the tunnel |
| `Forward(ctx, addr)` / `Serve(ctx, ln)` | Local TCP forwarder |
| `WhoAmI(ctx)` | How the server sees this device: name, role and policy |
| `LastHandshake()` | Time of the last completed handshake |
| `Close()` | Tears the tunnel down |

`ClientOptions.DisableHello` stops the client from reporting its hostname and OS to the dashboard.

## Server: embed it

```go
cfg, err := ollamawg.LoadServerConfig("server.yaml")
if err != nil {
	log.Fatal(err)
}
srv, err := ollamawg.NewServer(cfg, ollamawg.ServerOptions{
	ConfigPath: "server.yaml", // enables persistence and hot reload; omit for in-memory only
	Logger:     slog.Default(),
})
if err != nil {
	log.Fatal(err)
}
go func() {
	<-srv.Ready()
	log.Println("dashboard at", srv.AdminAddr())
}()
log.Fatal(srv.Run(ctx)) // returns when ctx is cancelled
```

Once it is running, you can drive it from code:

```go
cc, _ := srv.AddDevice("ci-runner", "readonly") // returns the client config; save or send it
srv.BlockDevice("laptop", true)                 // name, device ID or public key
srv.BlockIP("block", "203.0.113.0/24", "scanner")
srv.Reload()                                    // re-read the config file

for _, d := range srv.Devices() {
	fmt.Println(d.Name, d.Online, d.Endpoint, d.Last24h.Requests)
}
for _, e := range srv.Observer().Access(50, "", false) {
	fmt.Println(e.Time, e.Device, e.Path, e.Model, e.Status, e.PromptTokens, e.CompletionTokens)
}
```

## Building configs in code

```go
cfg, _ := ollamawg.NewServerConfig("vpn.example.com:51820", "10.77.0.0/24", 51820)
cfg.Server.Upstream = "http://127.0.0.1:11434"

cc, _ := cfg.AddPeer("laptop", "user")
cfg.Peers[len(cfg.Peers)-1].Models = []string{"llama3.2"}

_ = cfg.Save("server.yaml") // atomic, mode 0600
_ = cc.Save("laptop.yaml")
```

## Keys

```go
priv, _ := ollamawg.GeneratePrivateKey()   // clamped Curve25519, like `wg genkey`
pub := priv.PublicKey()
fmt.Println(pub.String(), pub.DeviceID())  // base64 key, short device ID
k, _ := ollamawg.ParseKey("Hq3...=")       // base64 or hex
```
