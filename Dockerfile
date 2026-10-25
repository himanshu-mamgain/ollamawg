# Build: docker build -t ollamawg .
# Run:   docker run -d --network host -v /etc/ollamawg:/etc/ollamawg ollamawg serve --config /etc/ollamawg/server.yaml
# Relay: docker run -d -p 51820:51820/udp -v /etc/ollamawg:/etc/ollamawg ollamawg relay --config /etc/ollamawg/relay.yaml
# Published images: ghcr.io/himanshu-mamgain/ollamawg (linux/amd64, linux/arm64).

# The build stage runs on the builder's own platform and cross-compiles for
# the target, which is much faster than building under emulation.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ollamawg ./cmd/ollamawg

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/himanshu-mamgain/ollamawg" \
      org.opencontainers.image.description="Private access to your Ollama from laptop and phone: WireGuard tunnel, per-device policy, dashboard and chat page." \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/ollamawg /usr/local/bin/ollamawg
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/ollamawg"]
CMD ["serve", "--config", "/etc/ollamawg/server.yaml"]
