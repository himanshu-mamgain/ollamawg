# Build: docker build -t ollamawg .
# Run:   docker run -d --network host -v /etc/ollamawg:/etc/ollamawg ollamawg serve --config /etc/ollamawg/server.yaml
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ollamawg ./cmd/ollamawg

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ollamawg /usr/local/bin/ollamawg
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/ollamawg"]
CMD ["serve", "--config", "/etc/ollamawg/server.yaml"]
