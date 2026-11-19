FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /wgportal ./cmd/wgportal

FROM alpine:3.22
RUN apk add --no-cache iptables ip6tables iproute2 wireguard-tools-wg ca-certificates
COPY --from=build /wgportal /usr/local/bin/wgportal
COPY entrypoint.sh /entrypoint.sh
VOLUME /data
EXPOSE 8080 51820/udp
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/entrypoint.sh"]
