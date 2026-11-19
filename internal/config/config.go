// Package config lee la configuración del portal desde variables de entorno.
package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen    string // dirección HTTP interna (Traefik delante)
	PublicURL string // https://vpn.alumnos.codecrypto.academy
	DataDir   string // peers.json + server.key

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	AllowedGroups    []string // vacío = cualquier usuario autenticado del realm
	AdminGroups      []string
	SessionKey       []byte

	WGInterface  string
	WGPort       int
	WGAddress    netip.Prefix // IP del servidor dentro del túnel + máscara, p. ej. 10.66.0.1/22
	WGEndpoint   string       // host:puerto que ponen los clientes
	WGDNS        string
	WGMTU        int
	WGAllowedIPs string // lo que enruta el cliente por el túnel
	MaxDevices   int
}

func Load() (*Config, error) {
	c := &Config{
		Listen:           env("LISTEN", ":8080"),
		PublicURL:        strings.TrimRight(env("PUBLIC_URL", ""), "/"),
		DataDir:          env("DATA_DIR", "/data"),
		OIDCIssuer:       env("OIDC_ISSUER", ""),
		OIDCClientID:     env("OIDC_CLIENT_ID", "vpn"),
		OIDCClientSecret: env("OIDC_CLIENT_SECRET", ""),
		AllowedGroups:    list(env("OIDC_ALLOWED_GROUPS", "")),
		AdminGroups:      list(env("OIDC_ADMIN_GROUPS", "vpn-admin")),
		WGInterface:      env("WG_INTERFACE", "wg0"),
		WGEndpoint:       env("WG_ENDPOINT", ""),
		WGDNS:            env("WG_DNS", "1.1.1.1, 9.9.9.9"),
		WGAllowedIPs:     env("WG_CLIENT_ALLOWED_IPS", "0.0.0.0/0, ::/0"),
	}
	var err error
	if c.WGPort, err = strconv.Atoi(env("WG_PORT", "51820")); err != nil {
		return nil, fmt.Errorf("WG_PORT: %w", err)
	}
	if c.WGMTU, err = strconv.Atoi(env("WG_MTU", "1380")); err != nil {
		return nil, fmt.Errorf("WG_MTU: %w", err)
	}
	if c.MaxDevices, err = strconv.Atoi(env("WG_MAX_DEVICES", "3")); err != nil {
		return nil, fmt.Errorf("WG_MAX_DEVICES: %w", err)
	}
	if c.WGAddress, err = netip.ParsePrefix(env("WG_ADDRESS", "10.66.0.1/22")); err != nil || !c.WGAddress.Addr().Is4() {
		return nil, fmt.Errorf("WG_ADDRESS debe ser IPv4/CIDR: %v", err)
	}
	if c.SessionKey, err = hex.DecodeString(os.Getenv("SESSION_KEY")); err != nil || len(c.SessionKey) < 32 {
		return nil, fmt.Errorf("SESSION_KEY: hex de al menos 32 bytes (openssl rand -hex 32)")
	}
	for k, v := range map[string]string{"PUBLIC_URL": c.PublicURL, "OIDC_ISSUER": c.OIDCIssuer,
		"OIDC_CLIENT_SECRET": c.OIDCClientSecret, "WG_ENDPOINT": c.WGEndpoint} {
		if v == "" {
			return nil, fmt.Errorf("falta %s", k)
		}
	}
	return c, nil
}

// Subnet es la red de los clientes (WG_ADDRESS sin los bits de host).
func (c *Config) Subnet() netip.Prefix { return c.WGAddress.Masked() }

// SecureCookies: solo se desactiva al probar en local por http.
func (c *Config) SecureCookies() bool { return strings.HasPrefix(c.PublicURL, "https://") }

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
