// Package wg gestiona la interfaz WireGuard del kernel (wgctrl) desde el portal.
package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Manager struct {
	iface  string
	client *wgctrl.Client
	pub    wgtypes.Key
}

type Peer struct {
	PublicKey string
	IP        netip.Addr
}

type Stats struct {
	LastHandshake time.Time `json:"lastHandshake"`
	RxBytes       int64     `json:"rxBytes"`
	TxBytes       int64     `json:"txBytes"`
	Endpoint      string    `json:"endpoint,omitempty"`
}

// Setup crea la interfaz si no existe, le pone IP/MTU, carga la clave del servidor
// (la genera la primera vez en keyPath, 0600) y deja exactamente los peers indicados.
func Setup(iface string, addr netip.Prefix, port, mtu int, keyPath string, peers []Peer) (*Manager, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		if err := ip("link", "add", "dev", iface, "type", "wireguard"); err != nil {
			return nil, fmt.Errorf("crear %s (¿módulo wireguard cargado en el host?): %w", iface, err)
		}
	}
	if err := ip("address", "replace", addr.String(), "dev", iface); err != nil {
		return nil, err
	}
	// MTU del túnel en el servidor: la de los clientes + margen (GCP usa 1460 en la VPC).
	if err := ip("link", "set", "dev", iface, "mtu", fmt.Sprint(mtu+40), "up"); err != nil {
		return nil, err
	}

	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	cfgPeers := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, p := range peers {
		pc, err := peerConfig(p)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("peer %s: %w", p.IP, err)
		}
		cfgPeers = append(cfgPeers, pc)
	}
	if err := c.ConfigureDevice(iface, wgtypes.Config{
		PrivateKey: &key, ListenPort: &port, ReplacePeers: true, Peers: cfgPeers,
	}); err != nil {
		c.Close()
		return nil, err
	}
	return &Manager{iface: iface, client: c, pub: key.PublicKey()}, nil
}

func (m *Manager) PublicKey() string { return m.pub.String() }

func (m *Manager) AddPeer(p Peer) error {
	pc, err := peerConfig(p)
	if err != nil {
		return err
	}
	return m.client.ConfigureDevice(m.iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}})
}

func (m *Manager) RemovePeer(publicKey string) error {
	k, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return err
	}
	return m.client.ConfigureDevice(m.iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: k, Remove: true}}})
}

// Stats por clave pública (handshake, tráfico).
func (m *Manager) Stats() map[string]Stats {
	out := map[string]Stats{}
	dev, err := m.client.Device(m.iface)
	if err != nil {
		return out
	}
	for _, p := range dev.Peers {
		s := Stats{LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint != nil {
			s.Endpoint = p.Endpoint.String()
		}
		out[p.PublicKey.String()] = s
	}
	return out
}

// ParsePublicKey valida una clave WireGuard en base64 (32 bytes, no todo ceros).
func ParsePublicKey(s string) (string, error) {
	k, err := wgtypes.ParseKey(strings.TrimSpace(s))
	if err != nil || k == (wgtypes.Key{}) {
		return "", errors.New("clave pública WireGuard no válida")
	}
	return k.String(), nil
}

func peerConfig(p Peer) (wgtypes.PeerConfig, error) {
	k, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}
	return wgtypes.PeerConfig{
		PublicKey:         k,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{{IP: p.IP.AsSlice(), Mask: net.CIDRMask(32, 32)}},
	}, nil
}

func loadOrCreateKey(path string) (wgtypes.Key, error) {
	if b, err := os.ReadFile(path); err == nil {
		return wgtypes.ParseKey(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return k, err
	}
	return k, os.WriteFile(path, []byte(k.String()+"\n"), 0o600)
}

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
