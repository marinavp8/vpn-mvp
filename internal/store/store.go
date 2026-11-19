// Package store guarda los dispositivos (peers) en un JSON con escritura atómica.
// Solo se guarda la clave PÚBLICA de cada dispositivo: la privada nunca sale del navegador del alumno.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Device struct {
	ID        string     `json:"id"`
	Owner     string     `json:"owner"`    // "sub" de Keycloak (estable)
	Username  string     `json:"username"` // preferred_username (para mostrar/auditar)
	Name      string     `json:"name"`
	PublicKey string     `json:"publicKey"`
	IP        netip.Addr `json:"ip"`
	CreatedAt time.Time  `json:"createdAt"`
}

var (
	ErrNotFound    = errors.New("dispositivo no encontrado")
	ErrDuplicate   = errors.New("esa clave pública ya está registrada")
	ErrLimit       = errors.New("has alcanzado el máximo de dispositivos")
	ErrPoolFull    = errors.New("no quedan IPs libres en la red VPN")
	ErrInvalidName = errors.New("nombre no válido (1-40 caracteres)")
)

type Store struct {
	mu      sync.Mutex
	path    string
	subnet  netip.Prefix
	server  netip.Addr
	devices []Device
}

func Open(path string, server netip.Prefix) (*Store, error) {
	s := &Store{path: path, subnet: server.Masked(), server: server.Addr()}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.devices); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) All() []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Device(nil), s.devices...)
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

func (s *Store) ByOwner(owner string) []Device {
	var out []Device
	for _, d := range s.All() {
		if d.Owner == owner {
			out = append(out, d)
		}
	}
	return out
}

func (s *Store) Get(id string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.ID == id {
			return d, nil
		}
	}
	return Device{}, ErrNotFound
}

// Add asigna la primera IP libre y persiste. apply se ejecuta con el lock tomado y
// antes de guardar: si falla (p. ej. no se pudo añadir el peer a wg0) no se guarda nada.
func (s *Store) Add(d Device, maxPerOwner int, apply func(Device) error) (Device, error) {
	if l := len([]rune(d.Name)); l < 1 || l > 40 {
		return Device{}, ErrInvalidName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	used := map[netip.Addr]bool{s.server: true}
	n := 0
	for _, e := range s.devices {
		if e.PublicKey == d.PublicKey {
			return Device{}, ErrDuplicate
		}
		if e.Owner == d.Owner {
			n++
		}
		used[e.IP] = true
	}
	if maxPerOwner > 0 && n >= maxPerOwner {
		return Device{}, ErrLimit
	}
	ip, ok := s.freeIP(used)
	if !ok {
		return Device{}, ErrPoolFull
	}
	d.IP, d.ID, d.CreatedAt = ip, newID(), time.Now().UTC()
	if err := apply(d); err != nil {
		return Device{}, err
	}
	s.devices = append(s.devices, d)
	if err := s.save(); err != nil {
		s.devices = s.devices[:len(s.devices)-1]
		return Device{}, err
	}
	return d, nil
}

func (s *Store) Delete(id string, apply func(Device) error) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.devices {
		if d.ID != id {
			continue
		}
		if err := apply(d); err != nil {
			return Device{}, err
		}
		s.devices = append(s.devices[:i:i], s.devices[i+1:]...)
		return d, s.save()
	}
	return Device{}, ErrNotFound
}

// freeIP: primera dirección de la subred que no sea red, broadcast, servidor ni usada.
func (s *Store) freeIP(used map[netip.Addr]bool) (netip.Addr, bool) {
	first := s.subnet.Addr().Next()
	for ip := first; s.subnet.Contains(ip); ip = ip.Next() {
		if !s.subnet.Contains(ip.Next()) { // broadcast
			break
		}
		if !used[ip] {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".peers-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
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
	return os.Rename(tmp.Name(), s.path)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
