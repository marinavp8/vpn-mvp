package store

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
)

func noop(Device) error { return nil }

func TestAllocationLimitsAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	srv := netip.MustParsePrefix("10.66.0.1/30") // hosts .1 (servidor) y .2
	s, err := Open(path, srv)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Add(Device{Owner: "a", Name: "portátil", PublicKey: "k1"}, 2, noop)
	if err != nil || d.IP != netip.MustParseAddr("10.66.0.2") {
		t.Fatalf("primera IP: %v %v", d.IP, err)
	}
	if _, err := s.Add(Device{Owner: "b", Name: "x", PublicKey: "k1"}, 2, noop); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicada: %v", err)
	}
	if _, err := s.Add(Device{Owner: "b", Name: "x", PublicKey: "k2"}, 2, noop); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("pool lleno (no debe dar el broadcast .3): %v", err)
	}
	if _, err := s.Add(Device{Owner: "b", Name: "", PublicKey: "k3"}, 2, noop); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("nombre vacío: %v", err)
	}

	s2, err := Open(path, srv)
	if err != nil || len(s2.All()) != 1 || s2.All()[0].Name != "portátil" {
		t.Fatalf("reabrir: %v %+v", err, s2.All())
	}
	if _, err := s2.Delete(d.ID, noop); err != nil {
		t.Fatal(err)
	}
	if d2, err := s2.Add(Device{Owner: "b", Name: "x", PublicKey: "k2"}, 2, noop); err != nil || d2.IP != d.IP {
		t.Fatalf("reutilizar IP liberada: %v %v", d2.IP, err)
	}
}

func TestPerOwnerLimitAndApplyFailure(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "p.json"), netip.MustParsePrefix("10.66.0.1/24"))
	for i, k := range []string{"a", "b"} {
		if _, err := s.Add(Device{Owner: "o", Name: "d", PublicKey: k}, 2, noop); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := s.Add(Device{Owner: "o", Name: "d", PublicKey: "c"}, 2, noop); !errors.Is(err, ErrLimit) {
		t.Fatalf("límite: %v", err)
	}
	boom := errors.New("wg caído")
	if _, err := s.Add(Device{Owner: "p", Name: "d", PublicKey: "c"}, 2, func(Device) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("apply: %v", err)
	}
	if len(s.All()) != 2 {
		t.Fatalf("no debe guardar si apply falla: %d", len(s.All()))
	}
}
