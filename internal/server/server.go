// Package server: rutas HTTP del portal (páginas + API JSON).
package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"codecrypto.academy/vpn/internal/auth"
	"codecrypto.academy/vpn/internal/config"
	"codecrypto.academy/vpn/internal/store"
	"codecrypto.academy/vpn/internal/wg"
)

type Server struct {
	cfg    *config.Config
	auth   *auth.Auth
	store  *store.Store
	wg     *wg.Manager
	static fs.FS
}

func New(cfg *config.Config, a *auth.Auth, s *store.Store, m *wg.Manager, static fs.FS) *Server {
	return &Server{cfg: cfg, auth: a, store: s, wg: m, static: static}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /login", s.auth.Login)
	mux.HandleFunc("GET /callback", s.auth.Callback)
	mux.HandleFunc("POST /logout", s.auth.Logout)

	mux.HandleFunc("GET /api/me", s.api(s.me))
	mux.HandleFunc("GET /api/devices", s.api(s.listOwn))
	mux.HandleFunc("POST /api/devices", s.api(s.create))
	mux.HandleFunc("DELETE /api/devices/{id}", s.api(s.remove))
	mux.HandleFunc("GET /api/admin/devices", s.api(s.listAll))

	files := http.FileServerFS(s.static)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && s.auth.User(r) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	return securityHeaders(mux, issuerOrigin(s.cfg.OIDCIssuer))
}

type apiFunc func(r *http.Request, u *auth.User) (any, int, error)

// api: exige sesión, comprueba Origin en escrituras y serializa a JSON.
func (s *Server) api(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		u := s.auth.User(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "sesión caducada")
			return
		}
		if r.Method != http.MethodGet {
			if err := s.auth.SameOrigin(r); err != nil {
				writeErr(w, http.StatusForbidden, err.Error())
				return
			}
		}
		out, code, err := f(r, u)
		if err != nil {
			if code >= 500 {
				slog.Error("api", "path", r.URL.Path, "user", u.Username, "err", err)
				writeErr(w, code, "error interno")
				return
			}
			writeErr(w, code, err.Error())
			return
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(out)
	}
}

type deviceView struct {
	store.Device
	wg.Stats
	Online bool `json:"online"`
}

func (s *Server) views(ds []store.Device) []deviceView {
	st := s.wg.Stats()
	out := make([]deviceView, 0, len(ds))
	for _, d := range ds {
		x := st[d.PublicKey]
		out = append(out, deviceView{Device: d, Stats: x, Online: time.Since(x.LastHandshake) < 3*time.Minute})
	}
	return out
}

func (s *Server) me(_ *http.Request, u *auth.User) (any, int, error) {
	return map[string]any{
		"username": u.Username, "email": u.Email, "admin": u.Admin, "maxDevices": s.cfg.MaxDevices,
		"server": map[string]any{
			"publicKey": s.wg.PublicKey(), "endpoint": s.cfg.WGEndpoint, "dns": s.cfg.WGDNS,
			"mtu": s.cfg.WGMTU, "allowedIPs": s.cfg.WGAllowedIPs,
		},
	}, http.StatusOK, nil
}

func (s *Server) listOwn(_ *http.Request, u *auth.User) (any, int, error) {
	return s.views(s.store.ByOwner(u.Sub)), http.StatusOK, nil
}

func (s *Server) listAll(_ *http.Request, u *auth.User) (any, int, error) {
	if !u.Admin {
		return nil, http.StatusForbidden, errors.New("solo administradores")
	}
	return s.views(s.store.All()), http.StatusOK, nil
}

func (s *Server) create(r *http.Request, u *auth.User) (any, int, error) {
	var in struct{ Name, PublicKey string }
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&in); err != nil {
		return nil, http.StatusBadRequest, errors.New("JSON no válido")
	}
	key, err := wg.ParsePublicKey(in.PublicKey)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if key == s.wg.PublicKey() {
		return nil, http.StatusBadRequest, store.ErrDuplicate
	}
	d, err := s.store.Add(store.Device{Owner: u.Sub, Username: u.Username, Name: strings.TrimSpace(in.Name), PublicKey: key},
		s.cfg.MaxDevices, func(d store.Device) error { return s.wg.AddPeer(wg.Peer{PublicKey: d.PublicKey, IP: d.IP}) })
	switch {
	case errors.Is(err, store.ErrDuplicate), errors.Is(err, store.ErrInvalidName):
		return nil, http.StatusBadRequest, err
	case errors.Is(err, store.ErrLimit), errors.Is(err, store.ErrPoolFull):
		return nil, http.StatusConflict, err
	case err != nil:
		return nil, http.StatusInternalServerError, err
	}
	slog.Info("alta dispositivo", "user", u.Username, "name", d.Name, "ip", d.IP)
	return d, http.StatusCreated, nil
}

func (s *Server) remove(r *http.Request, u *auth.User) (any, int, error) {
	d, err := s.store.Get(r.PathValue("id"))
	if err != nil || (d.Owner != u.Sub && !u.Admin) {
		return nil, http.StatusNotFound, store.ErrNotFound
	}
	if _, err := s.store.Delete(d.ID, func(d store.Device) error { return s.wg.RemovePeer(d.PublicKey) }); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	slog.Info("baja dispositivo", "by", u.Username, "owner", d.Username, "name", d.Name, "ip", d.IP)
	return map[string]bool{"ok": true}, http.StatusOK, nil
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// idpOrigin: form-action debe permitir la redirección del logout a Keycloak (otro origen).
func securityHeaders(h http.Handler, idpOrigin string) http.Handler {
	csp := "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self' " + idpOrigin
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func issuerOrigin(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
