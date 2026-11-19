// wgportal: portal de autoservicio WireGuard para alumnos (login con Keycloak).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"codecrypto.academy/vpn/internal/auth"
	"codecrypto.academy/vpn/internal/config"
	"codecrypto.academy/vpn/internal/server"
	"codecrypto.academy/vpn/internal/store"
	"codecrypto.academy/vpn/internal/wg"
	"codecrypto.academy/vpn/web"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("arranque", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "peers.json"), cfg.WGAddress)
	if err != nil {
		return err
	}
	var peers []wg.Peer
	for _, d := range st.All() {
		peers = append(peers, wg.Peer{PublicKey: d.PublicKey, IP: d.IP})
	}
	m, err := wg.Setup(cfg.WGInterface, cfg.WGAddress, cfg.WGPort, cfg.WGMTU, filepath.Join(cfg.DataDir, "server.key"), peers)
	if err != nil {
		return err
	}
	slog.Info("wireguard listo", "iface", cfg.WGInterface, "port", cfg.WGPort, "peers", len(peers), "publicKey", m.PublicKey())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Keycloak puede tardar en arrancar tras un reinicio de la VM: reintentar.
	var a *auth.Auth
	for i := 0; ; i++ {
		a, err = auth.New(ctx, auth.Options{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
			PublicURL: cfg.PublicURL, AllowedGroups: cfg.AllowedGroups, AdminGroups: cfg.AdminGroups,
			SessionKey: cfg.SessionKey, Secure: cfg.SecureCookies(),
		})
		if err == nil {
			break
		}
		if i == 30 || ctx.Err() != nil {
			return err
		}
		slog.Warn("OIDC no disponible, reintento en 5s", "err", err)
		time.Sleep(5 * time.Second)
	}

	srv := &http.Server{
		Addr: cfg.Listen, Handler: server.New(cfg, a, st, m, web.Static()).Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	slog.Info("portal escuchando", "addr", cfg.Listen, "url", cfg.PublicURL)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// La interfaz wg0 se queda: los túneles siguen funcionando mientras el contenedor viva.
	return nil
}
