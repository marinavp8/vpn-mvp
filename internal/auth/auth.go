// Package auth: login OIDC (Keycloak) con PKCE y sesión en cookie firmada con HMAC.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const sessionTTL = 8 * time.Hour

type User struct {
	Sub      string `json:"sub"`
	Username string `json:"usr"`
	Email    string `json:"eml,omitempty"`
	Admin    bool   `json:"adm,omitempty"`
	Exp      int64  `json:"exp"`
}

type Options struct {
	Issuer, ClientID, ClientSecret, PublicURL string
	AllowedGroups, AdminGroups                []string
	SessionKey                                []byte
	Secure                                    bool
}

type Auth struct {
	opt        Options
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
	sessCookie string
	flowCookie string
}

func New(ctx context.Context, o Options) (*Auth, error) {
	p, err := oidc.NewProvider(ctx, o.Issuer)
	if err != nil {
		return nil, err
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&meta)
	a := &Auth{
		opt: o,
		oauth: oauth2.Config{
			ClientID: o.ClientID, ClientSecret: o.ClientSecret, Endpoint: p.Endpoint(),
			RedirectURL: o.PublicURL + "/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:   p.Verifier(&oidc.Config{ClientID: o.ClientID}),
		endSession: meta.EndSession,
		sessCookie: "vpn_session", flowCookie: "vpn_flow",
	}
	if o.Secure { // __Host-: solo HTTPS, sin Domain, Path=/
		a.sessCookie, a.flowCookie = "__Host-vpn_session", "__Host-vpn_flow"
	}
	return a, nil
}

type flow struct {
	State, Nonce, Verifier string
	Exp                    int64
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	f := flow{State: rnd(), Nonce: rnd(), Verifier: oauth2.GenerateVerifier(), Exp: time.Now().Add(10 * time.Minute).Unix()}
	a.setCookie(w, a.flowCookie, a.sign("flow", f), 600)
	http.Redirect(w, r, a.oauth.AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)), http.StatusFound)
}

func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	var f flow
	c, err := r.Cookie(a.flowCookie)
	if err != nil || !a.verify("flow", c.Value, &f) || f.Exp < time.Now().Unix() ||
		!hmac.Equal([]byte(f.State), []byte(r.URL.Query().Get("state"))) {
		http.Error(w, "sesión de login caducada o no válida, vuelve a entrar", http.StatusBadRequest)
		return
	}
	a.setCookie(w, a.flowCookie, "", -1)
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "login cancelado: "+e, http.StatusUnauthorized)
		return
	}
	tok, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		slog.Warn("oidc exchange", "err", err)
		http.Error(w, "no se pudo completar el login", http.StatusBadGateway)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := a.verifier.Verify(r.Context(), raw)
	if err != nil || idt.Nonce != f.Nonce {
		http.Error(w, "id_token no válido", http.StatusUnauthorized)
		return
	}
	var cl struct {
		Sub      string   `json:"sub"`
		Username string   `json:"preferred_username"`
		Email    string   `json:"email"`
		Groups   []string `json:"groups"`
		Realm    struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := idt.Claims(&cl); err != nil || cl.Sub == "" {
		http.Error(w, "claims no válidos", http.StatusUnauthorized)
		return
	}
	// Grupos de Keycloak llegan como "/alumnos" (ruta completa); también aceptamos roles de realm.
	member := map[string]bool{}
	for _, g := range cl.Groups {
		member[strings.TrimPrefix(g, "/")] = true
	}
	for _, rl := range cl.Realm.Roles {
		member[rl] = true
	}
	in := func(gs []string) bool { return slices.ContainsFunc(gs, func(g string) bool { return member[g] }) }
	admin := in(a.opt.AdminGroups)
	if len(a.opt.AllowedGroups) > 0 && !in(a.opt.AllowedGroups) && !admin {
		slog.Info("login denegado (sin grupo)", "user", cl.Username)
		http.Error(w, "tu usuario no tiene acceso a la VPN", http.StatusForbidden)
		return
	}
	u := User{Sub: cl.Sub, Username: cl.Username, Email: cl.Email, Admin: admin, Exp: time.Now().Add(sessionTTL).Unix()}
	a.setCookie(w, a.sessCookie, a.sign("session", u), int(sessionTTL.Seconds()))
	slog.Info("login", "user", u.Username, "admin", u.Admin)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, a.sessCookie, "", -1)
	dest := "/"
	if a.endSession != "" {
		q := url.Values{"client_id": {a.opt.ClientID}, "post_logout_redirect_uri": {a.opt.PublicURL + "/"}}
		dest = a.endSession + "?" + q.Encode()
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// User devuelve el usuario de la sesión, o nil.
func (a *Auth) User(r *http.Request) *User {
	c, err := r.Cookie(a.sessCookie)
	if err != nil {
		return nil
	}
	var u User
	if !a.verify("session", c.Value, &u) || u.Sub == "" || u.Exp < time.Now().Unix() {
		return nil
	}
	return &u
}

// SameOrigin protege las peticiones que cambian estado (CSRF): Origin debe ser PUBLIC_URL.
func (a *Auth) SameOrigin(r *http.Request) error {
	if o := r.Header.Get("Origin"); o != a.opt.PublicURL {
		return errors.New("origen no permitido")
	}
	return nil
}

func (a *Auth) setCookie(w http.ResponseWriter, name, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: a.opt.Secure, SameSite: http.SameSiteLaxMode})
}

func (a *Auth) sign(purpose string, v any) string {
	b, _ := json.Marshal(v)
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + base64.RawURLEncoding.EncodeToString(a.mac(purpose, p))
}

func (a *Auth) verify(purpose, s string, v any) bool {
	p, sig, ok := strings.Cut(s, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, a.mac(purpose, p)) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	return err == nil && json.Unmarshal(b, v) == nil
}

func (a *Auth) mac(purpose, p string) []byte {
	m := hmac.New(sha256.New, a.opt.SessionKey)
	m.Write([]byte(purpose + "\x00" + p))
	return m.Sum(nil)
}

func rnd() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
