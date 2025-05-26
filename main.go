package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/caarlos0/env/v9"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
)

type Instance struct {
	oidcProvider *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	ClientID     string `env:"OIDC_CLIENT_ID,required"`
	ClientSecret string `env:"OIDC_CLIENT_SECRET,required"`
	IssuerURL    string `env:"OIDC_ISSUER_URL,required"`
	ListenAddr   string `env:"LISTEN_ADDR" envDefault:":6432"`
}

func (i *Instance) getOauthConfig(callbackURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     i.ClientID,
		ClientSecret: i.ClientSecret,
		RedirectURL:  callbackURL + "/_oauth",
		Endpoint:     i.oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
}

func (i *Instance) loadConfig() error {
	if err := env.Parse(i); err != nil {
		return fmt.Errorf("parsing env vars: %w", err)
	}
	return nil
}

func main() {
	instance := &Instance{}
	if err := instance.loadConfig(); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, instance.IssuerURL)
	if err != nil {
		log.Fatal(err)
	}
	instance.oidcProvider = provider
	instance.verifier = provider.Verifier(&oidc.Config{ClientID: instance.ClientID})

	err = http.ListenAndServe(instance.ListenAddr, instance)
	if err != nil {
		log.Fatal(err)
	}
}

func (i *Instance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	forwardedUri, _ := url.Parse(r.Header.Get("X-Forwarded-Uri"))
	switch forwardedUri.Path {
	case "/_oauth":
		i.handleCallback(w, r)
	default:
		i.handleRequest(w, r)
	}
}

func (i *Instance) handleCallback(w http.ResponseWriter, r *http.Request) {
	forwardedUri, _ := url.Parse(r.Header.Get("X-Forwarded-Uri"))
	query := forwardedUri.Query()

	state := query.Get("state")
	if state == "" {
		http.Error(w, "state parameter required", http.StatusBadRequest)
		return
	}

	code := query.Get("code")
	if code == "" {
		http.Error(w, "code parameter required", http.StatusBadRequest)
		return
	}

	callbackURL := i.generateCallbackUrl(r)
	oauth2Config := i.getOauthConfig(callbackURL)

	token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in OAuth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := i.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "_toa_tfw_auth",
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		Expires:  idToken.Expiry,
	})

	originalUri, err := base64.RawURLEncoding.DecodeString(state)
	if err == nil {
		http.Redirect(w, r, i.generateCallbackUrl(r)+string(originalUri), http.StatusFound)
	} else {
		http.Redirect(w, r, i.generateCallbackUrl(r)+"/", http.StatusFound)
	}
}

func (i *Instance) handleRequest(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("_toa_tfw_auth")
	if err == nil {
		if _, err := i.verifier.Verify(r.Context(), cookie.Value); err == nil {
			w.Header().Set("Authorization", "Bearer "+cookie.Value)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	currentPath := r.Header.Get("X-Forwarded-Uri")
	encodedUri := base64.RawURLEncoding.EncodeToString([]byte(currentPath))
	callbackURL := i.generateCallbackUrl(r)
	oauthConfig := i.getOauthConfig(callbackURL)

	http.Redirect(w, r, oauthConfig.AuthCodeURL(encodedUri), http.StatusFound)
}

func (i *Instance) generateCallbackUrl(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return proto + "://" + host
}
