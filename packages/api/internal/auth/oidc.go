// OIDC / SSO support. This file is the ONLY place draba talks to an external
// identity provider. It is entirely inert unless OIDC is configured: when
// NewOIDCService is given an empty issuer it returns (nil, nil) and every
// caller treats a nil *OIDCService as "SSO disabled", so no discovery request,
// no network traffic, and no behaviour change occurs on a default install.
//
// Security posture:
//   - The provider's ID token signature is verified against the IdP's JWKS by
//     go-oidc's verifier (RS256/ES256/etc.) — draba never trusts an unsigned
//     or self-asserted token.
//   - The OAuth2 "state" parameter is bound to the caller's cookie to stop
//     CSRF on the callback; "nonce" is bound into the ID token to stop replay.
//   - PKCE (S256) is always used, so an intercepted authorization code cannot
//     be redeemed without the original verifier.
//   - The client secret is read once from the environment and never leaves the
//     server; it is not exposed by any API.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig is the deploy-time configuration for SSO. All fields are required
// when SSO is enabled; an empty Issuer means SSO is disabled.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes requested in addition to "openid". Defaults to {"profile","email"}
	// when empty.
	Scopes []string
}

// OIDCService performs the OpenID Connect authorization-code flow against a
// single configured provider. It is safe for concurrent use.
type OIDCService struct {
	issuer   string
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
}

// OIDCClaims is the subset of ID-token claims draba consumes. Subject is the
// stable per-user identifier; Email/Name seed the local account on first login.
type OIDCClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Nonce         string `json:"nonce"`
}

// AuthCodeFlow carries the per-request secrets the caller must store (in
// short-lived httpOnly cookies) and replay on the callback. The State and
// Nonce defend against CSRF and replay; the PKCEVerifier is exchanged for
// tokens at the callback.
type AuthCodeFlow struct {
	// AuthURL is where the user agent is redirected to authenticate.
	AuthURL string
	// State must be echoed back by the IdP and matched on callback.
	State string
	// Nonce must equal the nonce claim in the returned ID token.
	Nonce string
	// PKCEVerifier is the code_verifier matching the code_challenge sent in
	// AuthURL; required at the token exchange.
	PKCEVerifier string
}

// NewOIDCService constructs an OIDCService by performing OIDC discovery against
// cfg.Issuer. It returns (nil, nil) when cfg.Issuer is empty so that a default
// (SSO-disabled) install incurs no network access and no dependency activation.
// A non-nil error means SSO was requested but the provider is unreachable or
// misconfigured — the caller should treat that as a fatal startup error so a
// broken SSO setup fails loudly instead of silently serving a dead login button.
func NewOIDCService(ctx context.Context, cfg OIDCConfig) (*OIDCService, error) {
	if cfg.Issuer == "" {
		return nil, nil // SSO disabled — inert.
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: issuer set but client_id, client_secret, or redirect_url is missing")
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery against %q failed: %w", cfg.Issuer, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"profile", "email"}
	}

	return &OIDCService{
		issuer:   cfg.Issuer,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       append([]string{oidc.ScopeOpenID}, scopes...),
		},
	}, nil
}

// Begin produces the authorization URL plus the state/nonce/PKCE-verifier the
// caller must persist for the matching callback. Every value is generated with
// a CSPRNG.
func (s *OIDCService) Begin() (*AuthCodeFlow, error) {
	state, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	url := s.oauth.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return &AuthCodeFlow{
		AuthURL:      url,
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
	}, nil
}

// Exchange completes the flow: it redeems code for tokens (sending the PKCE
// verifier), verifies the ID token's signature against the provider JWKS,
// checks the nonce, and returns the validated claims. expectedNonce must be
// the value originally produced by Begin and stored by the caller.
func (s *OIDCService) Exchange(ctx context.Context, code, pkceVerifier, expectedNonce string) (*OIDCClaims, error) {
	token, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange failed: %w", err)
	}

	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("oidc: provider response contained no id_token")
	}

	idToken, err := s.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}

	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: parsing id_token claims: %w", err)
	}

	// Replay defence: the nonce minted in Begin must match the one the IdP
	// embedded in the signed ID token. Constant-time compare avoids leaking
	// the nonce through timing.
	if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return nil, fmt.Errorf("oidc: id_token nonce mismatch")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("oidc: id_token has no subject claim")
	}
	return &claims, nil
}

// Issuer returns the configured provider issuer URL — used as the stable
// namespace half of a user's (issuer, subject) identity key.
func (s *OIDCService) Issuer() string {
	return s.issuer
}

// FlowCookieTTL bounds how long a started OIDC flow may sit before the user
// completes it; the state/nonce/PKCE cookies expire after this window.
const FlowCookieTTL = 10 * time.Minute

// randomURLToken returns 32 bytes of CSPRNG entropy, base64url-encoded.
func randomURLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: reading random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
