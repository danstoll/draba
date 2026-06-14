package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/I0-1O/draba/packages/api/internal/auth"
	"github.com/I0-1O/draba/packages/api/internal/models"
)

// OIDC transient cookie names. These carry the state, nonce, and PKCE verifier
// across the redirect to the IdP and back. They are httpOnly (never read by JS),
// short-lived (auth.FlowCookieTTL), and SameSite=Lax so they survive the
// top-level redirect back from the provider while still resisting CSRF.
const (
	oidcStateCookie = "draba_oidc_state"
	oidcNonceCookie = "draba_oidc_nonce"
	oidcPKCECookie  = "draba_oidc_pkce"
)

// oidcEnabled reports whether SSO is configured. A nil service means the
// operator did not set DRABA_OIDC_ISSUER, so every OIDC route is a 404 and no
// SSO machinery runs.
func (s *Server) oidcEnabled() bool { return s.oidc != nil }

// handleOIDCLogin handles GET /auth/oidc/login. It begins the authorization
// code flow and redirects the user agent to the identity provider, stashing
// the state/nonce/PKCE verifier in short-lived httpOnly cookies for the
// callback to verify.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		writeError(w, http.StatusNotFound, "OIDC_DISABLED", "SSO is not enabled on this instance")
		return
	}

	flow, err := s.oidc.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to start SSO login")
		return
	}

	secure := isSecureRequest(r)
	s.setFlowCookie(w, oidcStateCookie, flow.State, secure)
	s.setFlowCookie(w, oidcNonceCookie, flow.Nonce, secure)
	s.setFlowCookie(w, oidcPKCECookie, flow.PKCEVerifier, secure)

	http.Redirect(w, r, flow.AuthURL, http.StatusFound)
}

// handleOIDCCallback handles GET /auth/oidc/callback. It validates the state
// against the cookie, exchanges the code for tokens, verifies the ID token,
// finds-or-provisions the local user, and redirects back to the SPA with
// freshly issued draba access and refresh tokens in the URL fragment.
//
// On any failure it redirects to /login?sso_error=... rather than rendering an
// API error, because the user agent is a browser following a redirect, not an
// API client expecting JSON.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.oidcEnabled() {
		writeError(w, http.StatusNotFound, "OIDC_DISABLED", "SSO is not enabled on this instance")
		return
	}

	// Clear the transient cookies regardless of outcome.
	defer func() {
		secure := isSecureRequest(r)
		s.clearFlowCookie(w, oidcStateCookie, secure)
		s.clearFlowCookie(w, oidcNonceCookie, secure)
		s.clearFlowCookie(w, oidcPKCECookie, secure)
	}()

	// If the IdP reported an error, surface a fixed reason — never the raw
	// IdP-supplied value, which is attacker-influenceable.
	if r.URL.Query().Get("error") != "" {
		s.redirectSSOError(w, r, "idp_error")
		return
	}

	// CSRF defence: the state echoed by the IdP must equal the one we set.
	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil || stateCookie.Value == "" || r.URL.Query().Get("state") != stateCookie.Value {
		s.redirectSSOError(w, r, "state_mismatch")
		return
	}

	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil || nonceCookie.Value == "" {
		s.redirectSSOError(w, r, "missing_nonce")
		return
	}
	pkceCookie, err := r.Cookie(oidcPKCECookie)
	if err != nil || pkceCookie.Value == "" {
		s.redirectSSOError(w, r, "missing_pkce")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.redirectSSOError(w, r, "missing_code")
		return
	}

	claims, err := s.oidc.Exchange(r.Context(), code, pkceCookie.Value, nonceCookie.Value)
	if err != nil {
		s.redirectSSOError(w, r, "exchange_failed")
		return
	}

	user, err := s.findOrProvisionOIDCUser(claims)
	if err != nil {
		switch {
		case errors.Is(err, errOIDCProvisioningClosed):
			s.redirectSSOError(w, r, "provisioning_disabled")
		case errors.Is(err, errOIDCUserLimit):
			s.redirectSSOError(w, r, "user_limit")
		case errors.Is(err, errOIDCNoEmail):
			s.redirectSSOError(w, r, "no_email")
		default:
			s.redirectSSOError(w, r, "login_failed")
		}
		return
	}

	if user.ArchivedAt != nil {
		s.redirectSSOError(w, r, "account_inactive")
		return
	}

	access, err := s.tokens.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		s.redirectSSOError(w, r, "login_failed")
		return
	}
	refresh, err := s.tokens.IssueRefreshToken(user.ID, user.Email)
	if err != nil {
		s.redirectSSOError(w, r, "login_failed")
		return
	}

	// Hand the tokens to the SPA via the URL fragment (never the query string,
	// so they are not sent to the server or logged in access logs). The SPA's
	// /auth/callback route reads them from location.hash and stores them.
	base := strings.TrimRight(getBaseURL(), "/")
	target := base + "/auth/callback#access_token=" + access + "&refresh_token=" + refresh
	http.Redirect(w, r, target, http.StatusFound)
}

// Sentinel errors distinguishing why OIDC provisioning was refused, so the
// callback can map each to a distinct login-page message.
var (
	errOIDCProvisioningClosed = errors.New("oidc auto-provisioning disabled")
	errOIDCUserLimit          = errors.New("user limit reached")
	errOIDCNoEmail            = errors.New("oidc id_token has no email claim")
)

// findOrProvisionOIDCUser returns the local user for the given external
// identity, creating one on first login when auto-provisioning is enabled.
// The (issuer, subject) pair is the stable key; email/name are refreshed from
// claims each login. New-user creation respects the same tier user limit the
// password registration path enforces.
func (s *Server) findOrProvisionOIDCUser(claims *auth.OIDCClaims) (*models.User, error) {
	issuer := s.oidc.Issuer()

	existing, err := s.users.GetByOIDCSubject(issuer, claims.Subject)
	if err == nil {
		// Returning user — refresh profile from latest claims (best-effort).
		// An empty email here means the IdP stopped releasing it; keep the
		// stored one rather than overwriting a valid value with "".
		email := normalizeEmail(claims.Email)
		name := displayNameFromClaims(claims)
		if email != "" && (email != existing.Email || name != existing.DisplayName) {
			if uerr := s.users.UpdateOIDCProfile(existing.ID, email, name); uerr != nil {
				// Non-fatal: log and continue so a transient profile-refresh
				// failure never blocks an otherwise-valid login.
				slog.Warn("oidc: profile refresh failed", "user_id", existing.ID, "err", uerr)
				return existing, nil
			}
			existing.Email = email
			existing.DisplayName = name
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// First login for this identity — provision if allowed.
	if !s.oidcAutoCreate() {
		return nil, errOIDCProvisioningClosed
	}

	// A new account needs an email: users.email is NOT NULL UNIQUE and the
	// issued JWT carries it. Provisioning with "" would let the first user in
	// but collide every subsequent emailless user on the unique constraint.
	// Require the IdP to release an email scope for first-login provisioning.
	email := normalizeEmail(claims.Email)
	if email == "" {
		return nil, errOIDCNoEmail
	}

	count, err := s.users.Count()
	if err != nil {
		return nil, err
	}
	if err := s.tier.CheckUserLimit(count); err != nil {
		return nil, errOIDCUserLimit
	}

	now := time.Now()
	issuerCopy, subjectCopy := issuer, claims.Subject
	user := &models.User{
		ID:           newID(),
		Email:        email,
		DisplayName:  displayNameFromClaims(claims),
		IsSuperadmin: count == 0, // first user on a fresh install is the admin
		AuthProvider: "oidc",
		OIDCIssuer:   &issuerCopy,
		OIDCSubject:  &subjectCopy,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.CreateOIDC(user); err != nil {
		// A concurrent first login for the same subject, or an email already
		// taken by a local account, surfaces here.
		if isUniqueConstraintError(err) {
			// Re-fetch: the row may now exist (race) — prefer returning it.
			if u, gerr := s.users.GetByOIDCSubject(issuer, claims.Subject); gerr == nil {
				return u, nil
			}
			return nil, errors.New("oidc: email or identity already in use")
		}
		return nil, err
	}
	return user, nil
}

// ssoErrorReasons is the closed set of reason codes redirectSSOError may emit.
// Every reason the callback produces is a fixed internal string (never an
// IdP-supplied value), so the login page can map each to a friendly message
// and no externally-influenced data reaches the redirect URL.
var ssoErrorReasons = map[string]bool{
	"idp_error":             true,
	"state_mismatch":        true,
	"missing_nonce":         true,
	"missing_pkce":          true,
	"missing_code":          true,
	"exchange_failed":       true,
	"provisioning_disabled": true,
	"user_limit":            true,
	"no_email":              true,
	"account_inactive":      true,
	"login_failed":          true,
}

// redirectSSOError sends the browser back to the SPA login page with a stable
// machine-readable reason code it can map to a friendly message. The reason is
// validated against a fixed allow-list and the URL is built with net/url, so
// no caller mistake or IdP-supplied value can inject into the query string.
func (s *Server) redirectSSOError(w http.ResponseWriter, r *http.Request, reason string) {
	if !ssoErrorReasons[reason] {
		reason = "login_failed"
	}
	base := strings.TrimRight(getBaseURL(), "/")
	u, err := url.Parse(base + "/login")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	u.RawQuery = url.Values{"sso_error": {reason}}.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// setFlowCookie writes a short-lived httpOnly cookie for the OIDC flow.
func (s *Server) setFlowCookie(w http.ResponseWriter, name, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/auth/oidc",
		MaxAge:   int(auth.FlowCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearFlowCookie expires an OIDC flow cookie.
func (s *Server) clearFlowCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/auth/oidc",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// isSecureRequest reports whether the request arrived over HTTPS, honouring a
// terminating proxy's X-Forwarded-Proto header. Controls the cookie Secure
// flag so transient OIDC cookies are not marked Secure on a plain-HTTP dev
// instance (where the browser would then refuse to send them back).
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// normalizeEmail lowercases and trims an email claim. May be empty if the IdP
// did not release an email scope.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// displayNameFromClaims picks the best available display name: the name claim,
// else the local-part of the email, else the subject.
func displayNameFromClaims(c *auth.OIDCClaims) string {
	if n := strings.TrimSpace(c.Name); n != "" {
		return n
	}
	if c.Email != "" {
		if at := strings.IndexByte(c.Email, '@'); at > 0 {
			return c.Email[:at]
		}
	}
	return c.Subject
}
