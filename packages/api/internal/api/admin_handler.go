package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/I0-1O/draba/packages/api/internal/mailer"
)

// requireSuperadmin is a shared guard for admin endpoints. Returns false
// and writes a 403 if the caller is not a superadmin.
func (s *Server) requireSuperadmin(w http.ResponseWriter, r *http.Request) bool {
	claims := claimsFromContext(r.Context())
	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to verify permissions")
		return false
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return false
	}
	return true
}

// handleGetSMTP handles GET /admin/smtp. Returns the current SMTP config
// with the password masked. Superadmin-only.
func (s *Server) handleGetSMTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuperadmin(w, r) {
		return
	}

	cfg, err := s.mailer.LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to load SMTP config")
		return
	}
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"smtp": nil})
		return
	}

	// Mask the password in the response.
	masked := *cfg
	if masked.Password != "" {
		masked.Password = "••••••••"
	}
	writeJSON(w, http.StatusOK, map[string]any{"smtp": masked})
}

// handlePutSMTP handles PUT /admin/smtp. Saves the SMTP configuration and
// validates it by sending a test email to the caller's address. Superadmin-only.
func (s *Server) handlePutSMTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuperadmin(w, r) {
		return
	}

	var cfg mailer.SMTPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if cfg.Host == "" || cfg.Port == 0 || cfg.FromEmail == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "host, port, and fromEmail are required")
		return
	}

	// Fetch caller email for the validation test.
	claims := claimsFromContext(r.Context())
	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to send test email")
		return
	}

	// Validate by sending a test email before persisting.
	if err := mailer.SendWithConfig(&cfg, caller.Email, "draba SMTP test", smtpTestBody()); err != nil {
		slog.Warn("smtp validation failed", "err", err)
		writeError(w, http.StatusBadRequest, "SMTP_SEND_FAILED", "SMTP validation failed; check server logs for details")
		return
	}

	if err := s.mailer.SaveConfig(&cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save SMTP config")
		return
	}

	masked := cfg
	if masked.Password != "" {
		masked.Password = "••••••••"
	}
	writeJSON(w, http.StatusOK, map[string]any{"smtp": masked})
}

// handleTestSMTP handles POST /admin/smtp/test. Sends a test email using the
// provided config without persisting it. Superadmin-only.
func (s *Server) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuperadmin(w, r) {
		return
	}

	var cfg mailer.SMTPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	claims := claimsFromContext(r.Context())
	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to fetch caller")
		return
	}

	if err := mailer.SendWithConfig(&cfg, caller.Email, "draba SMTP test", smtpTestBody()); err != nil {
		slog.Warn("smtp test failed", "err", err)
		writeError(w, http.StatusBadRequest, "SMTP_SEND_FAILED", "SMTP test failed; check server logs for details")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "sent", "to": caller.Email})
}

// handleDeleteSMTP handles DELETE /admin/smtp. Clears the SMTP config.
// Superadmin-only.
func (s *Server) handleDeleteSMTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuperadmin(w, r) {
		return
	}
	if err := s.mailer.DeleteConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to clear SMTP config")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetAdminSettings handles GET /admin/settings. Returns instance-level
// defaults. Superadmin-only.
func (s *Server) handleGetAdminSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuperadmin(w, r) {
		return
	}

	keys := []string{"registration_policy", "default_timezone", "default_date_format", "default_week_start", "instance_name", "accent_color"}
	settings := make(map[string]string, len(keys))
	for _, k := range keys {
		v, err := s.instanceSets.Get(k)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to load settings")
			return
		}
		settings[k] = v
	}

	// Apply defaults for missing keys.
	if settings["registration_policy"] == "" {
		settings["registration_policy"] = "invite_only"
	}
	if settings["default_timezone"] == "" {
		settings["default_timezone"] = "UTC"
	}
	if settings["default_date_format"] == "" {
		settings["default_date_format"] = "MMM D, YYYY"
	}
	if settings["default_week_start"] == "" {
		settings["default_week_start"] = "monday"
	}

	writeJSON(w, http.StatusOK, map[string]any{"settings": settings})
}

// handlePatchAdminSettings handles PATCH /admin/settings. Updates one or more
// instance-level settings. Superadmin-only.
func (s *Server) handlePatchAdminSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireSuperadmin(w, r) {
		return
	}

	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	// Validate known keys and values.
	allowed := map[string]bool{
		"registration_policy": true,
		"default_timezone":    true,
		"default_date_format": true,
		"default_week_start":  true,
		"instance_name":       true,
		"accent_color":        true,
	}
	for k := range body {
		if !allowed[k] {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown setting key: "+k)
			return
		}
	}
	if v, ok := body["registration_policy"]; ok && v != "invite_only" && v != "open" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "registration_policy must be invite_only or open")
		return
	}
	if v, ok := body["default_week_start"]; ok && v != "monday" && v != "sunday" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "default_week_start must be monday or sunday")
		return
	}

	for k, v := range body {
		if err := s.instanceSets.Set(k, v); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save settings")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"settings": body})
}

// handleGetPublicBranding handles GET /settings/branding. Returns the
// instance name and accent color without requiring authentication, so the
// login page and shared timeline views can display branding before sign-in.
//
// Only cosmetic settings are exposed here. Never add sensitive keys (SMTP
// credentials, JWT secrets, registration policy, etc.) to this handler.
func (s *Server) handleGetPublicBranding(w http.ResponseWriter, _ *http.Request) {
	name, _ := s.instanceSets.Get("instance_name")
	accent, _ := s.instanceSets.Get("accent_color")
	writeJSON(w, http.StatusOK, map[string]any{
		"instanceName": name,
		"accentColor":  accent,
		// ssoEnabled lets the login page decide whether to show the "Sign in
		// with SSO" button. It is not sensitive — the same fact is observable
		// by probing /auth/oidc/login.
		"ssoEnabled": s.oidcEnabled(),
	})
}

func smtpTestBody() string {
	return `<html><body>
<p>This is a test email from <strong>draba</strong>.</p>
<p>If you received this, your SMTP configuration is working correctly.</p>
</body></html>`
}
