package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/I0-1O/draba/packages/api/internal/auth"
	"github.com/I0-1O/draba/packages/api/internal/models"
)

// handleRegister handles POST /auth/register. The first user on a fresh
// install registers without an invite (bootstrap); every subsequent user
// must present a valid invite token. Tier user limits are enforced before
// hashing the password to avoid wasted bcrypt work.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	req.Email = openapi_types.Email(strings.ToLower(strings.TrimSpace(string(req.Email))))
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Email == "" || req.Password == "" || req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "email, password, and displayName are required")
		return
	}
	if !isValidPassword(req.Password) {
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "password must be at least 8 characters")
		return
	}

	// First user may register without an invite; all subsequent users require one.
	count, err := s.users.Count()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "registration failed")
		return
	}

	if err := s.tier.CheckUserLimit(count); err != nil {
		writeError(w, http.StatusPaymentRequired, "TIER_USER_LIMIT", "user limit reached for current tier")
		return
	}

	var invite *models.Invite
	var inviteLinkTeamID string // non-empty when a reusable invite link was used
	if count > 0 {
		if req.InviteToken == nil || *req.InviteToken == "" {
			writeError(w, http.StatusForbidden, "INVITE_REQUIRED", "an invite token is required to register")
			return
		}
		// Try as a one-time invite first.
		inv, err := s.invites.GetValid(*req.InviteToken)
		if err != nil {
			// Not a valid one-time invite — check if it's a reusable invite link token.
			team, linkErr := s.teams.GetByInviteLinkToken(*req.InviteToken)
			if linkErr != nil {
				writeError(w, http.StatusForbidden, "INVITE_INVALID", "invite token is invalid or expired")
				return
			}
			inviteLinkTeamID = team.ID
		} else {
			if inv.Email != "" && !strings.EqualFold(inv.Email, string(req.Email)) {
				writeError(w, http.StatusForbidden, "INVITE_EMAIL_MISMATCH", "this invite was issued to a different email address")
				return
			}
			invite = inv
		}
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "registration failed")
		return
	}

	now := time.Now()
	user := &models.User{
		ID:           newID(),
		Email:        string(req.Email),
		PasswordHash: &hash,
		DisplayName:  req.DisplayName,
		AuthProvider: "local",
		IsSuperadmin: count == 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(user); err != nil {
		writeError(w, http.StatusConflict, "EMAIL_TAKEN", "an account with that email already exists")
		return
	}

	if invite != nil {
		if err := s.invites.MarkAccepted(invite.ID); err != nil {
			// User and tokens are still returned — email uniqueness prevents a
			// second registration. Log so the open invite is visible in monitoring.
			slog.Error("failed to mark invite accepted", "invite_id", invite.ID, "err", err)
		}
		userID := user.ID
		member := &models.TeamMember{
			ID:       newID(),
			TeamID:   invite.TeamID,
			UserID:   &userID,
			Role:     invite.Role,
			JoinedAt: now,
		}
		if err := s.teams.AddMember(member); err != nil {
			slog.Error("failed to add user to team after invite", "team_id", invite.TeamID, "user_id", user.ID, "err", err)
		}
	} else if inviteLinkTeamID != "" {
		userID := user.ID
		member := &models.TeamMember{
			ID:       newID(),
			TeamID:   inviteLinkTeamID,
			UserID:   &userID,
			Role:     "member",
			JoinedAt: now,
		}
		if err := s.teams.AddMember(member); err != nil {
			slog.Error("failed to add user to team via invite link", "team_id", inviteLinkTeamID, "user_id", user.ID, "err", err)
		}
	}

	access, err := s.tokens.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "registration failed")
		return
	}
	refresh, err := s.tokens.IssueRefreshToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "registration failed")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"user":         user,
		"accessToken":  access,
		"refreshToken": refresh,
	})
}

// handleLogin handles POST /auth/login. Returns the same generic
// INVALID_CREDENTIALS error for both unknown email and bad password so
// the endpoint cannot be used as an account-existence oracle.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	req.Email = openapi_types.Email(strings.ToLower(strings.TrimSpace(string(req.Email))))
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "email and password are required")
		return
	}

	user, err := s.users.GetByEmail(string(req.Email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "login failed")
		return
	}

	if user.ArchivedAt != nil {
		writeError(w, http.StatusForbidden, "ACCOUNT_INACTIVE", "this account has been deactivated")
		return
	}

	// An OIDC (SSO) account has no password and must never authenticate via
	// this endpoint — it can only log in through the OIDC flow. Same generic
	// error as a bad password so the endpoint cannot reveal that an address
	// belongs to an SSO account.
	if user.PasswordHash == nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
		return
	}

	if err := auth.CheckPassword(*user.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
		return
	}

	access, err := s.tokens.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "login failed")
		return
	}
	refresh, err := s.tokens.IssueRefreshToken(user.ID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "login failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"accessToken":  access,
		"refreshToken": refresh,
	})
}

// handleRefresh handles POST /auth/refresh. It exchanges a valid refresh
// token for a new access token; the refresh token itself is not rotated.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenJSONBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	claims, err := s.tokens.Validate(req.RefreshToken, "refresh")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "refresh token is invalid or expired")
		return
	}

	access, err := s.tokens.IssueAccessToken(claims.UserID, claims.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "token refresh failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": access,
	})
}

// handleMe handles GET /auth/me and returns the authenticated user's
// profile. Must be mounted behind authMiddleware.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	user, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to fetch user")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// handleForgotPassword handles POST /auth/forgot-password. Accepts an email
// address, generates a 1-hour reset token, stores the hash, and sends a
// reset link via SMTP. Always returns 200 to prevent email enumeration.
// When SMTP is not configured the email is silently skipped.
func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if body.Email == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "email is required")
		return
	}

	// Always return 200 regardless of whether the email exists.
	w.Header().Set("Content-Type", "application/json")
	defer func() { _, _ = w.Write([]byte(`{"status":"ok"}`)) }()

	user, err := s.users.GetByEmail(body.Email)
	if err != nil {
		// No user — return 200 without error (prevent enumeration).
		return
	}
	if user.ArchivedAt != nil {
		return
	}

	rawToken := newToken()
	expiresAt := time.Now().Add(time.Hour)
	if _, err := s.passwordTokens.Create(newID(), user.ID, rawToken, expiresAt); err != nil {
		slog.Error("forgot-password: failed to create token", "user_id", user.ID, "err", err)
		return
	}

	// DRABA_BASE_URL is used to build the reset link. Fall back to a placeholder
	// when not set so the email still contains useful info.
	baseURL := strings.TrimRight(getBaseURL(), "/")
	resetLink := baseURL + "/reset-password?token=" + url.QueryEscape(rawToken)

	subject := "Reset your draba password"
	body2 := "<html><body>" +
		"<p>You requested a password reset for your draba account.</p>" +
		"<p><a href=\"" + resetLink + "\">Click here to reset your password</a></p>" +
		"<p>This link expires in 1 hour. If you did not request this, you can ignore this email.</p>" +
		"</body></html>"

	if err := s.mailer.Send(user.Email, subject, body2); err != nil {
		slog.Error("forgot-password: failed to send email", "user_id", user.ID, "err", err)
	}
}

// handleResetPassword handles POST /auth/reset-password. Accepts a token and
// new password; validates the token, hashes the new password, and marks the
// token used. Returns 400 TOKEN_INVALID when the token is not found, expired,
// or already used.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if body.Token == "" || body.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "token and newPassword are required")
		return
	}
	if !isValidPassword(body.NewPassword) {
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "password must be at least 8 characters")
		return
	}

	resetToken, err := s.passwordTokens.GetValid(body.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, "TOKEN_INVALID", "reset token is invalid or expired")
		return
	}

	hash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reset password")
		return
	}

	if err := s.users.UpdatePassword(resetToken.UserID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reset password")
		return
	}

	if err := s.passwordTokens.MarkUsed(resetToken.ID); err != nil {
		slog.Warn("reset-password: failed to mark token used", "token_id", resetToken.ID, "err", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// getBaseURL returns DRABA_BASE_URL or a localhost fallback.
func getBaseURL() string {
	if v := os.Getenv("DRABA_BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// isValidPassword applies the minimum policy: at least 8 characters and
// no whitespace. Strength rules beyond length are intentionally lenient —
// length is what matters most against offline cracking.
func isValidPassword(p string) bool {
	if len(p) < 8 {
		return false
	}
	for _, r := range p {
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
