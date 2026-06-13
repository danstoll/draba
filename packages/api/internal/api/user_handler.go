package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/I0-1O/draba/packages/api/internal/auth"
)

// handleUpdateProfile handles PATCH /users/me. Updates display_name, color,
// and icon for the authenticated user. Color/icon changes propagate to all
// team_members rows that have not been explicitly overridden.
func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())

	var body struct {
		DisplayName *string `json:"displayName"`
		Color       *string `json:"color"`
		Icon        *string `json:"icon"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	user, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update profile")
		return
	}

	// Apply changes only for fields that were provided.
	displayName := user.DisplayName
	if body.DisplayName != nil {
		displayName = strings.TrimSpace(*body.DisplayName)
		if displayName == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "displayName cannot be empty")
			return
		}
	}

	color := user.Color
	if body.Color != nil {
		color = body.Color
	}
	icon := user.Icon
	if body.Icon != nil {
		icon = body.Icon
	}

	if err := s.users.UpdateProfile(user.ID, displayName, color, icon); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update profile")
		return
	}

	user.DisplayName = displayName
	user.Color = color
	user.Icon = icon
	writeJSON(w, http.StatusOK, user)
}

// handleGetMyStats handles GET /users/me/stats. Returns aggregated activity and
// timeline counts across all of the authenticated user's team memberships.
func (s *Server) handleGetMyStats(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	stats, err := s.teams.GetUserStats(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get stats")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleChangePassword handles PUT /users/me/password. Requires the caller
// to supply the current password before setting a new one.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())

	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if body.CurrentPassword == "" || body.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "currentPassword and newPassword are required")
		return
	}
	if !isValidPassword(body.NewPassword) {
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "new password must be at least 8 characters")
		return
	}

	user, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to change password")
		return
	}

	// An OIDC (SSO) account has no local password to change; password
	// management lives at the identity provider.
	if user.PasswordHash == nil {
		writeError(w, http.StatusBadRequest, "OIDC_ACCOUNT", "this account signs in via SSO and has no password to change")
		return
	}

	// Verify the current password before allowing the change.
	if err := auth.CheckPassword(*user.PasswordHash, body.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "WRONG_PASSWORD", "current password is incorrect")
		return
	}

	hash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to change password")
		return
	}

	if err := s.users.UpdatePassword(user.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to change password")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListAdminUsers handles GET /admin/users. Returns all users with team
// membership counts. Supports ?orphaned=true to filter to zero-membership users.
// Superadmin-only.
func (s *Server) handleListAdminUsers(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())

	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list users")
		return
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}

	orphanedOnly := r.URL.Query().Get("orphaned") == "true"
	rows, err := s.users.ListAll(orphanedOnly)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list users")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": rows})
}

// handlePromoteUser sets is_superadmin=true on a user. Superadmin-only.
// Participants (no user account) cannot be promoted.
func (s *Server) handlePromoteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	claims := claimsFromContext(r.Context())

	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to promote user")
		return
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}

	target, err := s.users.GetByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to promote user")
		return
	}

	if err := s.users.SetSuperadmin(target.ID, true); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to promote user")
		return
	}

	target.IsSuperadmin = true
	writeJSON(w, http.StatusOK, target)
}

// handleArchiveUser inactivates a user account. Superadmin-only.
// Archived users cannot log in; their data is preserved.
func (s *Server) handleArchiveUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	claims := claimsFromContext(r.Context())

	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to archive user")
		return
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	if userID == claims.UserID {
		writeError(w, http.StatusBadRequest, "CANNOT_SELF_ARCHIVE", "cannot archive your own account")
		return
	}

	target, err := s.users.GetByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to archive user")
		return
	}

	now := time.Now()
	if err := s.users.SetArchived(target.ID, &now); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to archive user")
		return
	}

	target.ArchivedAt = &now
	writeJSON(w, http.StatusOK, target)
}

// handleUnarchiveUser reactivates an inactivated user account. Superadmin-only.
func (s *Server) handleUnarchiveUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	claims := claimsFromContext(r.Context())

	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reactivate user")
		return
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}

	target, err := s.users.GetByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reactivate user")
		return
	}

	if err := s.users.SetArchived(target.ID, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to reactivate user")
		return
	}

	target.ArchivedAt = nil
	writeJSON(w, http.StatusOK, target)
}

// handleRevokeUser atomically revokes all access for a user. Superadmin-only.
// Self-revoke is blocked to prevent a superadmin from locking themselves out.
func (s *Server) handleRevokeUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	claims := claimsFromContext(r.Context())

	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to revoke user")
		return
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	if userID == claims.UserID {
		writeError(w, http.StatusBadRequest, "CANNOT_SELF_REVOKE", "cannot revoke your own account")
		return
	}

	target, err := s.users.GetByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to revoke user")
		return
	}

	result, err := s.users.RevokeUser(target.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to revoke user")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleDeleteUser hard-deletes a user. Superadmin-only. Only permitted when
// the user has no active activity assignments and belongs to a single team.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	claims := claimsFromContext(r.Context())

	caller, err := s.users.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete user")
		return
	}
	if !caller.IsSuperadmin {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	if userID == claims.UserID {
		writeError(w, http.StatusBadRequest, "CANNOT_SELF_DELETE", "cannot delete your own account")
		return
	}

	if _, err := s.users.GetByID(userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete user")
		return
	}

	teamCount, err := s.teams.CountTeamsForUser(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete user")
		return
	}
	if teamCount > 1 {
		writeError(w, http.StatusConflict, "MULTI_TEAM", "user belongs to multiple teams; remove them from each team first")
		return
	}

	if err := s.users.Delete(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
