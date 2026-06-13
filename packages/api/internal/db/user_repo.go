package db

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/I0-1O/draba/packages/api/internal/models"
)

// UserRepo is the persistence layer for User records.
type UserRepo struct {
	db *sqlx.DB
}

// NewUserRepo returns a UserRepo backed by db.
func NewUserRepo(db *sqlx.DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create inserts u. Returns an error if the email already exists
// (the users.email UNIQUE constraint surfaces as a wrapped driver error).
func (r *UserRepo) Create(u *models.User) error {
	_, err := r.db.NamedExec(`
		INSERT INTO users (id, email, password_hash, display_name, avatar_url, is_superadmin, created_at, updated_at)
		VALUES (:id, :email, :password_hash, :display_name, :avatar_url, :is_superadmin, :created_at, :updated_at)
	`, u)
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

// GetByEmail looks up a user by exact email match. Callers are expected to
// normalize (lowercase, trim) before calling. Returns sql.ErrNoRows wrapped
// when no row matches.
func (r *UserRepo) GetByEmail(email string) (*models.User, error) {
	var u models.User
	err := r.db.Get(&u, `SELECT * FROM users WHERE email = ?`, email)
	if err != nil {
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return &u, nil
}

// GetByOIDCSubject looks up a user by their external identity — the
// (issuer, subject) pair from the IdP. This is the stable key for an SSO
// account: email or display name may change at the IdP, but the subject does
// not. Returns sql.ErrNoRows (wrapped) when no row matches.
func (r *UserRepo) GetByOIDCSubject(issuer, subject string) (*models.User, error) {
	var u models.User
	err := r.db.Get(&u,
		`SELECT * FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`,
		issuer, subject,
	)
	if err != nil {
		return nil, fmt.Errorf("getting user by oidc subject: %w", err)
	}
	return &u, nil
}

// CreateOIDC inserts a new SSO user. The account has no password; identity is
// the (issuer, subject) pair. The row-level CHECK added in migration 024
// rejects an oidc account missing either field, so a malformed insert fails at
// the database rather than producing a half-formed account.
func (r *UserRepo) CreateOIDC(u *models.User) error {
	u.AuthProvider = "oidc"
	u.PasswordHash = nil
	_, err := r.db.NamedExec(`
		INSERT INTO users (id, email, display_name, avatar_url, is_superadmin,
		                   auth_provider, oidc_issuer, oidc_subject, created_at, updated_at)
		VALUES (:id, :email, :display_name, :avatar_url, :is_superadmin,
		        :auth_provider, :oidc_issuer, :oidc_subject, :created_at, :updated_at)
	`, u)
	if err != nil {
		return fmt.Errorf("creating oidc user: %w", err)
	}
	return nil
}

// UpdateOIDCProfile refreshes the email and display name of an existing SSO
// user from their latest IdP claims, so a name/email change upstream is
// reflected on next login. The (issuer, subject) identity is never changed.
func (r *UserRepo) UpdateOIDCProfile(id, email, displayName string) error {
	_, err := r.db.Exec(
		`UPDATE users SET email = ?, display_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		email, displayName, id,
	)
	if err != nil {
		return fmt.Errorf("updating oidc profile: %w", err)
	}
	return nil
}

// GetByID looks up a user by primary key.
func (r *UserRepo) GetByID(id string) (*models.User, error) {
	var u models.User
	err := r.db.Get(&u, `SELECT * FROM users WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("getting user by id: %w", err)
	}
	return &u, nil
}

// UpdatePasswordByEmail replaces the password hash for the user with the
// given email. Returns sql.ErrNoRows (wrapped) when no matching user exists.
func (r *UserRepo) UpdatePasswordByEmail(email, passwordHash string) error {
	res, err := r.db.Exec(
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
		passwordHash, email,
	)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("updating password: no user with email %q", email)
	}
	return nil
}

// Count returns the total number of users. Used by the registration flow
// to detect first-user bootstrap and to enforce tier user limits.
func (r *UserRepo) Count() (int, error) {
	var count int
	err := r.db.Get(&count, `SELECT COUNT(*) FROM users`)
	if err != nil {
		return 0, fmt.Errorf("counting users: %w", err)
	}
	return count, nil
}

// SearchByNameOrEmail returns up to 20 users whose display_name or email
// contains the query (case-insensitive). Archived users are excluded.
func (r *UserRepo) SearchByNameOrEmail(q string) ([]*models.User, error) {
	var users []*models.User
	like := "%" + q + "%"
	err := r.db.Select(&users, `
		SELECT * FROM users
		WHERE archived_at IS NULL
		  AND (display_name LIKE ? OR email LIKE ?)
		ORDER BY display_name ASC
		LIMIT 20
	`, like, like)
	if err != nil {
		return nil, fmt.Errorf("searching users: %w", err)
	}
	return users, nil
}

// SetSuperadmin sets or clears the is_superadmin flag on a user.
func (r *UserRepo) SetSuperadmin(id string, isSuperadmin bool) error {
	_, err := r.db.Exec(
		`UPDATE users SET is_superadmin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		isSuperadmin, id,
	)
	if err != nil {
		return fmt.Errorf("setting superadmin: %w", err)
	}
	return nil
}

// SetArchived sets or clears archived_at on a user. Archived users cannot log in.
func (r *UserRepo) SetArchived(id string, at *time.Time) error {
	_, err := r.db.Exec(
		`UPDATE users SET archived_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		at, id,
	)
	if err != nil {
		return fmt.Errorf("setting user archived: %w", err)
	}
	return nil
}

// Delete hard-deletes a user row. The caller must verify the user is deletable
// (no active activities, single team membership) before calling this.
func (r *UserRepo) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	return nil
}

// UpdateProfile sets display_name, color, and icon on a user. When color or
// icon changes, the new value is propagated to all team_members rows for the
// user where the member's value currently matches the user's old value or is NULL
// (i.e. has not been explicitly overridden by a team admin).
func (r *UserRepo) UpdateProfile(id, displayName string, color, icon *string) error {
	// Fetch old values for propagation comparison.
	var old models.User
	if err := r.db.Get(&old, `SELECT * FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("fetching user for profile update: %w", err)
	}

	tx, err := r.db.Beginx()
	if err != nil {
		return fmt.Errorf("beginning profile update transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(
		`UPDATE users SET display_name = ?, color = ?, icon = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		displayName, color, icon, id,
	)
	if err != nil {
		return fmt.Errorf("updating user profile: %w", err)
	}

	// Propagate color if changed: update team_members rows where color matches
	// the old value or is NULL (not explicitly overridden).
	if !ptrEqual(old.Color, color) {
		_, err = tx.Exec(
			`UPDATE team_members SET color = ? WHERE user_id = ? AND (color IS NULL OR color = ?)`,
			color, id, old.Color,
		)
		if err != nil {
			return fmt.Errorf("propagating color to team_members: %w", err)
		}
	}

	if !ptrEqual(old.Icon, icon) {
		_, err = tx.Exec(
			`UPDATE team_members SET icon = ? WHERE user_id = ? AND (icon IS NULL OR icon = ?)`,
			icon, id, old.Icon,
		)
		if err != nil {
			return fmt.Errorf("propagating icon to team_members: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing profile update: %w", err)
	}
	return nil
}

// UpdatePassword sets the password_hash on a user.
func (r *UserRepo) UpdatePassword(id, passwordHash string) error {
	_, err := r.db.Exec(
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	return nil
}

// ListAll returns all users with their active team membership count.
// When orphanedOnly is true, only users with zero active memberships are returned.
func (r *UserRepo) ListAll(orphanedOnly bool) ([]*models.AdminUserRow, error) {
	q := `
		SELECT u.*,
		       (SELECT COUNT(*) FROM team_members tm WHERE tm.user_id = u.id AND tm.archived_at IS NULL) AS team_count
		FROM users u
		ORDER BY u.display_name ASC
	`
	if orphanedOnly {
		q = `
			SELECT u.*,
			       0 AS team_count
			FROM users u
			WHERE (SELECT COUNT(*) FROM team_members tm WHERE tm.user_id = u.id AND tm.archived_at IS NULL) = 0
			ORDER BY u.display_name ASC
		`
	}
	var rows []*models.AdminUserRow
	if err := r.db.Select(&rows, q); err != nil {
		return nil, fmt.Errorf("listing admin users: %w", err)
	}
	return rows, nil
}

// RevokeUser atomically revokes all access for a user:
//  1. Sets users.archived_at (blocks login everywhere).
//  2. For each team_members row for the user:
//     – if assignment count is 0: deletes timeline_access then the row.
//     – otherwise: sets team_members.archived_at (inactivates without data loss).
//
// Returns a summary of the actions taken. The caller must ensure the user
// exists and is not a participant before calling.
func (r *UserRepo) RevokeUser(userID string) (*models.RevokeUserResult, error) {
	tx, err := r.db.Beginx()
	if err != nil {
		return nil, fmt.Errorf("beginning revoke transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()

	// Step 1: deactivate the account.
	if _, err := tx.Exec(
		`UPDATE users SET archived_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		now, userID,
	); err != nil {
		return nil, fmt.Errorf("deactivating user account: %w", err)
	}

	// Step 2: collect all team_members rows for the user.
	var memberIDs []string
	if err := tx.Select(&memberIDs,
		`SELECT id FROM team_members WHERE user_id = ?`, userID,
	); err != nil {
		return nil, fmt.Errorf("listing memberships: %w", err)
	}

	result := &models.RevokeUserResult{AccountDeactivated: true}

	for _, memberID := range memberIDs {
		var assignCount int
		if err := tx.Get(&assignCount,
			`SELECT COUNT(*) FROM activity_assignments WHERE team_member_id = ?`, memberID,
		); err != nil {
			return nil, fmt.Errorf("counting assignments for member %s: %w", memberID, err)
		}

		if assignCount == 0 {
			// No history — delete timeline_access then the member row.
			if _, err := tx.Exec(
				`DELETE FROM timeline_access WHERE team_member_id = ?`, memberID,
			); err != nil {
				return nil, fmt.Errorf("deleting timeline access for member %s: %w", memberID, err)
			}
			if _, err := tx.Exec(
				`DELETE FROM team_members WHERE id = ?`, memberID,
			); err != nil {
				return nil, fmt.Errorf("deleting member %s: %w", memberID, err)
			}
			result.MembershipsRemoved++
		} else {
			// Has activity history — inactivate without deleting.
			if _, err := tx.Exec(
				`UPDATE team_members SET archived_at = ? WHERE id = ?`, now, memberID,
			); err != nil {
				return nil, fmt.Errorf("inactivating member %s: %w", memberID, err)
			}
			result.MembershipsInactivated++
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing revoke transaction: %w", err)
	}
	return result, nil
}

// ptrEqual reports whether two string pointers point to equal values,
// treating nil and a pointer to "" as distinct.
func ptrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
