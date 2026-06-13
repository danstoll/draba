package db_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/I0-1O/draba/packages/api/internal/db"
)

// TestMigrate_024_OIDCColumns verifies the OIDC identity columns and the
// auth_provider CHECK constraint exist after the full migration chain.
func TestMigrate_024_OIDCColumns(t *testing.T) {
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Migrate(database))

	for _, col := range []string{"auth_provider", "oidc_issuer", "oidc_subject"} {
		var n int
		require.NoError(t, database.Get(&n,
			`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = ?`, col))
		assert.Equal(t, 1, n, "users.%s should exist after migration 024", col)
	}

	// password_hash must now be nullable (notnull = 0) so OIDC-only users
	// can be created without a password.
	var notnull int
	require.NoError(t, database.Get(&notnull,
		`SELECT "notnull" FROM pragma_table_info('users') WHERE name = 'password_hash'`))
	assert.Equal(t, 0, notnull, "password_hash should be nullable after migration 024")

	// The unique OIDC index must exist.
	var idx int
	require.NoError(t, database.Get(&idx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_users_oidc'`))
	assert.Equal(t, 1, idx, "idx_users_oidc should exist")
}

// TestMigrate_024_PreservesDependentRows is the critical safety test. The
// users table is referenced by ~17 foreign keys, several with ON DELETE
// CASCADE. Migration 024 rebuilds users via DROP TABLE; if it failed to
// disable foreign_keys first, the DROP would cascade-delete every dependent
// row. This test seeds a user with team / membership / activity children and
// asserts the user AND all children survive the rebuild intact.
func TestMigrate_024_PreservesDependentRows(t *testing.T) {
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Migrate(database))

	// Seed a local user.
	_, err = database.Exec(`
		INSERT INTO users (id, email, password_hash, display_name, is_superadmin, auth_provider, created_at, updated_at)
		VALUES ('u1', 'alice@example.com', 'hash', 'Alice', 1, 'local', datetime('now'), datetime('now'))`)
	require.NoError(t, err)

	// Seed a team + membership (team_members references users(id) ON DELETE CASCADE).
	_, err = database.Exec(`
		INSERT INTO teams (id, name, slug, created_at, updated_at)
		VALUES ('t1', 'Acme', 'acme', datetime('now'), datetime('now'))`)
	require.NoError(t, err)
	_, err = database.Exec(`
		INSERT INTO team_members (id, team_id, user_id, role, joined_at)
		VALUES ('m1', 't1', 'u1', 'admin', datetime('now'))`)
	require.NoError(t, err)

	// Re-run the 024 rebuild SQL against the populated DB. (db.Migrate already
	// applied it once with no rows; this exercises the dangerous path where
	// dependent rows exist at rebuild time, which is what a real upgrade hits.)
	// Read the file the same way the existing migration tests do — relative to
	// the package dir.
	sql, err := os.ReadFile("migrations/024_oidc_identity.sql")
	require.NoError(t, err)
	_, err = database.Exec(string(sql))
	require.NoError(t, err, "re-applying 024 against populated DB must not error")

	// The user must survive.
	var users int
	require.NoError(t, database.Get(&users, `SELECT COUNT(*) FROM users WHERE id = 'u1'`))
	assert.Equal(t, 1, users, "user must survive the users-table rebuild")

	// The dependent membership must survive (would be 0 if the DROP cascaded).
	var members int
	require.NoError(t, database.Get(&members, `SELECT COUNT(*) FROM team_members WHERE user_id = 'u1'`))
	assert.Equal(t, 1, members, "dependent team_members row must survive the rebuild")

	// Foreign keys must be back ON after the migration.
	var fk int
	require.NoError(t, database.Get(&fk, `PRAGMA foreign_keys`))
	assert.Equal(t, 1, fk, "foreign_keys must be re-enabled after migration 024")

	// No orphaned foreign keys anywhere.
	rows, err := database.Query(`PRAGMA foreign_key_check`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	assert.False(t, rows.Next(), "foreign_key_check must report no violations")
}
