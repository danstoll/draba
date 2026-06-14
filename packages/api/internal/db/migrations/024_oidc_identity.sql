-- Migration 024: OIDC / SSO identity support.
--
-- Adds the columns needed to authenticate a user via an external OpenID
-- Connect provider instead of (or in addition to) a local password:
--
--   auth_provider  'local' | 'oidc'  — how this account authenticates.
--   oidc_issuer    the IdP's issuer URL (only set for oidc accounts).
--   oidc_subject   the IdP's stable subject claim (sub) for this user.
--
-- An OIDC-only user has no password, so password_hash must become nullable.
-- SQLite cannot drop a NOT NULL constraint in place, so this is a table
-- rebuild (see migration 023). UNLIKE the shares rebuild in 023, ~17 tables
-- hold foreign keys REFERENCES users(id), several with ON DELETE CASCADE.
-- Dropping users with foreign_keys=ON would therefore cascade-delete every
-- dependent row (team_members, activities, preferences, …) — catastrophic
-- data loss.
--
-- We follow the official SQLite "Making Other Kinds Of Table Schema Changes"
-- procedure (sqlite.org/lang_altertable.html §8):
--   1. foreign_keys=OFF  (so the DROP does not cascade)
--   2. rebuild the table preserving every column
--   3. foreign_key_check  (assert no FK was orphaned by the rebuild)
--   4. foreign_keys=ON
--
-- NOTE on transactions: PRAGMA foreign_keys is a no-op inside a transaction,
-- so this migration must NOT be wrapped in BEGIN/COMMIT. draba's migrator
-- runs each file as a bare Exec on a single-connection pool, which is exactly
-- the context this procedure requires. The accompanying migration test asserts
-- that a user with dependent rows survives this migration intact.

PRAGMA foreign_keys=OFF;

CREATE TABLE users_new (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    display_name  TEXT NOT NULL,
    avatar_url    TEXT,
    color         TEXT,
    icon          TEXT,
    is_superadmin BOOLEAN NOT NULL DEFAULT 0,
    auth_provider TEXT NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'oidc')),
    oidc_issuer   TEXT,
    oidc_subject  TEXT,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    archived_at   DATETIME,
    -- A local account must carry a password; an oidc account must carry an
    -- issuer+subject. Enforced at the row level so a malformed account can
    -- never be inserted regardless of which code path writes it.
    CHECK (
        (auth_provider = 'local' AND password_hash IS NOT NULL)
        OR
        (auth_provider = 'oidc'  AND oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL)
    )
);

-- Every existing row is a local password user. Column order is pinned
-- explicitly (not SELECT *) so a future column added to users before this
-- migration runs cannot silently shift values into the wrong column.
INSERT INTO users_new (
    id, email, password_hash, display_name, avatar_url, color, icon,
    is_superadmin, auth_provider, oidc_issuer, oidc_subject,
    created_at, updated_at, archived_at
)
SELECT
    id, email, password_hash, display_name, avatar_url, color, icon,
    is_superadmin, 'local', NULL, NULL,
    created_at, updated_at, archived_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- One external identity maps to exactly one account. SQLite treats NULLs as
-- distinct in a UNIQUE index, so the many local rows with NULL/NULL coexist
-- freely while any concrete (issuer, subject) pair is forced unique.
CREATE UNIQUE INDEX idx_users_oidc ON users(oidc_issuer, oidc_subject);
CREATE INDEX idx_users_email ON users(email);

-- Re-enable enforcement. The migrator runs PRAGMA foreign_key_check after each
-- migration and aborts if it returns any rows (see db.checkForeignKeys), so an
-- orphaned FK from a bad rebuild fails the migration rather than leaving a
-- corrupt schema. This rebuild intends zero violations.
PRAGMA foreign_keys=ON;
