package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/I0-1O/draba/packages/api/internal/api"
	"github.com/I0-1O/draba/packages/api/internal/auth"
	"github.com/I0-1O/draba/packages/api/internal/db"
	"github.com/I0-1O/draba/packages/api/internal/events"
	"github.com/I0-1O/draba/packages/api/internal/models"
	"github.com/I0-1O/draba/packages/api/internal/tier"
	"github.com/I0-1O/draba/packages/api/internal/ws"
)

// newTestServerNoOIDC builds a Server with SSO left disabled. It exercises the
// "OIDC not configured" branch of the handlers without contacting any IdP.
func newTestServerNoOIDC(t *testing.T) (http.Handler, *db.UserRepo) {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Migrate(database))

	users := db.NewUserRepo(database)
	tokens := auth.NewTokenService("oidc-test-secret")
	bus := events.NewBus()
	hub := ws.NewHub(bus, tokens, func(_, _ string) error { return nil })

	srv := api.NewServer(
		users,
		db.NewInviteRepo(database),
		db.NewTeamRepo(database),
		db.NewActivityRepo(database),
		db.NewTimelineRepo(database),
		db.NewSavedFilterRepo(database),
		db.NewUserPreferenceRepo(database),
		db.NewAPITokenRepo(database),
		db.NewInstanceSettingsRepo(database),
		db.NewPasswordResetTokenRepo(database),
		db.NewStatusRepo(database),
		db.NewTagRepo(database),
		db.NewShareRepo(database),
		nil, // mailer not needed for these tests
		tokens,
		tier.Unlimited,
		bus,
		hub,
	)
	return srv.Routes(), users
}

// TestOIDC_DisabledReturns404 verifies that with SSO unconfigured, both OIDC
// endpoints report disabled rather than panicking or leaking a redirect.
func TestOIDC_DisabledReturns404(t *testing.T) {
	handler, _ := newTestServerNoOIDC(t)

	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s should report SSO disabled", path)
		assert.Contains(t, rec.Body.String(), "OIDC_DISABLED", "%s body should carry the disabled code", path)
	}
}

// TestOIDC_BrandingExposesSSOFlag verifies the public branding endpoint tells
// the login page whether to show the SSO button — false when disabled.
func TestOIDC_BrandingExposesSSOFlag(t *testing.T) {
	handler, _ := newTestServerNoOIDC(t)

	req := httptest.NewRequest(http.MethodGet, "/settings/branding", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"ssoEnabled":false`)
}

// TestLogin_RejectsOIDCUser verifies an SSO account (nil password) can never be
// authenticated through the password login endpoint, and that the error is the
// same generic INVALID_CREDENTIALS used for a bad password (no account-type
// oracle).
func TestLogin_RejectsOIDCUser(t *testing.T) {
	handler, users := newTestServerNoOIDC(t)

	issuer, subject := "https://idp.example.com", "sub-123"
	now := time.Now()
	require.NoError(t, users.CreateOIDC(&models.User{
		ID:          "oidc-user",
		Email:       "sso@example.com",
		DisplayName: "SSO User",
		OIDCIssuer:  &issuer,
		OIDCSubject: &subject,
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	body := `{"email":"sso@example.com","password":"anything-at-all"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_CREDENTIALS")
}

// TestOIDC_CreateAndLookupRoundTrip verifies the OIDC user persistence path:
// an SSO user can be created with no password and looked up by (issuer,
// subject), and the same (issuer, subject) is unique.
func TestOIDC_CreateAndLookupRoundTrip(t *testing.T) {
	_, users := newTestServerNoOIDC(t)

	issuer, subject := "https://idp.example.com", "sub-abc"
	now := time.Now()
	u := &models.User{
		ID:          "u-oidc",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		OIDCIssuer:  &issuer,
		OIDCSubject: &subject,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	require.NoError(t, users.CreateOIDC(u))

	got, err := users.GetByOIDCSubject(issuer, subject)
	require.NoError(t, err)
	assert.Equal(t, "u-oidc", got.ID)
	assert.Equal(t, "oidc", got.AuthProvider)
	assert.Nil(t, got.PasswordHash, "OIDC user must have no password")

	// A second user with the same external identity is rejected by the unique
	// index from migration 024.
	dup := *u
	dup.ID = "u-oidc-2"
	dup.Email = "alice2@example.com"
	assert.Error(t, users.CreateOIDC(&dup), "duplicate (issuer, subject) must be rejected")
}
