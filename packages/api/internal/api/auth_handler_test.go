package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/I0-1O/draba/packages/api/internal/api"
	"github.com/I0-1O/draba/packages/api/internal/auth"
	"github.com/I0-1O/draba/packages/api/internal/db"
	"github.com/I0-1O/draba/packages/api/internal/events"
	"github.com/I0-1O/draba/packages/api/internal/mailer"
	"github.com/I0-1O/draba/packages/api/internal/models"
	"github.com/I0-1O/draba/packages/api/internal/tier"
	"github.com/I0-1O/draba/packages/api/internal/ws"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	srv, _ := newTestServerWithDB(t, tier.Unlimited)
	return srv
}

func newTestServerWithTier(t *testing.T, tr tier.Tier) http.Handler {
	t.Helper()
	srv, _ := newTestServerWithDB(t, tr)
	return srv
}

// newTestServerWithDB also returns the backing in-memory database, for tests
// that must flip state with no API surface — e.g. share revocation/expiry,
// whose endpoints land in Phase 13.5.
func newTestServerWithDB(t *testing.T, tr tier.Tier) (http.Handler, *sqlx.DB) {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Migrate(database))

	users := db.NewUserRepo(database)
	invites := db.NewInviteRepo(database)
	teams := db.NewTeamRepo(database)
	activitiesRepo := db.NewActivityRepo(database)
	timelinesRepo := db.NewTimelineRepo(database)
	tokens := auth.NewTokenService("test-secret")
	bus := events.NewBus()
	hub := ws.NewHub(bus, tokens, func(_, _ string) error { return nil })

	savedFiltersRepo := db.NewSavedFilterRepo(database)
	preferencesRepo := db.NewUserPreferenceRepo(database)
	apiTokensRepo := db.NewAPITokenRepo(database)
	instanceSetsRepo := db.NewInstanceSettingsRepo(database)
	passwordTokensRepo := db.NewPasswordResetTokenRepo(database)
	statusRepo := db.NewStatusRepo(database)
	tagsRepo := db.NewTagRepo(database)
	m := mailer.New(instanceSetsRepo, nil)
	return api.NewServer(users, invites, teams, activitiesRepo, timelinesRepo, savedFiltersRepo, preferencesRepo, apiTokensRepo, instanceSetsRepo, passwordTokensRepo, statusRepo, tagsRepo, db.NewShareRepo(database), m, tokens, tr, bus, hub).Routes(), database
}

func postJSON(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestRegister_FirstUserNoInvite(t *testing.T) {
	srv := newTestServer(t)

	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email":       "alice@example.com",
		"password":    "supersecret",
		"displayName": "Alice",
	})

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp["accessToken"])
	assert.NotEmpty(t, resp["refreshToken"])
}

func TestRegister_FirstUserIsSuperadmin(t *testing.T) {
	srv := newTestServer(t)

	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email":       "alice@example.com",
		"password":    "supersecret",
		"displayName": "Alice",
	})
	require.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	user := resp["user"].(map[string]any)
	assert.True(t, user["isSuperadmin"].(bool), "first registered user must be superadmin")
}

func TestRegister_SubsequentUserIsNotSuperadmin(t *testing.T) {
	srv, _ := newTeamTestServer(t)

	// Alice registers first.
	aliceToken, _ := seedUser(t, srv, "alice@example.com", "password1", "Alice")

	// Alice creates a team and invites Bob.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authReq(http.MethodPost, "/teams", map[string]string{"name": "Acme"}, aliceToken))
	require.Equal(t, http.StatusCreated, w.Code)
	var team map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&team))

	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authReq(http.MethodPost, fmt.Sprintf("/teams/%s/invites", team["id"]),
		map[string]string{"email": "bob@example.com", "role": "member"}, aliceToken))
	require.Equal(t, http.StatusCreated, w2.Code)
	var inv map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&inv))

	// Bob registers via invite.
	b, _ := json.Marshal(map[string]string{
		"email": "bob@example.com", "password": "password2",
		"displayName": "Bob", "inviteToken": inv["token"].(string),
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req)
	require.Equal(t, http.StatusCreated, w3.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w3.Body).Decode(&resp))
	user := resp["user"].(map[string]any)
	assert.False(t, user["isSuperadmin"].(bool), "subsequent users must not be superadmin")
}

func TestRegister_SecondUserRequiresInvite(t *testing.T) {
	srv := newTestServer(t)

	// Register first user
	postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})

	// Attempt second registration without invite
	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "bob@example.com", "password": "supersecret", "displayName": "Bob",
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRegister_DuplicateEmail(t *testing.T) {
	srv := newTestServer(t)

	postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})
	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "anotherpass", "displayName": "Alice2",
	})
	// Second user without invite → 403 (invite required), not 409
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestLogin_ValidCredentials(t *testing.T) {
	srv := newTestServer(t)

	postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})

	w := postJSON(t, srv, "/auth/login", map[string]string{
		"email": "alice@example.com", "password": "supersecret",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp["accessToken"])
}

func TestLogin_WrongPassword(t *testing.T) {
	srv := newTestServer(t)

	postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})

	w := postJSON(t, srv, "/auth/login", map[string]string{
		"email": "alice@example.com", "password": "wrongpass",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_ValidToken(t *testing.T) {
	srv := newTestServer(t)

	// Register and get tokens
	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})
	var reg map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&reg))
	refreshToken := reg["refreshToken"].(string)

	// Refresh
	w2 := postJSON(t, srv, "/auth/refresh", map[string]string{
		"refreshToken": refreshToken,
	})
	assert.Equal(t, http.StatusOK, w2.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&resp))
	assert.NotEmpty(t, resp["accessToken"])
}

func TestMe_AuthenticatedRequest(t *testing.T) {
	srv := newTestServer(t)

	// Register
	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})
	var reg map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&reg))
	accessToken := reg["accessToken"].(string)

	// Call /auth/me
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req)

	assert.Equal(t, http.StatusOK, w2.Code)
	var user map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&user))
	assert.Equal(t, "alice@example.com", user["email"])
}

func TestMe_Unauthenticated(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegister_TierUserLimitReached(t *testing.T) {
	// Seed a DB with 5 users already present, then confirm the 6th attempt returns 402.
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Migrate(database))

	users := db.NewUserRepo(database)
	seedHash := "x"
	for i := range 5 {
		require.NoError(t, users.Create(&models.User{
			ID:           fmt.Sprintf("user-%d", i),
			Email:        fmt.Sprintf("seed%d@example.com", i),
			PasswordHash: &seedHash,
			DisplayName:  fmt.Sprintf("Seed %d", i),
			AuthProvider: "local",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}))
	}

	toks2 := auth.NewTokenService("test-secret")
	bus2 := events.NewBus()
	hub2 := ws.NewHub(bus2, toks2, func(_, _ string) error { return nil })
	isr2 := db.NewInstanceSettingsRepo(database)
	srv := api.NewServer(users, db.NewInviteRepo(database), db.NewTeamRepo(database), db.NewActivityRepo(database), db.NewTimelineRepo(database), db.NewSavedFilterRepo(database), db.NewUserPreferenceRepo(database), db.NewAPITokenRepo(database), isr2, db.NewPasswordResetTokenRepo(database), db.NewStatusRepo(database), db.NewTagRepo(database), db.NewShareRepo(database), mailer.New(isr2, nil), toks2, tier.Team, bus2, hub2).Routes()

	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "newcomer@example.com", "password": "supersecret", "displayName": "Newcomer",
	})
	assert.Equal(t, http.StatusPaymentRequired, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	errObj, _ := resp["error"].(map[string]any)
	assert.Equal(t, "TIER_USER_LIMIT", errObj["code"])
}

func TestRegister_UnlimitedTierAllowsAll(t *testing.T) {
	srv := newTestServerWithTier(t, tier.Unlimited)

	w := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "alice@example.com", "password": "supersecret", "displayName": "Alice",
	})
	assert.Equal(t, http.StatusCreated, w.Code)

	// Second user fails due to missing invite, not a tier limit — confirm it's 403 not 402.
	w2 := postJSON(t, srv, "/auth/register", map[string]string{
		"email": "bob@example.com", "password": "supersecret", "displayName": "Bob",
	})
	assert.Equal(t, http.StatusForbidden, w2.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&resp))
	errObj, _ := resp["error"].(map[string]any)
	assert.Equal(t, "INVITE_REQUIRED", errObj["code"])
}
