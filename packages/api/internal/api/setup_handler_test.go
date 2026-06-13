package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestSetupStatus_NeedsSetup(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/setup/status", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["needsSetup"])
}

func TestSetupStatus_NoSetupNeeded(t *testing.T) {
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Migrate(database))

	usersRepo := db.NewUserRepo(database)
	adminHash := "x"
	require.NoError(t, usersRepo.Create(&models.User{
		ID:           "u1",
		Email:        "admin@example.com",
		PasswordHash: &adminHash,
		DisplayName:  "Admin",
		AuthProvider: "local",
		IsSuperadmin: true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}))

	toks := auth.NewTokenService("setup-test-secret")
	bus := events.NewBus()
	hub := ws.NewHub(bus, toks, func(_, _ string) error { return nil })
	isrSetup := db.NewInstanceSettingsRepo(database)
	srv := api.NewServer(
		usersRepo,
		db.NewInviteRepo(database),
		db.NewTeamRepo(database),
		db.NewActivityRepo(database),
		db.NewTimelineRepo(database),
		db.NewSavedFilterRepo(database),
		db.NewUserPreferenceRepo(database),
		db.NewAPITokenRepo(database),
		isrSetup,
		db.NewPasswordResetTokenRepo(database),
		db.NewStatusRepo(database),
		db.NewTagRepo(database),
		db.NewShareRepo(database),
		mailer.New(isrSetup, nil),
		toks, tier.Unlimited, bus, hub,
	).Routes()

	req := httptest.NewRequest(http.MethodGet, "/setup/status", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp["needsSetup"])
}

func TestSetupStatus_NoAuthRequired(t *testing.T) {
	srv := newTestServer(t)

	// No Authorization header — must still return 200.
	req := httptest.NewRequest(http.MethodGet, "/setup/status", http.NoBody)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
