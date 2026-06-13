// Package api hosts the HTTP handlers, routing, and middleware for the
// draba REST API. Handlers are intentionally thin: they decode requests,
// delegate to repositories and services, and write responses. Business
// logic belongs in the domain packages, not here.
package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/I0-1O/draba/packages/api/internal/auth"
	"github.com/I0-1O/draba/packages/api/internal/db"
	"github.com/I0-1O/draba/packages/api/internal/events"
	"github.com/I0-1O/draba/packages/api/internal/mailer"
	"github.com/I0-1O/draba/packages/api/internal/models"
	"github.com/I0-1O/draba/packages/api/internal/tier"
	"github.com/I0-1O/draba/packages/api/internal/ws"
)

// TimelineStore is the persistence interface required by timeline handlers.
// The concrete implementation is *db.TimelineRepo; tests may substitute a fake.
type TimelineStore interface {
	Create(t *models.Timeline) error
	GetByID(id string) (*models.Timeline, error)
	GetByShareToken(token string) (*models.Timeline, error)
	ListByTeam(teamID string, includeArchived bool) ([]*models.Timeline, error)
	HasAccess(timelineID, teamMemberID string) (bool, error)
	GrantAccess(timelineID, teamMemberID, role string) error
	RevokeAccess(timelineID, teamMemberID string) error
	GetAccessRole(timelineID, teamMemberID string) (string, error)
	ListAccess(timelineID string) ([]*models.TimelineAccessEntry, error)
	SetArchived(id string, at *time.Time) error
	Update(t *models.Timeline) error
	Delete(id string) error
}

// Server holds shared dependencies for all HTTP handlers.
type Server struct {
	users          *db.UserRepo
	invites        *db.InviteRepo
	teams          *db.TeamRepo
	activities     *db.ActivityRepo
	timelines      TimelineStore
	savedFilters   *db.SavedFilterRepo
	preferences    *db.UserPreferenceRepo
	apiTokens      *db.APITokenRepo
	instanceSets   *db.InstanceSettingsRepo
	passwordTokens *db.PasswordResetTokenRepo
	statuses       *db.StatusRepo
	tags           *db.TagRepo
	shares         *db.ShareRepo
	shareCache     *shareCache
	icsCache       *icsFeedCache
	unlockLimiter  *rateLimiter
	mailer         *mailer.Mailer
	tokens         *auth.TokenService
	tier           tier.Tier
	bus            *events.Bus
	hub            *ws.Hub
	uiFS           fs.FS
	// oidc is non-nil only when SSO is configured (DRABA_OIDC_ISSUER set).
	// When nil, the /auth/oidc/* routes report SSO as disabled and no external
	// identity provider is ever contacted. Set via WithOIDC.
	oidc *auth.OIDCService
	// oidcAutoCreateUsers controls whether an unknown external identity is
	// auto-provisioned a local account on first SSO login.
	oidcAutoCreateUsers bool
}

// NewServer constructs a Server with its required dependencies. It does not
// touch the network; call Routes to obtain the http.Handler to serve.
func NewServer(
	users *db.UserRepo,
	invites *db.InviteRepo,
	teams *db.TeamRepo,
	activitiesRepo *db.ActivityRepo,
	timelinesRepo TimelineStore,
	savedFiltersRepo *db.SavedFilterRepo,
	preferencesRepo *db.UserPreferenceRepo,
	apiTokensRepo *db.APITokenRepo,
	instanceSetsRepo *db.InstanceSettingsRepo,
	passwordTokensRepo *db.PasswordResetTokenRepo,
	statusesRepo *db.StatusRepo,
	tagsRepo *db.TagRepo,
	sharesRepo *db.ShareRepo,
	m *mailer.Mailer,
	tokens *auth.TokenService,
	t tier.Tier,
	bus *events.Bus,
	hub *ws.Hub,
) *Server {
	// Both public-share caches share the DRABA_SHARE_CACHE_TTL setting.
	sc := newShareCache()
	return &Server{
		users:          users,
		invites:        invites,
		teams:          teams,
		activities:     activitiesRepo,
		timelines:      timelinesRepo,
		savedFilters:   savedFiltersRepo,
		preferences:    preferencesRepo,
		apiTokens:      apiTokensRepo,
		instanceSets:   instanceSetsRepo,
		passwordTokens: passwordTokensRepo,
		statuses:       statusesRepo,
		tags:           tagsRepo,
		shares:         sharesRepo,
		shareCache:     sc,
		icsCache:       newICSFeedCache(sc.ttl),
		unlockLimiter:  newRateLimiter(unlockMaxAttempts, time.Hour),
		mailer:         m,
		tokens:         tokens,
		tier:           t,
		bus:            bus,
		hub:            hub,
	}
}

// WithUI registers an embedded React SPA to be served at GET /. The FS must
// be rooted at the build output directory (i.e. contain index.html directly).
// When called, all unmatched GET paths fall back to index.html so React Router
// handles client-side navigation. Safe to skip in dev (no-op when not called).
func (s *Server) WithUI(uiFS fs.FS) *Server {
	s.uiFS = uiFS
	return s
}

// WithOIDC enables SSO. Passing a nil service leaves SSO disabled (the zero
// value), so callers can wire it unconditionally from a possibly-nil
// constructor result. autoCreate controls first-login auto-provisioning.
func (s *Server) WithOIDC(svc *auth.OIDCService, autoCreate bool) *Server {
	s.oidc = svc
	s.oidcAutoCreateUsers = autoCreate
	return s
}

// oidcAutoCreate reports whether unknown external identities are provisioned a
// local account on first SSO login.
func (s *Server) oidcAutoCreate() bool { return s.oidcAutoCreateUsers }

// Routes returns the fully-wired HTTP handler for the API, including all
// core routes plus any routes added by registered tier modules.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /setup/status", s.handleSetupStatus)
	mux.HandleFunc("GET /version", s.handleVersion)

	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	mux.HandleFunc("GET /auth/me", chain(s.handleMe, s.authMiddleware))
	mux.HandleFunc("POST /auth/forgot-password", s.handleForgotPassword)
	mux.HandleFunc("POST /auth/reset-password", s.handleResetPassword)
	// OIDC / SSO. Public (no auth): they start and complete the external login
	// flow. Both report SSO disabled with 404 when DRABA_OIDC_ISSUER is unset.
	mux.HandleFunc("GET /auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleOIDCCallback)

	mux.HandleFunc("GET /users/me/preferences", chain(s.handleGetPreferences, s.authMiddleware))
	mux.HandleFunc("PUT /users/me/preferences", chain(s.handleUpsertPreference, s.authMiddleware))
	mux.HandleFunc("GET /users/me/stats", chain(s.handleGetMyStats, s.authMiddleware))
	mux.HandleFunc("PATCH /users/me", chain(s.handleUpdateProfile, s.authMiddleware))
	mux.HandleFunc("PUT /users/me/password", chain(s.handleChangePassword, s.authMiddleware))

	mux.HandleFunc("GET /admin/smtp", chain(s.handleGetSMTP, s.authMiddleware))
	mux.HandleFunc("PUT /admin/smtp", chain(s.handlePutSMTP, s.authMiddleware))
	mux.HandleFunc("POST /admin/smtp/test", chain(s.handleTestSMTP, s.authMiddleware))
	mux.HandleFunc("DELETE /admin/smtp", chain(s.handleDeleteSMTP, s.authMiddleware))
	mux.HandleFunc("GET /admin/settings", chain(s.handleGetAdminSettings, s.authMiddleware))
	mux.HandleFunc("PATCH /admin/settings", chain(s.handlePatchAdminSettings, s.authMiddleware))
	mux.HandleFunc("GET /admin/users", chain(s.handleListAdminUsers, s.authMiddleware))

	// Public — no auth required; used by the login page and shared views.
	mux.HandleFunc("GET /settings/branding", s.handleGetPublicBranding)

	mux.HandleFunc("POST /tokens", chain(s.handleCreateAPIToken, s.authMiddleware))
	mux.HandleFunc("GET /tokens", chain(s.handleListAPITokens, s.authMiddleware))
	mux.HandleFunc("DELETE /tokens/{id}", chain(s.handleDeleteAPIToken, s.authMiddleware))

	mux.HandleFunc("GET /teams", chain(s.handleListTeams, s.authMiddleware))
	mux.HandleFunc("POST /teams", chain(s.handleCreateTeam, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}", chain(s.handleGetTeam, s.authMiddleware))
	mux.HandleFunc("PATCH /teams/{id}", chain(s.handleUpdateTeam, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/archive", chain(s.handleArchiveTeam, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/unarchive", chain(s.handleUnarchiveTeam, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/invites", chain(s.handleCreateInvite, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/invites", chain(s.handleListInvites, s.authMiddleware))
	mux.HandleFunc("DELETE /teams/{id}/invites/{inviteId}", chain(s.handleDeleteInvite, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/invite-link", chain(s.handleCreateInviteLink, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/invite-link/reset", chain(s.handleResetInviteLink, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/invite-link", chain(s.handleGetInviteLink, s.authMiddleware))
	mux.HandleFunc("DELETE /teams/{id}/invite-link", chain(s.handleDeleteInviteLink, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/members", chain(s.handleListMembers, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/members/{memberId}", chain(s.handleGetMember, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/members/{memberId}/stats", chain(s.handleGetMemberStats, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/members", chain(s.handleAddMember, s.authMiddleware))
	mux.HandleFunc("PATCH /teams/{id}/members/{memberId}", chain(s.handleUpdateMember, s.authMiddleware))
	mux.HandleFunc("DELETE /teams/{id}/members/{memberId}", chain(s.handleDeleteMember, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/members/{memberId}/archive", chain(s.handleArchiveMember, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/members/{memberId}/unarchive", chain(s.handleUnarchiveMember, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/participants", chain(s.handleCreateParticipant, s.authMiddleware))
	mux.HandleFunc("GET /users/search", chain(s.handleSearchUsers, s.authMiddleware))
	mux.HandleFunc("POST /users/{id}/promote", chain(s.handlePromoteUser, s.authMiddleware))
	mux.HandleFunc("POST /users/{id}/archive", chain(s.handleArchiveUser, s.authMiddleware))
	mux.HandleFunc("POST /users/{id}/unarchive", chain(s.handleUnarchiveUser, s.authMiddleware))
	mux.HandleFunc("POST /users/{id}/revoke", chain(s.handleRevokeUser, s.authMiddleware))
	mux.HandleFunc("DELETE /users/{id}", chain(s.handleDeleteUser, s.authMiddleware))
	// Activity routes use the team-scoped prefix (GET /teams/{id}/timelines/{timelineId}/...)
	// to avoid a Go 1.22 mux conflict with GET /timelines/share/{token}: both are
	// 3-segment GET paths and neither is more specific when the third segment differs.
	mux.HandleFunc("POST /teams/{id}/timelines/{timelineId}/activities", chain(s.handleCreateActivity, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/timelines/{timelineId}/activities", chain(s.handleListActivities, s.authMiddleware))
	mux.HandleFunc("PATCH /activities/{id}", chain(s.handleUpdateActivity, s.authMiddleware))
	mux.HandleFunc("DELETE /activities/{id}", chain(s.handleDeleteActivity, s.authMiddleware))
	mux.HandleFunc("POST /activities/{id}/archive", chain(s.handleArchiveActivity, s.authMiddleware))
	mux.HandleFunc("POST /activities/{id}/unarchive", chain(s.handleUnarchiveActivity, s.authMiddleware))

	mux.HandleFunc("GET /teams/{id}/tags", chain(s.handleListTags, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/tags", chain(s.handleCreateTag, s.authMiddleware))
	mux.HandleFunc("PATCH /tags/{id}", chain(s.handleUpdateTag, s.authMiddleware))
	mux.HandleFunc("DELETE /tags/{id}", chain(s.handleDeleteTag, s.authMiddleware))

	mux.HandleFunc("GET /teams/{id}/saved_filters/all", chain(s.handleListAllTeamSavedFilters, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/saved_filters", chain(s.handleListSavedFilters, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/saved_filters", chain(s.handleCreateSavedFilter, s.authMiddleware))
	mux.HandleFunc("PATCH /saved_filters/{id}", chain(s.handleUpdateSavedFilter, s.authMiddleware))
	mux.HandleFunc("DELETE /saved_filters/{id}", chain(s.handleDeleteSavedFilter, s.authMiddleware))

	mux.HandleFunc("GET /teams/{id}/status-templates", chain(s.handleListStatusTemplates, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/status-templates", chain(s.handleCreateStatusTemplate, s.authMiddleware))
	mux.HandleFunc("PATCH /status-templates/{id}", chain(s.handleUpdateStatusTemplate, s.authMiddleware))
	mux.HandleFunc("DELETE /status-templates/{id}", chain(s.handleDeleteStatusTemplate, s.authMiddleware))
	mux.HandleFunc("POST /status-templates/{id}/items", chain(s.handleCreateTemplateItem, s.authMiddleware))
	mux.HandleFunc("PATCH /status-template-items/{id}", chain(s.handleUpdateTemplateItem, s.authMiddleware))
	mux.HandleFunc("DELETE /status-template-items/{id}", chain(s.handleDeleteTemplateItem, s.authMiddleware))

	mux.HandleFunc("GET /teams/{id}/timelines", chain(s.handleListTimelines, s.authMiddleware))
	mux.HandleFunc("POST /teams/{id}/timelines", chain(s.handleCreateTimeline, s.authMiddleware))
	// GET /timelines/share/{token} must be registered before GET /timelines/{id} so
	// the more-specific literal "share" segment takes precedence.
	mux.HandleFunc("GET /timelines/share/{token}", s.handleGetTimelineByShareToken)
	mux.HandleFunc("GET /timelines/{id}", chain(s.handleGetTimeline, s.authMiddleware))
	// Timeline statuses are placed under /teams/{id}/timelines/{timelineId}/statuses
	// rather than /timelines/{id}/statuses to avoid a Go 1.22 mux pattern conflict
	// with GET /timelines/share/{token} (both are 3-segment paths and conflict on
	// paths like /timelines/share/statuses).
	mux.HandleFunc("GET /teams/{id}/timelines/{timelineId}/statuses", chain(s.handleListTimelineStatuses, s.authMiddleware))
	mux.HandleFunc("POST /timelines/{id}/archive", chain(s.handleArchiveTimeline, s.authMiddleware))
	mux.HandleFunc("POST /timelines/{id}/unarchive", chain(s.handleUnarchiveTimeline, s.authMiddleware))

	mux.HandleFunc("PATCH /timelines/{id}", chain(s.handleUpdateTimeline, s.authMiddleware))
	mux.HandleFunc("DELETE /timelines/{id}", chain(s.handleDeleteTimeline, s.authMiddleware))
	// Access list routes use the team-scoped prefix to avoid a Go 1.22 mux
	// conflict with GET /timelines/share/{token} on 3-segment GET paths.
	mux.HandleFunc("GET /teams/{id}/timelines/{timelineId}/access", chain(s.handleListTimelineAccess, s.authMiddleware))
	mux.HandleFunc("PUT /teams/{id}/timelines/{timelineId}/access/{memberId}", chain(s.handleGrantTimelineAccess, s.authMiddleware))
	mux.HandleFunc("DELETE /teams/{id}/timelines/{timelineId}/access/{memberId}", chain(s.handleRevokeTimelineAccess, s.authMiddleware))
	// Timeline status CRUD — POST shares the team-scoped prefix with GET statuses.
	// PATCH and DELETE use a flat /statuses/{id} prefix (2 segments, no conflict).
	mux.HandleFunc("POST /teams/{id}/timelines/{timelineId}/statuses", chain(s.handleCreateTimelineStatus, s.authMiddleware))
	mux.HandleFunc("PATCH /statuses/{id}", chain(s.handleUpdateStatus, s.authMiddleware))
	mux.HandleFunc("DELETE /statuses/{id}", chain(s.handleDeleteStatus, s.authMiddleware))

	// Share routes.
	// GET /shares/{token} is public — no auth. The token is the credential.
	// POST /timelines/{id}/shares uses the same /timelines/{id}/... prefix
	// as archive/unarchive so it avoids the Go 1.22 mux pattern conflict with
	// GET /timelines/share/{token} (only GET-method paths conflict).
	// GET /teams/{id}/timelines/{timelineId}/shares uses the team-scoped prefix
	// to avoid the GET conflict described above.
	mux.HandleFunc("GET /shares/{token}", s.handleGetShareProjection)
	mux.HandleFunc("POST /shares/{token}/unlock", s.handleUnlockShare)
	mux.HandleFunc("POST /timelines/{id}/shares", chain(s.handleCreateShare, s.authMiddleware))
	mux.HandleFunc("GET /teams/{id}/timelines/{timelineId}/shares", chain(s.handleListShares, s.authMiddleware))
	mux.HandleFunc("PATCH /shares/{id}", chain(s.handleUpdateShare, s.authMiddleware))
	mux.HandleFunc("DELETE /shares/{id}", chain(s.handleDeleteShare, s.authMiddleware))
	// Token rotation — the revocation story for ICS feeds (no password gate).
	// GET /shares/{token}.ics is served inside handleGetShareProjection: the
	// {token} wildcard spans the whole segment, so the .ics suffix arrives in
	// the path value and is dispatched there.
	mux.HandleFunc("POST /shares/{id}/regenerate", chain(s.handleRegenerateShare, s.authMiddleware))
	// Named feed variant: the {file} slug is cosmetic (calendar clients
	// default the calendar name from the URL filename); the token is the key.
	mux.HandleFunc("GET /shares/{token}/{file}", s.handleGetShareICSNamed)

	// GET /ws is intentionally outside authMiddleware — ServeWS validates the
	// JWT itself before upgrading, because WebSocket clients can't set headers.
	mux.HandleFunc("GET /ws", s.hub.ServeWS)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	if s.uiFS != nil {
		mux.Handle("GET /", spaHandler(s.uiFS))
	}

	ctx := &tier.ModuleContext{Mux: mux, Tier: s.tier}
	for _, m := range tier.Registered() {
		if err := m.Register(ctx); err != nil {
			// Module registration is a startup invariant — a failure here is a programming error.
			panic(fmt.Sprintf("tier module %q failed to register: %v", m.Name(), err))
		}
	}

	return requestLogger(mux)
}

// chain applies a single middleware to a handler function.
func chain(h http.HandlerFunc, m func(http.Handler) http.Handler) http.HandlerFunc {
	return m(h).ServeHTTP
}

// spaHandler serves the embedded React SPA. Known static assets are served
// directly; any unrecognised path falls back to index.html so React Router
// handles client-side navigation.
func spaHandler(uiFS fs.FS) http.Handler {
	fserver := http.FileServer(http.FS(uiFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := uiFS.Open(path); err != nil {
			// Unknown path — serve index.html and let React Router handle it.
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			fserver.ServeHTTP(w, r)
			return
		}
		fserver.ServeHTTP(w, r)
	})
}
