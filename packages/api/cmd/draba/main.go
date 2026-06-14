// Command draba is the API server entry point. It wires repositories,
// the auth token service, and tier configuration into the HTTP server,
// then listens for requests until the process is killed.
package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/I0-1O/draba/packages/api/internal/api"
	"github.com/I0-1O/draba/packages/api/internal/auth"
	"github.com/I0-1O/draba/packages/api/internal/buildinfo"
	"github.com/I0-1O/draba/packages/api/internal/db"
	"github.com/I0-1O/draba/packages/api/internal/events"
	"github.com/I0-1O/draba/packages/api/internal/mailer"
	"github.com/I0-1O/draba/packages/api/internal/tier"
	"github.com/I0-1O/draba/packages/api/internal/ws"
	sampledata "github.com/I0-1O/draba/packages/api/sample_data"
	drabui "github.com/I0-1O/draba/packages/api/ui"
)

const banner = "\n" +
	"      _           _\n" +
	"     | |         | |\n" +
	"   __| |_ __ __ _| |__   __ _\n" +
	"  / _` | '__/ _` | '_ \\ / _` |\n" +
	" | (_| | | | (_| | |_) | (_| |\n" +
	"  \\__,_|_|  \\__,_|_.__/ \\__,_|\n" +
	"\n" +
	"  see who's doing what, when.\n\n"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		runResetPassword(os.Args[2:])
		return
	}

	setupLogger()
	fmt.Print(banner)
	slog.Info("build", "commit", buildinfo.Short(), "built", buildinfo.Built)

	port := getenv("DRABA_PORT", "8080")
	dsn := getenv("DRABA_DB_DSN", "/data/draba.db")
	jwtSecret := os.Getenv("DRABA_JWT_SECRET")
	if jwtSecret == "" {
		slog.Error("DRABA_JWT_SECRET must be set")
		os.Exit(1)
	}

	t, err := tier.Load()
	if err != nil {
		slog.Error("tier load failed", "err", err)
		os.Exit(1)
	}
	l := t.Limits()
	if l.MaxUsers == 0 {
		slog.Info("tier", "tier", t)
	} else {
		slog.Info("tier", "tier", t, "maxUsers", l.MaxUsers, "maxTeams", l.MaxTeams)
	}

	database, err := db.Open(dsn)
	if err != nil {
		slog.Error("db: open failed", "err", err)
		os.Exit(1)
	}
	slog.Info("db: opened", "dsn", dsn)

	if err := db.Migrate(database); err != nil {
		slog.Error("db: migrate failed", "err", err)
		os.Exit(1)
	}
	slog.Info("db: migrations applied")

	// Optional pre-launch convenience: seed the canonical sample dataset into an
	// empty database so a freshly-wiped dev/test instance comes up populated.
	// Gated by DRABA_SEED_SAMPLE_DATA and a no-op once the DB has any users — it
	// must stay unset in any real deployment.
	if os.Getenv("DRABA_SEED_SAMPLE_DATA") == "1" {
		sql, err := sampledata.SQL()
		if err != nil {
			slog.Error("db: reading embedded sample data failed", "err", err)
			os.Exit(1)
		}
		seeded, err := db.SeedSampleDataIfEmpty(database, sql)
		if err != nil {
			slog.Error("db: sample-data seed failed", "err", err)
			os.Exit(1)
		}
		if seeded {
			slog.Info("db: sample data seeded (database was empty)")
		} else {
			slog.Info("db: sample-data seed skipped (database already populated)")
		}
	}

	users := db.NewUserRepo(database)
	invites := db.NewInviteRepo(database)
	teams := db.NewTeamRepo(database)
	activityRepo := db.NewActivityRepo(database)
	timelineRepo := db.NewTimelineRepo(database)
	savedFilterRepo := db.NewSavedFilterRepo(database)
	preferenceRepo := db.NewUserPreferenceRepo(database)
	apiTokenRepo := db.NewAPITokenRepo(database)
	instanceSetsRepo := db.NewInstanceSettingsRepo(database)
	passwordTokensRepo := db.NewPasswordResetTokenRepo(database)
	statusRepo := db.NewStatusRepo(database)
	tagRepo := db.NewTagRepo(database)
	shareRepo := db.NewShareRepo(database)
	m := mailer.New(instanceSetsRepo, []byte(jwtSecret))
	tokens := auth.NewTokenService(jwtSecret)

	bus := events.NewBus()
	hub := ws.NewHub(bus, tokens, func(teamID, userID string) error {
		_, err := teams.GetMember(teamID, userID)
		return err
	})
	go hub.Run()
	slog.Info("ws: hub running")

	if mods := tier.Registered(); len(mods) > 0 {
		slog.Info("modules loaded", "count", len(mods))
	}

	srv := api.NewServer(users, invites, teams, activityRepo, timelineRepo, savedFilterRepo, preferenceRepo, apiTokenRepo, instanceSetsRepo, passwordTokensRepo, statusRepo, tagRepo, shareRepo, m, tokens, t, bus, hub)

	// Wire up the embedded React SPA when a production build is present.
	// In dev the static/ directory only has .gitkeep so this is a no-op.
	if sub, err := fs.Sub(drabui.FS, "static"); err == nil {
		if _, err := sub.Open("index.html"); err == nil {
			srv.WithUI(sub)
			slog.Info("ui: serving embedded SPA")
		}
	}

	// Optional SSO. OIDC is disabled unless DRABA_OIDC_ISSUER is set. When it
	// is, discovery runs against the issuer at startup; a failure here is fatal
	// so a broken SSO setup is caught at boot rather than presenting users a
	// dead login button. The client secret is read once and never leaves the
	// process.
	oidcSvc, err := auth.NewOIDCService(context.Background(), auth.OIDCConfig{
		Issuer:       os.Getenv("DRABA_OIDC_ISSUER"),
		ClientID:     os.Getenv("DRABA_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("DRABA_OIDC_CLIENT_SECRET"),
		RedirectURL:  oidcRedirectURL(),
	})
	if err != nil {
		slog.Error("oidc: configuration failed", "err", err)
		os.Exit(1)
	}
	if oidcSvc != nil {
		// Auto-provisioning defaults ON (first SSO login creates the account),
		// matching the password-register bootstrap. Set DRABA_OIDC_AUTO_CREATE=0
		// to require accounts be pre-created before SSO login is allowed.
		autoCreate := os.Getenv("DRABA_OIDC_AUTO_CREATE") != "0"
		srv.WithOIDC(oidcSvc, autoCreate)
		slog.Info("oidc: SSO enabled", "issuer", os.Getenv("DRABA_OIDC_ISSUER"), "autoCreate", autoCreate)
	}

	slog.Info("listening", "port", port)
	if err := http.ListenAndServe(":"+port, srv.Routes()); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

// oidcRedirectURL returns the OIDC callback URL the IdP must redirect back to.
// It honours an explicit DRABA_OIDC_REDIRECT_URL override, otherwise derives it
// from DRABA_BASE_URL so a single base-URL setting covers both the app and the
// SSO callback.
func oidcRedirectURL() string {
	if v := os.Getenv("DRABA_OIDC_REDIRECT_URL"); v != "" {
		return v
	}
	if os.Getenv("DRABA_OIDC_ISSUER") == "" {
		return "" // SSO disabled; no redirect needed.
	}
	return strings.TrimRight(getenv("DRABA_BASE_URL", "http://localhost:8080"), "/") + "/auth/oidc/callback"
}

// setupLogger initialises the global slog logger. Level is controlled by
// DRABA_LOG_LEVEL (debug | info | warn | error); default is info.
// All output goes to stdout so Docker captures it in `docker logs`.
func setupLogger() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("DRABA_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

// getenv returns the env var value or fallback when unset/empty.
func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
