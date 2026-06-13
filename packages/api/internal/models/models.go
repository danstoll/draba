// Package models holds the domain types shared across the API, db,
// and event-bus packages. These types are persisted directly via sqlx
// (db tags) and serialised on the wire (json tags); changing tags is a
// schema change.
package models

import "time"

// Activity is a scheduled item of work belonging to a Timeline. ArchivedAt is
// non-nil when the activity is soft-deleted; list endpoints exclude archived
// activities by default.
//
// AssignedMemberIDs is not stored on the activities table; it is populated by
// the repository from activity_assignments after every list query.
//
// GoogleEventID and CaldavUID are preserved as-is — they identify the
// corresponding records in external calendar systems (VEVENT identifiers).
type Activity struct {
	ID                string     `db:"id"                  json:"id"`
	TimelineID        string     `db:"timeline_id"         json:"timelineId"`
	Title             string     `db:"title"               json:"title"`
	Description       *string    `db:"description"         json:"description,omitempty"`
	Notes             *string    `db:"notes"               json:"notes,omitempty"`
	Icon              *string    `db:"icon"                json:"icon,omitempty"`
	Color             *string    `db:"color"               json:"color,omitempty"`
	StartAt           time.Time  `db:"start_at"            json:"startAt"`
	EndAt             time.Time  `db:"end_at"              json:"endAt"`
	AllDay            bool       `db:"all_day"             json:"allDay"`
	StatusID          *string    `db:"status_id"           json:"statusId,omitempty"`
	ParentActivityID  *string    `db:"parent_activity_id"  json:"parentActivityId,omitempty"`
	PercentComplete   *int       `db:"percent_complete"    json:"percentComplete,omitempty"`
	Location          *string    `db:"location"            json:"location,omitempty"`
	URL               *string    `db:"url"                 json:"url,omitempty"`
	Rrule             *string    `db:"rrule"               json:"rrule,omitempty"`
	CaldavUID         *string    `db:"caldav_uid"          json:"caldavUid,omitempty"`
	GoogleEventID     *string    `db:"google_event_id"     json:"googleEventId,omitempty"`
	CreatedBy         string     `db:"created_by"          json:"createdBy"`
	CreatedAt         time.Time  `db:"created_at"          json:"createdAt"`
	UpdatedAt         time.Time  `db:"updated_at"          json:"updatedAt"`
	ArchivedAt        *time.Time `db:"archived_at"         json:"archivedAt,omitempty"`
	AssignedMemberIDs []string   `db:"-"                   json:"assignedMemberIds"`
	TagIDs            []string   `db:"-"                   json:"tagIds"`
}

// TeamMemberWithUser joins a TeamMember row with its associated User so
// callers receive display names and emails in a single query. Participants
// (no user account) have empty email and avatar; their display_name comes
// from team_members.display_name via COALESCE in the query.
type TeamMemberWithUser struct {
	TeamMember
	Email       string  `db:"email"        json:"email"`
	DisplayName string  `db:"display_name" json:"displayName"`
	AvatarURL   *string `db:"avatar_url"   json:"avatarUrl,omitempty"`
}

// User is an authenticated account. PasswordHash is omitted from JSON
// to avoid leaking it through any handler that returns a User.
// ArchivedAt is non-nil when the account is inactivated; login is rejected
// for archived users. Color and Icon are user-level identity fields (migration
// 010); they propagate to team_members rows for the user when changed.
//
// AuthProvider, OIDCIssuer, and OIDCSubject are added in migration 024. A
// local user has AuthProvider "local" and a non-nil PasswordHash. An OIDC
// (SSO) user has AuthProvider "oidc", a nil PasswordHash, and a non-nil
// (OIDCIssuer, OIDCSubject) pair identifying them at the external IdP.
type User struct {
	ID           string     `db:"id"             json:"id"`
	Email        string     `db:"email"          json:"email"`
	PasswordHash *string    `db:"password_hash"  json:"-"`
	DisplayName  string     `db:"display_name"   json:"displayName"`
	AvatarURL    *string    `db:"avatar_url"     json:"avatarUrl,omitempty"`
	Color        *string    `db:"color"          json:"color,omitempty"`
	Icon         *string    `db:"icon"           json:"icon,omitempty"`
	IsSuperadmin bool       `db:"is_superadmin"  json:"isSuperadmin"`
	AuthProvider string     `db:"auth_provider"  json:"authProvider"`
	OIDCIssuer   *string    `db:"oidc_issuer"    json:"-"`
	OIDCSubject  *string    `db:"oidc_subject"   json:"-"`
	CreatedAt    time.Time  `db:"created_at"     json:"createdAt"`
	UpdatedAt    time.Time  `db:"updated_at"     json:"updatedAt"`
	ArchivedAt   *time.Time `db:"archived_at"    json:"archivedAt,omitempty"`
}

// Team is a workspace that groups users and their scheduled work. Color and
// Icon are identity fields added in migration 006; both are nullable until
// explicitly set by an admin. Description, Notes, and ArchivedAt are added in
// migration 008; ArchivedAt is non-nil when the team is soft-deleted.
// InviteLinkToken is a stable, reusable token added in migration 009; when
// non-nil it can be used by anyone to join the team during registration.
type Team struct {
	ID              string     `db:"id"                  json:"id"`
	Name            string     `db:"name"                json:"name"`
	Slug            string     `db:"slug"                json:"slug"`
	Description     *string    `db:"description"         json:"description,omitempty"`
	Notes           *string    `db:"notes"               json:"notes,omitempty"`
	Color           *string    `db:"color"               json:"color,omitempty"`
	Icon            *string    `db:"icon"                json:"icon,omitempty"`
	InviteLinkToken *string    `db:"invite_link_token"   json:"inviteLinkToken,omitempty"`
	CreatedAt       time.Time  `db:"created_at"          json:"createdAt"`
	UpdatedAt       time.Time  `db:"updated_at"          json:"updatedAt"`
	ArchivedAt      *time.Time `db:"archived_at"         json:"archivedAt,omitempty"`
}

// TeamMember is the join row that puts a person in a Team. UserID is nil
// for login-less Participants; DisplayName is populated for them instead.
// Role is the team-level role: "admin" or "member". Color and Icon are
// identity fields (migration 006); Color stores a color ID (e.g. "teal").
// ArchivedAt is non-nil when the member is inactivated (migration 009);
// inactivated members lose access but their data and assignments are preserved.
type TeamMember struct {
	ID          string     `db:"id"           json:"id"`
	TeamID      string     `db:"team_id"      json:"teamId"`
	UserID      *string    `db:"user_id"      json:"userId,omitempty"`
	DisplayName *string    `db:"display_name" json:"displayName,omitempty"`
	Role        string     `db:"role"         json:"role"`
	Color       *string    `db:"color"        json:"color,omitempty"`
	Icon        *string    `db:"icon"         json:"icon,omitempty"`
	JoinedAt    time.Time  `db:"joined_at"    json:"joinedAt"`
	ArchivedAt  *time.Time `db:"archived_at"  json:"archivedAt,omitempty"`
}

// MemberStats holds computed activity and timeline counts for a member.
// All counts are date-relative and scoped to activities the member is assigned to.
type MemberStats struct {
	ActiveTimelines    int `json:"activeTimelines"`
	ArchivedTimelines  int `json:"archivedTimelines"`
	PastDue            int `json:"pastDue"`
	Running            int `json:"running"`
	Upcoming           int `json:"upcoming"`
	Unscheduled        int `json:"unscheduled"`
	ArchivedActivities int `json:"archivedActivities"`
}

// MemberDetail combines a TeamMemberWithUser with computed stats and the
// member's full list of team memberships. Returned by GET /teams/:id/members/:memberId.
// UserArchivedAt reflects users.archived_at (account-level deactivation), distinct
// from ArchivedAt which is team_members.archived_at (membership-level inactivation).
type MemberDetail struct {
	TeamMemberWithUser
	Stats          MemberStats          `json:"stats"`
	Teams          []TeamMemberWithUser `json:"teams"`
	Deletable      bool                 `json:"deletable"`
	UserArchivedAt *time.Time           `json:"userArchivedAt,omitempty"`
}

// Timeline is a named date range over a team's events. It is not a data
// container — it is a view over a team's events for a given date window.
// Access is governed by timeline_access + team role; share_token allows
// unauthenticated read access via a stable public URL. Color and Icon are
// identity fields (migration 006). Description and Notes are free-text fields
// added in migration 013.
type Timeline struct {
	ID          string     `db:"id"          json:"id"`
	TeamID      string     `db:"team_id"     json:"teamId"`
	Name        string     `db:"name"        json:"name"`
	Description *string    `db:"description" json:"description,omitempty"`
	Notes       *string    `db:"notes"       json:"notes,omitempty"`
	StartDate   string     `db:"start_date"  json:"startDate"`
	EndDate     string     `db:"end_date"    json:"endDate"`
	Color       *string    `db:"color"       json:"color,omitempty"`
	Icon        *string    `db:"icon"        json:"icon,omitempty"`
	ShareToken  string     `db:"share_token" json:"shareToken"`
	IcalToken   string     `db:"ical_token"  json:"icalToken"`
	CreatedBy   string     `db:"created_by"  json:"createdBy"`
	CreatedAt   time.Time  `db:"created_at"  json:"createdAt"`
	UpdatedAt   time.Time  `db:"updated_at"  json:"updatedAt"`
	ArchivedAt  *time.Time `db:"archived_at" json:"archivedAt,omitempty"`
	// ShareCount is a derived count of the timeline's active (non-revoked,
	// non-expired) share links — view shares and ICS feeds alike. Populated by
	// the repo read queries; it backs the timeline tile's share chip (13.5).
	ShareCount int `db:"share_count" json:"shareCount"`
}

// SavedFilter is a user-owned, team-scoped named filter spec. Definition is
// an opaque JSON string interpreted by the client; the server treats it as
// arbitrary text and only validates that it parses as JSON.
type SavedFilter struct {
	ID           string    `db:"id"             json:"id"`
	TeamID       string    `db:"team_id"        json:"teamId"`
	UserID       string    `db:"user_id"        json:"userId"`
	Name         string    `db:"name"           json:"name"`
	Definition   string    `db:"definition"     json:"definition"`
	IsTeamFilter bool      `db:"is_team_filter" json:"isTeamFilter"`
	CreatedAt    time.Time `db:"created_at"     json:"createdAt"`
	UpdatedAt    time.Time `db:"updated_at"     json:"updatedAt"`
}

// UserPreference stores a single key/value setting for a user, optionally
// scoped to a timeline. TimelineID is “” for global preferences so the
// UNIQUE(user_id, timeline_id, key) DB constraint works without NULL handling.
// Serialised JSON omits TimelineID when empty so callers see null for global prefs.
type UserPreference struct {
	ID         string    `db:"id"          json:"id"`
	UserID     string    `db:"user_id"     json:"userId"`
	TimelineID string    `db:"timeline_id" json:"timelineId,omitempty"`
	Key        string    `db:"key"         json:"key"`
	Value      string    `db:"value"       json:"value"`
	UpdatedAt  time.Time `db:"updated_at"  json:"updatedAt"`
}

// APIToken is a long-lived Bearer credential a user issues for programmatic
// access. token_hash stores SHA-256(rawToken); the raw value is shown to the
// caller only once on creation. RevokedAt is non-nil when the token has been
// revoked; revoked tokens are not deleted so listing remains stable.
type APIToken struct {
	ID         string     `db:"id"           json:"id"`
	UserID     string     `db:"user_id"      json:"userId"`
	Name       string     `db:"name"         json:"name"`
	TokenHash  string     `db:"token_hash"   json:"-"`
	Scope      string     `db:"scope"        json:"scope"`
	LastUsedAt *time.Time `db:"last_used_at" json:"lastUsedAt,omitempty"`
	CreatedAt  time.Time  `db:"created_at"   json:"createdAt"`
	RevokedAt  *time.Time `db:"revoked_at"   json:"revokedAt,omitempty"`
}

// InstanceSetting stores a single instance-level configuration value.
// SMTP config and defaults live here. The value column is plain text;
// the mailer package handles decryption of the SMTP password field.
type InstanceSetting struct {
	Key       string    `db:"key"        json:"key"`
	Value     string    `db:"value"      json:"value"`
	UpdatedAt time.Time `db:"updated_at" json:"updatedAt"`
}

// PasswordResetToken is a single-use token for the forgot-password flow.
// TokenHash stores SHA-256 of the raw token; the raw value is sent by email
// and never stored. UsedAt is set when the token is consumed.
type PasswordResetToken struct {
	ID        string     `db:"id"         json:"id"`
	UserID    string     `db:"user_id"    json:"userId"`
	TokenHash string     `db:"token_hash" json:"-"`
	ExpiresAt time.Time  `db:"expires_at" json:"expiresAt"`
	UsedAt    *time.Time `db:"used_at"    json:"usedAt,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"createdAt"`
}

// AdminUserRow is a flat view of a user for the admin users list. It includes
// the user's fields plus the count of active team memberships.
type AdminUserRow struct {
	User
	TeamCount int `db:"team_count" json:"teamCount"`
}

// Valid Share.Kind and Share.Scope values.
const (
	ShareKindView      = "view"
	ShareKindICS       = "ics"
	ShareScopeTimeline = "timeline"
	ShareScopeMember   = "member"
)

// Share is a public read-only link scoped to one timeline. Kind discriminates
// the two flavors (migration 022): "view" shares freeze one view configuration
// and are served as a web snapshot at /s/{token}; "ics" shares are live
// subscribable calendar feeds served at GET /shares/{token}.ics. ICS shares
// carry Scope ("timeline" | "member") + MemberID and never a view config,
// filter, or password — the unguessable token is their only secret.
// PasswordHash is set only when a view share requires a password (Phase 13.2);
// ExpiresAt and RevokedAt support lifecycle management (Phase 13.4/13.5).
type Share struct {
	ID           string     `db:"id"             json:"id"`
	TimelineID   string     `db:"timeline_id"    json:"timelineId"`
	Token        string     `db:"token"          json:"token"`
	Kind         string     `db:"kind"           json:"kind"`
	Scope        *string    `db:"scope"          json:"scope,omitempty"`
	MemberID     *string    `db:"member_id"      json:"memberId,omitempty"`
	Name         *string    `db:"name"           json:"name,omitempty"`
	Description  *string    `db:"description"    json:"description,omitempty"`
	ViewType     string     `db:"view_type"      json:"viewType"`
	ViewConfig   string     `db:"view_config"    json:"viewConfig"`
	PasswordHash *string    `db:"password_hash"  json:"-"`
	ExpiresAt    *time.Time `db:"expires_at"     json:"expiresAt,omitempty"`
	// CreatedBy is nil when the share was created by a superadmin who holds
	// no team_members row in the timeline's team (migration 023).
	CreatedBy    *string    `db:"created_by"     json:"createdBy,omitempty"`
	CreatedAt    time.Time  `db:"created_at"     json:"createdAt"`
	LastViewedAt *time.Time `db:"last_viewed_at" json:"lastViewedAt,omitempty"`
	ViewCount    int        `db:"view_count"     json:"viewCount"`
	RevokedAt    *time.Time `db:"revoked_at"     json:"revokedAt,omitempty"`
	// Protected is a derived, read-only flag (password_hash is never serialized).
	// It is populated by the repo read methods so clients can show a lock badge
	// without ever seeing the hash.
	Protected bool `db:"-" json:"protected"`
}

// PublicMember is the safe projection of a team member for public share
// responses. It exposes only display fields — never email, role, or user_id.
type PublicMember struct {
	ID          string  `json:"id"`
	DisplayName string  `json:"displayName"`
	Color       *string `json:"color,omitempty"`
	Icon        *string `json:"icon,omitempty"`
}

// PublicActivity is the safe projection of an activity for public share
// responses. It includes standard display fields but omits notes (unless
// explicitly included for List shares with Notes enabled), caldav/google
// identifiers, and any internal fields.
type PublicActivity struct {
	ID                string    `json:"id"`
	Title             string    `json:"title"`
	Description       *string   `json:"description,omitempty"`
	Notes             *string   `json:"notes,omitempty"`
	Icon              *string   `json:"icon,omitempty"`
	Color             *string   `json:"color,omitempty"`
	StartAt           time.Time `json:"startAt"`
	EndAt             time.Time `json:"endAt"`
	AllDay            bool      `json:"allDay"`
	StatusID          *string   `json:"statusId,omitempty"`
	ParentActivityID  *string   `json:"parentActivityId,omitempty"`
	PercentComplete   *int      `json:"percentComplete,omitempty"`
	AssignedMemberIDs []string  `json:"assignedMemberIds"`
	TagIDs            []string  `json:"tagIds"`
}

// PublicTimeline is the safe timeline projection for share responses.
type PublicTimeline struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Color     *string `json:"color,omitempty"`
	Icon      *string `json:"icon,omitempty"`
	StartDate string  `json:"startDate"`
	EndDate   string  `json:"endDate"`
}

// PublicShare is the safe projection of a share row for the unauthenticated
// gateway response. It omits operational telemetry (view_count, last_viewed_at)
// and internal fields (created_by, revoked_at) that must not reach anonymous callers.
type PublicShare struct {
	ID         string     `json:"id"`
	TimelineID string     `json:"timelineId"`
	Token      string     `json:"token"`
	Name       *string    `json:"name,omitempty"`
	ViewType   string     `json:"viewType"`
	ViewConfig string     `json:"viewConfig"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// ShareProjection is the full aggregate returned by GET /shares/{token}.
// It contains all data the public viewer needs to render the configured view.
type ShareProjection struct {
	Share      PublicShare      `json:"share"`
	Timeline   PublicTimeline   `json:"timeline"`
	TeamName   string           `json:"teamName"`
	Members    []PublicMember   `json:"members"`
	Statuses   []Status         `json:"statuses"`
	Tags       []Tag            `json:"tags"`
	Activities []PublicActivity `json:"activities"`
}

// RevokeUserResult summarizes the outcome of POST /users/:id/revoke.
// The three counters let the caller show a meaningful summary in the UI.
type RevokeUserResult struct {
	AccountDeactivated     bool `json:"accountDeactivated"`
	MembershipsInactivated int  `json:"membershipsInactivated"`
	MembershipsRemoved     int  `json:"membershipsRemoved"`
}

// StatusTemplate is a reusable named preset of statuses owned by a team.
// When a timeline is created the team's chosen template's items are copied
// into live Status rows for that timeline.
type StatusTemplate struct {
	ID          string    `db:"id"          json:"id"`
	TeamID      string    `db:"team_id"     json:"teamId"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description,omitempty"`
	Position    int       `db:"position"    json:"position"`
	CreatedBy   string    `db:"created_by"  json:"createdBy"`
	CreatedAt   time.Time `db:"created_at"  json:"createdAt"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updatedAt"`
	// Items is populated by the repository when listing templates.
	Items []StatusTemplateItem `db:"-" json:"items"`
}

// StatusTemplateItem is one status value within a StatusTemplate.
type StatusTemplateItem struct {
	ID         string  `db:"id"          json:"id"`
	TemplateID string  `db:"template_id" json:"templateId"`
	Name       string  `db:"name"        json:"name"`
	Color      string  `db:"color"       json:"color"`
	Icon       *string `db:"icon"        json:"icon,omitempty"`
	IsClosed   bool    `db:"is_closed"   json:"isClosed"`
	Position   int     `db:"position"    json:"position"`
}

// Status is a live status value on a specific timeline. Rows are copied from a
// StatusTemplate's items when the timeline is created and then evolve independently.
type Status struct {
	ID         string    `db:"id"          json:"id"`
	TimelineID string    `db:"timeline_id" json:"timelineId"`
	Name       string    `db:"name"        json:"name"`
	Color      string    `db:"color"       json:"color"`
	Icon       *string   `db:"icon"        json:"icon,omitempty"`
	IsClosed   bool      `db:"is_closed"   json:"isClosed"`
	Position   int       `db:"position"    json:"position"`
	CreatedAt  time.Time `db:"created_at"  json:"createdAt"`
	UpdatedAt  time.Time `db:"updated_at"  json:"updatedAt"`
}

// TimelineAccessEntry is a single timeline access grant joined with the team
// member's display info. Returned by GET /teams/:id/timelines/:timelineId/access.
type TimelineAccessEntry struct {
	TimelineID   string  `db:"timeline_id"    json:"timelineId"`
	TeamMemberID string  `db:"team_member_id" json:"teamMemberId"`
	Role         string  `db:"role"           json:"role"`
	DisplayName  string  `db:"display_name"   json:"displayName"`
	Email        string  `db:"email"          json:"email"`
	Color        *string `db:"color"          json:"color,omitempty"`
	Icon         *string `db:"icon"           json:"icon,omitempty"`
	UserID       *string `db:"user_id"        json:"userId,omitempty"`
}

// Tag is a team-scoped label that can be applied to activities. Tags are
// normalized: a team_id+name pair is unique, enabling rename-all and
// name-based filter matching across timelines.
type Tag struct {
	ID        string    `db:"id"         json:"id"`
	TeamID    string    `db:"team_id"    json:"teamId"`
	Name      string    `db:"name"       json:"name"`
	Color     *string   `db:"color"      json:"color,omitempty"`
	CreatedBy string    `db:"created_by" json:"createdBy"`
	CreatedAt time.Time `db:"created_at" json:"createdAt"`
}

// Invite is a single-use token that grants an email address the right to
// join a Team. AcceptedAt is non-nil once consumed; expired or accepted
// invites are rejected by the registration handler.
type Invite struct {
	ID         string     `db:"id"          json:"id"`
	TeamID     string     `db:"team_id"     json:"teamId"`
	Email      string     `db:"email"       json:"email"`
	Token      string     `db:"token"       json:"token"`
	Role       string     `db:"role"        json:"role"`
	InvitedBy  string     `db:"invited_by"  json:"invitedBy"`
	ExpiresAt  time.Time  `db:"expires_at"  json:"expiresAt"`
	AcceptedAt *time.Time `db:"accepted_at" json:"acceptedAt,omitempty"`
	CreatedAt  time.Time  `db:"created_at"  json:"createdAt"`
}
