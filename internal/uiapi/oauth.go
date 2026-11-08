package uiapi

import "time"

// OAuth grant states.
const (
	OAuthGrantActive  = "active"
	OAuthGrantExpired = "expired"
	OAuthGrantRevoked = "revoked"
)

// OAuthGrant is the consent of a user to a declared OAuth client
// (GET /api/v1/oauth/grants): never its tokens.
type OAuthGrant struct {
	ID          string     `json:"id"`
	ClientID    string     `json:"client_id"`
	ClientName  string     `json:"client_name"`
	Subject     string     `json:"subject"`
	SubjectName string     `json:"subject_name,omitempty"`
	Scopes      []string   `json:"scopes"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ConsentedAt time.Time  `json:"consented_at"`
	LastUsedAt  time.Time  `json:"last_used_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

// OAuthGrantList is the answer of GET /api/v1/oauth/grants.
type OAuthGrantList struct {
	Grants []OAuthGrant `json:"grants"`
	// Manage tells whether the caller holds gate.oauth.manage (listing and
	// revoking the grants of every user).
	Manage bool `json:"manage"`
}

// OAuthRevoked is the answer of a revocation by client or subject.
type OAuthRevoked struct {
	Revoked int `json:"revoked"`
}
