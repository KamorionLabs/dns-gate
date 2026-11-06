package uiapi

import "time"

// Teams own RRsets. They are declared in the teams block of the base file
// or of the managed layer, derived from claims (team_from families, issuer
// team_claim), or, during the migration to the teams block, referenced
// without being declared.
//
//	GET  /api/v1/teams                        -> TeamList     (ui.read)
//	GET  /api/v1/teams/{team}                 -> TeamDetail   (ui.read)
//	POST /api/v1/teams/{team}/rename          TeamRenameRequest -> Transfer (policy.propose)
//	POST /api/v1/zones/{zone}/transfers       TransferProposal  -> Transfer (dns.record.write or dns.ownership.approve)
//	GET  /api/v1/transfers?zone=&status=&limit=&cursor= -> TransferPage (ui.read on the zone)
//	GET  /api/v1/transfers/{id}               -> Transfer
//	POST /api/v1/transfers/{id}/approve       DecisionRequest -> Transfer
//	POST /api/v1/transfers/{id}/reject        DecisionRequest -> Transfer
//
// A transfer request moves RRsets of one team to another once approved by
// someone allowed to write every RRset through the owner team, or holding
// dns.ownership.approve on it: another person with
// ownership.require_second_approver, the requester itself may otherwise.
// A rename moves every RRset of a team in every zone (store only), in the
// background; it is proposed by a policy.propose holder and approved by a
// policy.approve holder.

// Team kinds (TeamInfo.Kind).
const (
	TeamKindDeclared = "declared" // teams block of the base file or of the managed layer
	TeamKindAuto     = "auto"     // referenced without being declared (migration)
	TeamKindFamily   = "family"   // teams derived from a claim by team_from (Name is the prefix and "*")
	TeamKindClaim    = "claim"    // teams taken from the team_claim of an issuer (Name is "*")
	TeamKindStore    = "store"    // owns RRsets but is referenced nowhere
)

// TeamInfo describes a team.
type TeamInfo struct {
	Name        string       `json:"name"`
	Kind        string       `json:"kind"`
	Layer       string       `json:"layer,omitempty"` // base | managed (declared teams)
	Description string       `json:"description,omitempty"`
	Members     *TeamMembers `json:"members,omitempty"` // with policy.read only
	Roles       []string     `json:"roles"`             // roles of the bindings naming the team
	VirtualKeys []string     `json:"virtual_keys,omitempty"`
	Family      *TeamFrom    `json:"family,omitempty"` // derivation of a family
	Issuer      string       `json:"issuer,omitempty"` // issuer of a claim kind
	Warning     string       `json:"warning,omitempty"`
	// RRsets is the number of RRsets the team owns in the zones the caller
	// can read.
	RRsets int `json:"rrsets"`
}

// TeamList is GET /api/v1/teams. Strict tells whether team references must
// be declared (the base file has a teams block).
type TeamList struct {
	Strict bool       `json:"strict"`
	Teams  []TeamInfo `json:"teams"`
}

// TeamZone counts what a team owns in a zone.
type TeamZone struct {
	Zone       string `json:"zone"`
	RRsets     int    `json:"rrsets"`
	Tombstones int    `json:"tombstones"`
}

// TeamDetail is GET /api/v1/teams/{team}: the team, what it owns in the
// zones the caller can read, and its pending transfers.
type TeamDetail struct {
	TeamInfo
	Owned     []TeamZone `json:"owned"`
	Transfers []Transfer `json:"transfers"`
	// Permissions are the rules of the team's roles, per zone; given to
	// policy.read holders and to the members of the team.
	Permissions []Permission `json:"permissions,omitempty"`
}

// Transfer kinds.
const (
	TransferKindRRsets = "rrsets" // RRsets of one zone
	TransferKindRename = "rename" // every RRset of a team, every zone
)

// Transfer statuses. Approval applies the transfer at once: a transfer is
// applied, or failed when its RRsets changed since the request. It stays
// applying while the apply cannot run (zone locked, store or provider
// unavailable, gate restarted): the gate retries it in the background for
// a day, then marks it failed.
const (
	TransferProposed = "proposed"
	TransferApplying = "applying"
	TransferApplied  = "applied"
	TransferRejected = "rejected"
	TransferExpired  = "expired"
	TransferFailed   = "failed"
)

// TransferRRset is one RRset of a transfer. Hash is its content hash when
// the request was made; a tombstone is a recently deleted RRset still
// reserved for its team.
type TransferRRset struct {
	Host      string `json:"host"`
	Type      string `json:"type"`
	Hash      string `json:"hash,omitempty"`
	Tombstone bool   `json:"tombstone,omitempty"`
}

// Transfer is an ownership transfer request.
type Transfer struct {
	ID              string          `json:"id"`
	Kind            string          `json:"kind"`
	Zone            string          `json:"zone,omitempty"` // empty for a rename
	FromTeam        string          `json:"from_team"`
	ToTeam          string          `json:"to_team"`
	RRsets          []TransferRRset `json:"rrsets"`
	Status          string          `json:"status"`
	Comment         string          `json:"comment"`
	Requester       Actor           `json:"requester"`
	CreatedAt       time.Time       `json:"created_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	DecidedBy       *Actor          `json:"decided_by,omitempty"`
	DecidedAt       *time.Time      `json:"decided_at,omitempty"`
	DecisionComment string          `json:"decision_comment,omitempty"`
	Moved           int             `json:"moved,omitempty"` // RRsets and tombstones moved by the apply
	Error           string          `json:"error,omitempty"` // why a failed transfer was not applied
	// CanDecide tells whether the caller may approve it (the requester may
	// always withdraw a proposed request).
	CanDecide bool `json:"can_decide"`
	// SelfApproved marks a request approved by its requester
	// (ownership.require_second_approver is false).
	SelfApproved bool `json:"self_approved,omitempty"`
}

// TransferProposal is the body of POST /api/v1/zones/{zone}/transfers. Every
// RRset must be owned by the same team (or reserved for it by a tombstone).
type TransferProposal struct {
	RRsets  []RRsetRef `json:"rrsets"`
	ToTeam  string     `json:"to_team"`
	Comment string     `json:"comment"`
	// Apply approves the request at once, by its requester: only when
	// ownership.require_second_approver is false.
	Apply bool `json:"apply,omitempty"`
}

// TeamRenameRequest is the body of POST /api/v1/teams/{team}/rename.
type TeamRenameRequest struct {
	To      string `json:"to"`
	Comment string `json:"comment"`
	// Apply approves the rename at once, by its requester: only when
	// ownership.require_second_approver is false.
	Apply bool `json:"apply,omitempty"`
}

// TransferPage lists transfers, newest first.
type TransferPage struct {
	Transfers  []Transfer `json:"transfers"`
	NextCursor string     `json:"next_cursor,omitempty"`
}
