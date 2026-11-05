package uiapi

import "github.com/KamorionLabs/dns-gate/internal/dns"

// Adoption brings RRsets created outside the gate (foreign) under its
// ownership, for a team. It requires dns.record.adopt on each RRset and never
// applies to protected or server-managed (SOA, locked) records.
//
//	POST /api/v1/zones/{zone}/adopt/preview  AdoptSelection -> AdoptPreview   (dns.record.adopt)
//	POST /api/v1/zones/{zone}/adopt          AdoptApply     -> AdoptResult    (dns.record.adopt)
//	GET  /api/v1/zones/{zone}/terraform?team=&hosts=&types=  -> text/plain HCL (ui.read)
//
// Apply is all-or-nothing: if any selected RRset is no longer adoptable (or
// changed since the preview, see PreviewToken), nothing is adopted and the
// response is 409 {"reason":"adopt_conflict"}.

// RRsetRef identifies an RRset.
type RRsetRef struct {
	Host string `json:"host"`
	Type string `json:"type"`
}

// AdoptSelection selects foreign RRsets explicitly and/or by filter.
type AdoptSelection struct {
	RRsets []RRsetRef `json:"rrsets,omitempty"`
	Hosts  []string   `json:"hosts,omitempty"` // globs, combined with Types
	Types  []string   `json:"types,omitempty"`
	Owner  string     `json:"owner,omitempty"` // team; defaults to the caller's team
}

// AdoptCandidate is one RRset in a preview.
type AdoptCandidate struct {
	Host      string   `json:"host"`
	Type      string   `json:"type"`
	TTL       int      `json:"ttl"`
	Values    []string `json:"values"`
	Status    string   `json:"status"` // current inventory status
	Adoptable bool     `json:"adoptable"`
	Reason    string   `json:"reason,omitempty"` // why not: protected, server_managed, owned_by_other_team, already_owned, forbidden, relative_target
}

// AdoptPreview is the dry-run result.
type AdoptPreview struct {
	Zone         string           `json:"zone"`
	Owner        string           `json:"owner"`
	Candidates   []AdoptCandidate `json:"candidates"`
	PreviewToken string           `json:"preview_token"` // binds apply to this exact upstream content
}

// AdoptApply adopts the adoptable candidates of a preview.
type AdoptApply struct {
	RRsets       []RRsetRef `json:"rrsets"`
	Owner        string     `json:"owner,omitempty"`
	Comment      string     `json:"comment"` // required
	PreviewToken string     `json:"preview_token"`
}

// AdoptResult lists what was adopted.
type AdoptResult struct {
	Zone      string     `json:"zone"`
	Owner     string     `json:"owner"`
	Adopted   []RRsetRef `json:"adopted"`
	RequestID string     `json:"request_id"`
}

// RRsetChange is a desired state for one RRset (Values nil or empty with
// Delete=true removes it). Used by MCP plan/apply and the UI.
type RRsetChange struct {
	Host   string     `json:"host"`
	Type   string     `json:"type"`
	TTL    int        `json:"ttl,omitempty"`
	Values []string   `json:"values,omitempty"`
	Alias  *dns.Alias `json:"alias,omitempty"`
	Delete bool       `json:"delete,omitempty"`
	// ExpectedHash, when set, is the content hash (dns.ContentHash) the
	// RRset must have upstream for the change to apply: precondition
	// otherwise. MustNotExist refuses the change if the RRset exists.
	ExpectedHash string `json:"expected_hash,omitempty"`
	MustNotExist bool   `json:"must_not_exist,omitempty"`
}

// PlanResult is a dry run of RRset changes for a subject.
type PlanResult struct {
	Zone        string   `json:"zone"`
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason,omitempty"` // zonewrite reason when refused
	Message     string   `json:"message,omitempty"`
	Changes     []Change `json:"changes"`
	ZoneVersion int64    `json:"zone_version"`
	PlanID      string   `json:"plan_id,omitempty"` // set by the MCP layer, binds apply to this plan
}
