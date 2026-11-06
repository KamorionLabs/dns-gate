// Package uiapi defines the read-only JSON API consumed by the web UI
// (and usable with bearer tokens). All routes are under /api/v1 and require
// the ui.read action; they never call a provider synchronously except to fill
// an empty inventory cache.
//
//	GET /api/v1/me                         -> Me
//	GET /api/v1/connect                    -> Connect
//	GET /api/v1/connect/claude-desktop.mcpb -> Claude Desktop extension (zip)
//	GET /api/v1/zones                      -> []ZoneSummary
//	GET /api/v1/zones/{zone}/rrsets        -> ZoneInventory
//	GET /api/v1/audit?zone=&host=&type=&subject=&category=&decision=&since=&until=&limit=&cursor=
//	                                       -> AuditPage
//	POST /api/v1/tokens                    -> gate token of the UI session
package uiapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
)

// Me describes the logged-in user.
type Me struct {
	Subject     string       `json:"subject"`  // issuer:id
	Name        string       `json:"name"`     // display name
	Category    string       `json:"category"` // human | pipeline | key
	Roles       []string     `json:"roles"`
	Teams       []string     `json:"teams"`
	Groups      []string     `json:"groups"`
	Permissions []Permission `json:"permissions"`
}

// Permission is one effective rule of a role of the subject (base and
// managed layers merged, managed rules clipped to the bounds).
type Permission struct {
	Role    string   `json:"role"`
	Zones   []string `json:"zones"`
	Actions []string `json:"actions"`
	Hosts   []string `json:"hosts"` // empty: the whole zone
	Types   []string `json:"types"` // empty: any type
}

// Connect is what a client needs to reach the gate (Connect page).
type Connect struct {
	BaseURL  string         `json:"base_url"`
	MCP      ConnectMCP     `json:"mcp"`
	Issuer   *ConnectIssuer `json:"issuer,omitempty"` // UI login issuer, absent without UI
	ClientID string         `json:"client_id,omitempty"`
	CLIScope string         `json:"cli_scope,omitempty"` // scope a CLI requests for a gate token
	// ClaudeDesktopExtensionURL downloads the Claude Desktop extension of the
	// gate; empty without MCP or UI login.
	ClaudeDesktopExtensionURL string `json:"claude_desktop_extension_url"`
	// TokensURL issues gate tokens to the UI session (POST, CSRF); empty
	// without a gate issuer.
	TokensURL string `json:"tokens_url,omitempty"`
}

// ConnectMCP describes the MCP endpoint.
type ConnectMCP struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	AllowWrites bool   `json:"allow_writes"`
}

// ConnectIssuer describes the OIDC issuer humans sign in with.
type ConnectIssuer struct {
	URL      string `json:"url"`
	Kind     string `json:"kind"`                // entra | oidc | saml (URL: the gate issuer, if any)
	TenantID string `json:"tenant_id,omitempty"` // Entra only
}

// ZoneSummary is one zone: managed, or discovered in a provider account
// and not managed (Unmanaged, read-only; counts stay zero until its content
// has been read once).
type ZoneSummary struct {
	Zone         string     `json:"zone"`
	Provider     string     `json:"provider"`
	Unmanaged    bool       `json:"unmanaged,omitempty"`
	RRsets       int        `json:"rrsets"`  // total upstream RRsets
	Managed      int        `json:"managed"` // owned by the gate (active)
	Tainted      int        `json:"tainted"`
	Pending      int        `json:"pending"`
	Foreign      int        `json:"foreign"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"` // last upstream read
	LastWriteAt  *time.Time `json:"last_write_at,omitempty"`  // latest successful gate write, from the journal
}

// RRset statuses.
const (
	StatusManaged = "managed"
	StatusTainted = "tainted"
	StatusPending = "pending"
	StatusForeign = "foreign" // exists upstream, not owned: read-only for the gate
	StatusMissing = "missing" // owned but gone upstream (drift)
)

// RRset is one RRset with its ownership.
type RRset struct {
	Host          string     `json:"host"`
	Type          string     `json:"type"`
	TTL           int        `json:"ttl"`
	Values        []string   `json:"values"`
	Alias         *dns.Alias `json:"alias,omitempty"`
	ReadOnly      string     `json:"read_only,omitempty"`
	Hash          string     `json:"hash"`
	Status        string     `json:"status"`
	Protected     bool       `json:"protected"`
	Owner         string     `json:"owner,omitempty"` // team
	CreatedBy     *Actor     `json:"created_by,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	UpdatedBy     *Actor     `json:"updated_by,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	Adopted       bool       `json:"adopted"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastRequestID string     `json:"last_request_id,omitempty"`
}

// Actor is who did something.
type Actor struct {
	Subject  string `json:"subject"`  // issuer:id
	Name     string `json:"name"`     // display (pipeline name, user email, key id)
	Category string `json:"category"` // human | pipeline | key
}

// ZoneInventory is the RRsets of a zone.
type ZoneInventory struct {
	Zone         string     `json:"zone"`
	Provider     string     `json:"provider,omitempty"`  // id of the provider serving the zone
	Unmanaged    bool       `json:"unmanaged,omitempty"` // discovered, not managed: read-only, no adoption
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
	RRsets       []RRset    `json:"rrsets"`
}

// AuditEntry is one audit event as shown in the UI.
type AuditEntry struct {
	Time       time.Time  `json:"time"`
	RequestID  string     `json:"request_id"`
	Actor      Actor      `json:"actor"`
	Teams      []string   `json:"teams,omitempty"`
	Action     string     `json:"action"`
	Zone       string     `json:"zone,omitempty"`
	Decision   string     `json:"decision"` // allow | deny | error
	Reason     string     `json:"reason,omitempty"`
	Changes    []Change   `json:"changes,omitempty"`
	Provider   string     `json:"provider,omitempty"` // id of the provider of the zone
	SnapshotID SnapshotID `json:"snapshot_id,omitempty"`
}

// SnapshotID is the provider snapshot taken before a write (EuroDNS). It
// is written as a JSON string and read from a string or, for events
// recorded before the provider-neutral model, a number.
type SnapshotID string

// UnmarshalJSON accepts a string, a number or null.
func (s *SnapshotID) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case nil:
		*s = ""
	case string:
		*s = SnapshotID(x)
	case float64:
		*s = SnapshotID(strings.TrimSpace(string(b)))
	default:
		return fmt.Errorf("snapshot id: unexpected JSON %s", b)
	}
	return nil
}

// Change is one RRset change in an audit entry.
type Change struct {
	Op        string     `json:"op"` // create | update | delete | adopt | taint | expire
	Host      string     `json:"host"`
	Type      string     `json:"type"`
	OldTTL    int        `json:"old_ttl,omitempty"`
	OldValues []string   `json:"old_values,omitempty"`
	OldAlias  *dns.Alias `json:"old_alias,omitempty"`
	NewTTL    int        `json:"new_ttl,omitempty"`
	NewValues []string   `json:"new_values,omitempty"`
	NewAlias  *dns.Alias `json:"new_alias,omitempty"`
}

// AuditPage is a page of audit entries, newest first.
type AuditPage struct {
	Entries    []AuditEntry `json:"entries"`
	NextCursor string       `json:"next_cursor,omitempty"`
}
