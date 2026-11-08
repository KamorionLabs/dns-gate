// Package identity defines the authenticated caller.
package identity

import (
	"context"
	"net/netip"
)

// Kind is how the caller authenticated.
type Kind string

const (
	KindOIDC       Kind = "oidc"
	KindVirtualKey Kind = "virtual-key"
	KindAPIKey     Kind = "api-key"
)

// Subject is an authenticated caller after role binding.
type Subject struct {
	Kind   Kind
	Issuer string         // issuer name from config (not the URL)
	ID     string         // "sub" claim, virtual key id or API key id
	Claims map[string]any // raw claims (empty for virtual keys)
	Roles  []string       // bound roles
	Teams  []string       // owner teams the subject acts for
	// TeamRoles are the roles the subject holds through the bindings of
	// each of its teams (every role for each team of a virtual key; the
	// roles of bindings without a team for teams of an issuer team_claim).
	TeamRoles map[string][]string

	Groups []string // groups the subject belongs to (base and managed)
	// Delegations the subject may act for (policy.delegations), file order.
	Delegations []string

	Name     string // display name (email, pipeline name, key id)
	Category string // CategoryHuman | CategoryPipeline | CategoryKey

	// Addr is the source address of the request of an API key subject.
	Addr netip.Addr

	// Client is the delegated client the token of the subject was issued
	// to, nil when the subject acts directly. A delegated subject holds the
	// rights of the user capped by Scopes and the zones of the client.
	Client *Client
	// Scopes cap the actions of a delegated subject (internal/scope).
	Scopes []string
	// Intent is set on a copy of a delegated subject evaluated for a plan
	// or for the ownership checks of a transfer.
	Intent Intent
}

// Client is a delegated client of an issuer (issuers[].delegated_clients).
type Client struct {
	ID       string
	Name     string
	Zones    []string
	Surfaces []string
}

// Intent is the purpose a delegated subject is evaluated for.
type Intent string

// Intents.
const (
	IntentPlan     Intent = "plan"
	IntentTransfer Intent = "transfer"
)

// WithIntent returns a copy of the subject evaluated for intent.
func (s *Subject) WithIntent(i Intent) *Subject {
	c := *s
	c.Intent = i
	return &c
}

// ClientName returns the name of the delegated client, empty when none.
func (s *Subject) ClientName() string {
	if s == nil || s.Client == nil {
		return ""
	}
	return s.Client.Name
}

// ClientID returns the id of the delegated client, empty when none.
func (s *Subject) ClientID() string {
	if s == nil || s.Client == nil {
		return ""
	}
	return s.Client.ID
}

// Subject categories, shown in the UI and the audit log.
const (
	CategoryHuman    = "human"
	CategoryPipeline = "pipeline"
	CategoryKey      = "key"
	CategorySystem   = "system" // gate:* actors (reconciler, garbage collector)
)

// RolesFor returns the roles the subject holds through the bindings of a
// team it acts for.
func (s *Subject) RolesFor(team string) []string {
	if s == nil {
		return nil
	}
	for _, t := range s.Teams {
		if t == team {
			return s.TeamRoles[team]
		}
	}
	return nil
}

// ForTeam returns a copy of the subject acting for one of its teams only.
func (s *Subject) ForTeam(team string) *Subject {
	c := *s
	c.Teams = []string{team}
	return &c
}

// String returns "issuer:id".
func (s *Subject) String() string {
	if s == nil {
		return ""
	}
	return s.Issuer + ":" + s.ID
}

type ctxKey struct{}

// With stores the subject in the context.
func With(ctx context.Context, s *Subject) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// From returns the subject, nil if unauthenticated.
func From(ctx context.Context) *Subject { s, _ := ctx.Value(ctxKey{}).(*Subject); return s }
