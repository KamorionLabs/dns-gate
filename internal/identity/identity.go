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

	Groups []string // groups the subject belongs to (base and managed)
	// Delegations the subject may act for (policy.delegations), file order.
	Delegations []string

	Name     string // display name (email, pipeline name, key id)
	Category string // CategoryHuman | CategoryPipeline | CategoryKey

	// Addr is the source address of the request of an API key subject.
	Addr netip.Addr
}

// Subject categories, shown in the UI and the audit log.
const (
	CategoryHuman    = "human"
	CategoryPipeline = "pipeline"
	CategoryKey      = "key"
	CategorySystem   = "system" // gate:* actors (reconciler, garbage collector)
)

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
