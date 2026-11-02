// Package requestid carries the request id in the context.
package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

// Header is the request id header, accepted from clients when well formed.
const Header = "X-Request-ID"

var valid = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

type ctxKey struct{}

// With stores the id in the context.
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the id, empty if absent.
func From(ctx context.Context) string { s, _ := ctx.Value(ctxKey{}).(string); return s }

// FromHeader returns the client id when valid, a new random id otherwise.
func FromHeader(v string) string {
	if valid.MatchString(v) {
		return v
	}
	return New()
}

// New returns a random 128-bit hex id.
func New() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
