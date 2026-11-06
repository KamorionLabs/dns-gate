package zonewrite

import (
	"context"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// Each write of an ephemeral subject to an ephemeral RRset pushes its
// expiry back: a second ACME challenge added to the RRset late is not
// garbage-collected with the first one.
func TestEphemeralExpiryRefreshed(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	solver := &identity.Subject{Issuer: "api-key", ID: "k", Roles: []string{"acme"}, Teams: []string{"team-a"}}
	if err := e.add(solver, zoneName, rec("TXT", "_acme-challenge", `"one"`)); err != nil {
		t.Fatal(err)
	}
	o, err := e.st.Get(ctx, zoneName, "_acme-challenge", "TXT")
	if err != nil || o.ExpiresAt == nil || !o.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) {
		t.Fatalf("created %+v %v", o, err)
	}
	e.clock.Add(50 * time.Minute)
	if err := e.add(solver, zoneName, rec("TXT", "_acme-challenge", `"two"`)); err != nil {
		t.Fatal(err)
	}
	o, _ = e.st.Get(ctx, zoneName, "_acme-challenge", "TXT")
	if o.ExpiresAt == nil || !o.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) {
		t.Fatalf("expiry not refreshed: %v", o.ExpiresAt)
	}

	if err := e.add(alice, zoneName, rec("TXT", "_acme-challenge.perm", `"x"`)); err != nil {
		t.Fatal(err)
	}
	if err := e.add(solver, zoneName, rec("TXT", "_acme-challenge.perm", `"y"`)); err != nil {
		t.Fatal(err)
	}
	o, _ = e.st.Get(ctx, zoneName, "_acme-challenge.perm", "TXT")
	if o.ExpiresAt != nil {
		t.Fatalf("permanent RRset became ephemeral: %v", o.ExpiresAt)
	}
}
