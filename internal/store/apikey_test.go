package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func apiKeyConformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	ks, ok := s.(APIKeyStore)
	if !ok {
		t.Fatal("store does not implement APIKeyStore")
	}
	now := clock.Now().Truncate(time.Millisecond)
	exp := now.Add(24 * time.Hour)
	k := APIKey{ID: "0123456789abcdef", Name: "certbot web", Description: "renewals", Team: "web", Role: "acme",
		SecretHash: "h1", ExpiresAt: &exp, AllowedCIDRs: []string{"192.0.2.0/24"}, CreatedAt: now,
		CreatedBy: "idp:alice", CreatedByName: "alice"}
	if _, err := ks.GetAPIKey(ctx, k.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err := ks.CreateAPIKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := ks.CreateAPIKey(ctx, k); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := ks.CreateAPIKey(ctx, APIKey{ID: "x"}); err == nil {
		t.Fatal("invalid key stored")
	}
	got, err := ks.GetAPIKey(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Name != k.Name || got.Team != "web" || got.Role != "acme" || got.SecretHash != "h1" ||
		got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || !slices.Equal(got.AllowedCIDRs, k.AllowedCIDRs) ||
		!got.CreatedAt.Equal(now) || got.CreatedBy != "idp:alice" || got.LastUsedAt != nil || got.RevokedAt != nil {
		t.Fatalf("stored %+v", got)
	}

	used := now.Add(time.Minute)
	if err := ks.TouchAPIKey(ctx, k.ID, used, "192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	if err := ks.TouchAPIKey(ctx, "ffffffffffffffff", used, "192.0.2.7"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch missing: %v", err)
	}

	rot := now.Add(time.Hour)
	overlap := rot.Add(time.Hour)
	upd := *got
	upd.SecretHash, upd.PreviousHash, upd.PreviousExpiresAt, upd.RotatedAt = "h2", "h1", &overlap, &rot
	upd.Team, upd.Role, upd.AllowedCIDRs, upd.ExpiresAt = "other", "admin", nil, nil
	if err := ks.UpdateAPIKey(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if err := ks.UpdateAPIKey(ctx, upd); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	got, _ = ks.GetAPIKey(ctx, k.ID)
	if got.Version != 2 || got.SecretHash != "h2" || got.PreviousHash != "h1" || !got.PreviousExpiresAt.Equal(overlap) ||
		!got.RotatedAt.Equal(rot) || got.Team != "web" || got.Role != "acme" || len(got.AllowedCIDRs) != 0 || got.ExpiresAt != nil ||
		got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) || got.LastUsedIP != "192.0.2.7" {
		t.Fatalf("after update %+v", got)
	}

	other := APIKey{ID: "fedcba9876543210", Team: "api", Role: "acme", SecretHash: "h3", CreatedAt: now.Add(time.Second)}
	if err := ks.CreateAPIKey(ctx, other); err != nil {
		t.Fatal(err)
	}
	list, err := ks.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != k.ID || list[1].ID != other.ID {
		t.Fatalf("list %+v", list)
	}

	reg := ACMERegistration{KeyID: k.ID, Subdomain: "8e5700ea-a4bf-41c7-8a77-e990661dcc6a", Domain: "www.example.com",
		AllowFrom: []string{"192.0.2.0/24"}, CreatedAt: now, UpdatedAt: now}
	if err := ks.PutACMERegistration(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := ks.PutACMERegistration(ctx, reg); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate registration: %v", err)
	}
	if err := ks.PutACMERegistration(ctx, ACMERegistration{KeyID: k.ID, Subdomain: "example.com", Domain: "example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	r, err := ks.GetACMERegistration(ctx, k.ID, reg.Subdomain)
	if err != nil || r.Version != 1 || r.Domain != "www.example.com" || !slices.Equal(r.AllowFrom, reg.AllowFrom) || len(r.Values) != 0 {
		t.Fatalf("registration %+v %v", r, err)
	}
	r.Values, r.UpdatedAt = []string{"v1", "v2"}, now.Add(time.Minute)
	if err := ks.PutACMERegistration(ctx, *r); err != nil {
		t.Fatal(err)
	}
	if err := ks.PutACMERegistration(ctx, *r); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale registration: %v", err)
	}
	r, _ = ks.GetACMERegistration(ctx, k.ID, reg.Subdomain)
	if r.Version != 2 || !slices.Equal(r.Values, []string{"v1", "v2"}) || !r.UpdatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("updated registration %+v", r)
	}
	if _, err := ks.GetACMERegistration(ctx, other.ID, reg.Subdomain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("registration of another key: %v", err)
	}
	regs, err := ks.ListACMERegistrations(ctx, k.ID)
	if err != nil || len(regs) != 2 || regs[0].Domain != "example.com" || regs[1].Domain != "www.example.com" {
		t.Fatalf("registrations %+v %v", regs, err)
	}
	if err := ks.DeleteACMERegistration(ctx, k.ID, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ks.DeleteACMERegistration(ctx, k.ID, "example.com"); err != nil {
		t.Fatalf("delete twice: %v", err)
	}
	if regs, _ := ks.ListACMERegistrations(ctx, k.ID); len(regs) != 1 {
		t.Fatalf("after delete %+v", regs)
	}
	if regs, _ := ks.ListACMERegistrations(ctx, other.ID); len(regs) != 0 {
		t.Fatalf("other key registrations %+v", regs)
	}

	if r, _ := ks.GetACMERegistration(ctx, k.ID, reg.Subdomain); r.Origin != ACMEOriginClient || r.ExpiresAt != nil {
		t.Fatalf("default origin %+v", r)
	}
	soon, later := now.Add(time.Hour), now.Add(48*time.Hour)
	owner := "idp:repo:example/certs"
	for sub, exp := range map[string]*time.Time{"a.example.com": &soon, "b.example.com": &later, "c.example.com": nil} {
		if err := ks.PutACMERegistration(ctx, ACMERegistration{KeyID: owner, Subdomain: sub, Domain: sub, Origin: ACMEOriginHTTPReq, CreatedAt: now, UpdatedAt: now, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	if r, _ := ks.GetACMERegistration(ctx, owner, "a.example.com"); r.Origin != ACMEOriginHTTPReq || r.ExpiresAt == nil || !r.ExpiresAt.Equal(soon) {
		t.Fatalf("origin and expiry %+v", r)
	}
	n, err := ks.PurgeACMERegistrations(ctx, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	regs, _ = ks.ListACMERegistrations(ctx, owner)
	if _, isDynamo := s.(*dynamo); !isDynamo && (n != 1 || len(regs) != 2) {
		t.Fatalf("purge removed %d, left %+v", n, regs)
	}
}
