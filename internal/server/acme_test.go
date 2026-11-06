package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/store"
)

type conflictingStore struct {
	store.APIKeyStore
	conflicts int
}

func (c *conflictingStore) PutACMERegistration(ctx context.Context, r store.ACMERegistration) error {
	if c.conflicts > 0 {
		c.conflicts--
		return store.ErrConflict
	}
	return c.APIKeyStore.PutACMERegistration(ctx, r)
}

// A registration saved after a write is retried on a version conflict,
// against the stored version.
func TestSaveRegistrationRetries(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory().(store.APIKeyStore)
	now := time.Now()
	base := store.ACMERegistration{KeyID: "k", Subdomain: "example.com", Domain: "example.com", CreatedAt: now, UpdatedAt: now}
	if err := mem.PutACMERegistration(ctx, base); err != nil {
		t.Fatal(err)
	}
	cs := &conflictingStore{APIKeyStore: mem, conflicts: 2}
	s := &Server{cfg: Config{APIKeys: cs}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	stale := base
	stale.Version = 1
	err := s.saveRegistration(ctx, stale, func(r *store.ACMERegistration) { r.Values = []string{"v1"} })
	if err != nil {
		t.Fatal(err)
	}
	got, _ := mem.GetACMERegistration(ctx, "k", "example.com")
	if !slices.Equal(got.Values, []string{"v1"}) || got.Version != 2 {
		t.Fatalf("saved %+v", got)
	}
	cs.conflicts = 10
	if err := s.saveRegistration(ctx, *got, func(r *store.ACMERegistration) { r.Values = []string{"v2"} }); err == nil {
		t.Fatal("endless conflicts not reported")
	}
}

// A registration deleted meanwhile is not recreated when it came from the
// API (acme_domains) or when its key is revoked.
func TestSaveRegistrationNoResurrection(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory().(store.APIKeyStore)
	now := time.Now()
	revoked := now
	if err := mem.CreateAPIKey(ctx, store.APIKey{ID: "1111111111111111", Team: "web", Role: "acme", SecretHash: "h", CreatedAt: now, RoleGrant: "{}"}); err != nil {
		t.Fatal(err)
	}
	k, _ := mem.GetAPIKey(ctx, "1111111111111111")
	k.RevokedAt = &revoked
	if err := mem.UpdateAPIKey(ctx, *k); err != nil {
		t.Fatal(err)
	}
	if err := mem.CreateAPIKey(ctx, store.APIKey{ID: "2222222222222222", Team: "web", Role: "acme", SecretHash: "h", CreatedAt: now, RoleGrant: "{}"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{APIKeys: mem}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, reg := range []store.ACMERegistration{
		{KeyID: "2222222222222222", Subdomain: "uuid-api", Domain: "example.com", Origin: store.ACMEOriginAPI, CreatedAt: now, UpdatedAt: now, Version: 1},
		{KeyID: "1111111111111111", Subdomain: "example.com", Domain: "example.com", Origin: store.ACMEOriginClient, CreatedAt: now, UpdatedAt: now, Version: 1},
	} {
		_ = s.saveRegistration(ctx, reg, func(r *store.ACMERegistration) { r.Values = []string{"v"} })
		if _, err := mem.GetACMERegistration(ctx, reg.KeyID, reg.Subdomain); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s registration of key %s recreated", reg.Origin, reg.KeyID)
		}
	}
}
