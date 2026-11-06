package server

import (
	"context"
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
