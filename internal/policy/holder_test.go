package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/store"
)

type countingActive struct {
	fakeActive
	calls int
}

func (c *countingActive) ActiveRevision(ctx context.Context) (*store.PolicyRevision, error) {
	c.calls++
	return c.fakeActive.ActiveRevision(ctx)
}

func TestHolderRefreshIfStale(t *testing.T) {
	h, _ := NewHolder(layeredConfig())
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	raw, _ := json.Marshal(goodDoc())
	src := &countingActive{fakeActive: fakeActive{rev: &store.PolicyRevision{ID: "rev-0001", Document: raw}}}
	ctx := context.Background()

	if err := h.RefreshIfStale(ctx, src, 10*time.Second); err != nil || src.calls != 1 || h.Current().RevisionID != "rev-0001" {
		t.Fatalf("first call must load: %v calls=%d rev=%q", err, src.calls, h.Current().RevisionID)
	}
	now = now.Add(9 * time.Second)
	src.rev = &store.PolicyRevision{ID: "rev-0002", Document: raw}
	if err := h.RefreshIfStale(ctx, src, 10*time.Second); err != nil || src.calls != 1 || h.Current().RevisionID != "rev-0001" {
		t.Fatalf("fresh snapshot must not reload: %v calls=%d", err, src.calls)
	}
	now = now.Add(2 * time.Second)
	if err := h.RefreshIfStale(ctx, src, 10*time.Second); err != nil || src.calls != 2 || h.Current().RevisionID != "rev-0002" {
		t.Fatalf("stale snapshot must reload: %v calls=%d rev=%q", err, src.calls, h.Current().RevisionID)
	}

	now = now.Add(time.Minute)
	src.rev, src.err = nil, context.DeadlineExceeded
	if err := h.RefreshIfStale(ctx, src, 10*time.Second); err == nil || h.Current().RevisionID != "rev-0002" {
		t.Fatalf("a failed refresh keeps the snapshot: %v", err)
	}
	if err := h.RefreshIfStale(ctx, src, 10*time.Second); err != nil || src.calls != 3 {
		t.Fatalf("a failed refresh is retried after maxAge only: %v calls=%d", err, src.calls)
	}

	now = now.Add(time.Minute)
	src.err = nil
	src.rev = &store.PolicyRevision{ID: "rev-0003", Document: raw}
	if err := h.Refresh(ctx, src); err != nil {
		t.Fatal(err)
	}
	if err := h.RefreshIfStale(ctx, src, 0); err != nil || src.calls != 4 {
		t.Fatalf("Refresh counts as a refresh: %v calls=%d", err, src.calls)
	}
}
