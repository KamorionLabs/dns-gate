package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func oauthConformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	now := clock.Now().Truncate(time.Millisecond)
	g := OAuthGrant{
		ID: "g-1", ClientID: "skopea", Subject: "idp:alice", SubjectName: "Alice", Issuer: "idp", Session: []byte(`{"c":{"sub":"alice"}}`),
		AuthTime: now.Unix(), Scopes: []string{"dns.read"}, CreatedAt: now, ConsentedAt: now, LastUsedAt: now,
		ExpiresAt: now.Add(90 * 24 * time.Hour), ClaimsAt: now, Generation: 1, BaseGeneration: 1, RefreshHash: "h1",
	}
	if err := s.CreateOAuthGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthGrant(ctx, g); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate grant: %v", err)
	}
	other := g
	other.ID, other.ClientID, other.Subject, other.CreatedAt = "g-2", "copilot", "idp:bob", now.Add(time.Second)
	if err := s.CreateOAuthGrant(ctx, other); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOAuthGrant(ctx, "g-1")
	if err != nil || got.Version != 1 || string(got.Session) != `{"c":{"sub":"alice"}}` || got.Scopes[0] != "dns.read" || !got.ExpiresAt.Equal(g.ExpiresAt) || got.RotatedAt != nil || !got.Active(now) {
		t.Fatalf("get grant: %v %+v", err, got)
	}
	if _, err := s.GetOAuthGrant(ctx, "g-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing grant: %v", err)
	}
	all, _ := s.ListOAuthGrants(ctx, OAuthGrantQuery{})
	if len(all) != 2 || all[0].ID != "g-2" {
		t.Fatalf("list: %+v", all)
	}
	if l, _ := s.ListOAuthGrants(ctx, OAuthGrantQuery{ClientID: "skopea", Subject: "idp:alice"}); len(l) != 1 || l[0].ID != "g-1" {
		t.Fatalf("list by client and subject: %+v", l)
	}
	if l, _ := s.ListOAuthGrants(ctx, OAuthGrantQuery{Subject: "idp:bob"}); len(l) != 1 || l[0].ID != "g-2" {
		t.Fatalf("list by subject: %+v", l)
	}
	rot := now.Add(time.Minute)
	got.Generation, got.PreviousHash, got.RefreshHash, got.RotatedAt, got.Pending = 2, "h1", "h2", &rot, "sealed"
	got.ClientID, got.Subject = "changed", "changed"
	if err := s.UpdateOAuthGrant(ctx, *got); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOAuthGrant(ctx, *got); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale grant update: %v", err)
	}
	got, _ = s.GetOAuthGrant(ctx, "g-1")
	if got.Version != 2 || got.Generation != 2 || got.PreviousHash != "h1" || got.RotatedAt == nil || !got.RotatedAt.Equal(rot) || got.Pending != "sealed" || got.ClientID != "skopea" || got.Subject != "idp:alice" {
		t.Fatalf("updated grant: %+v", got)
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cur := *got
			cur.Generation = 3
			results <- s.UpdateOAuthGrant(ctx, cur)
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent rotations: %d won", wins)
	}

	code := OAuthCode{Hash: "c1", ClientID: "skopea", Data: []byte(`{"x":1}`), ExpiresAt: now.Add(2 * time.Minute)}
	if err := s.PutOAuthCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOAuthCode(ctx, code); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate code: %v", err)
	}
	c, err := s.TakeOAuthCode(ctx, "c1")
	if err != nil || c.ClientID != "skopea" || string(c.Data) != `{"x":1}` || !c.ExpiresAt.Equal(code.ExpiresAt) {
		t.Fatalf("take code: %v %+v", err, c)
	}
	if _, err := s.TakeOAuthCode(ctx, "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("code taken twice: %v", err)
	}

	if err := s.UseOAuthJTI(ctx, "skopea:j1", now.Add(5*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := s.UseOAuthJTI(ctx, "skopea:j1", now.Add(5*time.Minute), now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("replayed jti: %v", err)
	}
	if err := s.UseOAuthJTI(ctx, "skopea:j1", now.Add(20*time.Minute), now.Add(10*time.Minute)); err != nil {
		t.Fatalf("jti after its expiry: %v", err)
	}

	rev := now
	other.RevokedAt, other.Version = &rev, 1
	if err := s.UpdateOAuthGrant(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOAuthCode(ctx, OAuthCode{Hash: "c2", ClientID: "skopea", Data: []byte("{}"), ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PurgeOAuth(ctx, now.Add(OAuthGrantRetention+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*dynamo); ok {
		return
	}
	if _, err := s.GetOAuthGrant(ctx, "g-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked grant not purged: %v", err)
	}
	if _, err := s.GetOAuthGrant(ctx, "g-1"); err != nil {
		t.Fatalf("active grant purged: %v", err)
	}
	if _, err := s.TakeOAuthCode(ctx, "c2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code not purged: %v", err)
	}
}
