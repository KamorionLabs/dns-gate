package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// One fetch at a time, none for unknown kids within jwksRefreshMin, and
// callers with a cached key never wait for a fetch.
func TestKeySetSingleFlightAndBackoff(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var fetches atomic.Int32
	release := make(chan struct{})
	var block atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if block.Load() {
			<-release
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	}))
	t.Cleanup(srv.Close)
	now := time.Now()
	ks := newKeySet("", srv.URL, srv.Client())
	ks.now = func() time.Time { return now }
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ks.key(ctx, "k1"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := fetches.Load(); n != 1 {
		t.Fatalf("concurrent first lookups: %d fetches", n)
	}
	for i := 0; i < 5; i++ {
		if _, err := ks.key(ctx, "random"); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("unknown kids within the backoff: %d fetches", n)
	}

	now = now.Add(jwksRefreshMin + time.Second)
	block.Store(true)
	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = ks.key(ctx, "random-2")
	}()
	<-started
	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := make(chan error, 1)
	go func() {
		_, err := ks.key(ctx, "k1")
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("cached key during a fetch: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cached key waited for the fetch in flight")
	}
	close(release)
}
