package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	jwksRefreshMin = 30 * time.Second // minimum delay between refetches on unknown kid
	jwksMaxAge     = time.Hour
	maxDocBytes    = 1 << 20
)

// keySet fetches and caches the JWKS of an issuer, resolving it through OIDC
// discovery when no explicit URL is configured. One fetch runs at a time:
// callers holding a cached key never wait for it, callers needing it wait
// for the fetch in flight, and a fetch starts at most every jwksRefreshMin
// (an unknown kid in between is refused without fetching).
type keySet struct {
	issuer  string
	jwksURL string
	client  *http.Client

	mu        sync.Mutex
	keys      jose.JSONWebKeySet
	fetchedAt time.Time
	attemptAt time.Time
	inflight  chan struct{}
	now       func() time.Time
}

func newKeySet(issuer, jwksURL string, client *http.Client) *keySet {
	return &keySet{issuer: issuer, jwksURL: jwksURL, client: client, now: time.Now}
}

// key returns the verification key for kid, refetching the set when the kid
// is unknown (rotation) or the cache is old.
func (k *keySet) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	now := k.now()
	cached := k.lookup(kid)
	if cached != nil && now.Sub(k.fetchedAt) <= jwksMaxAge {
		k.mu.Unlock()
		return cached, nil
	}
	if wait := k.inflight; wait != nil {
		k.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		if key := k.lookup(kid); key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if !k.attemptAt.IsZero() && now.Sub(k.attemptAt) <= jwksRefreshMin {
		k.mu.Unlock()
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	done := make(chan struct{})
	k.inflight, k.attemptAt = done, now
	jwksURL := k.jwksURL
	k.mu.Unlock()

	set, resolved, err := k.fetch(ctx, jwksURL)

	k.mu.Lock()
	defer k.mu.Unlock()
	k.inflight = nil
	close(done)
	if err == nil {
		k.keys, k.jwksURL, k.fetchedAt = set, resolved, now
	}
	if key := k.lookup(kid); key != nil {
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (k *keySet) lookup(kid string) *jose.JSONWebKey {
	var candidates []jose.JSONWebKey
	if kid != "" {
		candidates = k.keys.Key(kid)
	} else if len(k.keys.Keys) == 1 {
		candidates = k.keys.Keys
	}
	for i := range candidates {
		c := candidates[i]
		if c.Use == "" || c.Use == "sig" {
			if !c.IsPublic() {
				continue
			}
			return &c
		}
	}
	return nil
}

// fetch reads the key set, discovering its URL first when jwksURL is empty;
// it returns the set and the URL it came from.
func (k *keySet) fetch(ctx context.Context, jwksURL string) (jose.JSONWebKeySet, string, error) {
	var set jose.JSONWebKeySet
	if jwksURL == "" {
		u, err := k.discover(ctx)
		if err != nil {
			return set, "", err
		}
		jwksURL = u
	}
	if err := k.getJSON(ctx, jwksURL, &set); err != nil {
		return set, "", fmt.Errorf("jwks: %w", err)
	}
	return set, jwksURL, nil
}

func (k *keySet) discover(ctx context.Context) (string, error) {
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	u := strings.TrimSuffix(k.issuer, "/") + "/.well-known/openid-configuration"
	if err := k.getJSON(ctx, u, &doc); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if strings.TrimSuffix(doc.Issuer, "/") != strings.TrimSuffix(k.issuer, "/") {
		return "", fmt.Errorf("discovery: issuer mismatch %q", doc.Issuer)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("discovery: no jwks_uri")
	}
	return doc.JWKSURI, nil
}

func (k *keySet) getJSON(ctx context.Context, url string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxDocBytes)).Decode(v)
}
