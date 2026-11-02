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
// discovery when no explicit URL is configured.
type keySet struct {
	issuer  string
	jwksURL string
	client  *http.Client

	mu        sync.Mutex
	keys      jose.JSONWebKeySet
	fetchedAt time.Time
	now       func() time.Time
}

func newKeySet(issuer, jwksURL string, client *http.Client) *keySet {
	return &keySet{issuer: issuer, jwksURL: jwksURL, client: client, now: time.Now}
}

// key returns the verification key for kid, refetching the set when the kid
// is unknown (rotation) or the cache is old.
func (k *keySet) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	stale := now.Sub(k.fetchedAt) > jwksMaxAge
	if !stale {
		if key := k.lookup(kid); key != nil {
			return key, nil
		}
	}
	if stale || now.Sub(k.fetchedAt) > jwksRefreshMin {
		if err := k.fetch(ctx); err != nil {
			if key := k.lookup(kid); key != nil {
				return key, nil
			}
			return nil, err
		}
		k.fetchedAt = now
	}
	if key := k.lookup(kid); key != nil {
		return key, nil
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

func (k *keySet) fetch(ctx context.Context) error {
	if k.jwksURL == "" {
		u, err := k.discover(ctx)
		if err != nil {
			return err
		}
		k.jwksURL = u
	}
	var set jose.JSONWebKeySet
	if err := k.getJSON(ctx, k.jwksURL, &set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	k.keys = set
	return nil
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
