// Package oidctest is a minimal local OpenID provider for tests: discovery,
// JWKS, token signing and an authorization code flow with PKCE.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Provider is a running test issuer.
type Provider struct {
	*httptest.Server
	Key    *rsa.PrivateKey
	KeyID  string
	signer jose.Signer

	mu    sync.Mutex
	codes map[string]pendingCode
	// LoginClaims are the claims of the user who "logs in" on /authorize.
	LoginClaims map[string]any
	// ClientID expected on the authorization and token endpoints.
	ClientID string
}

type pendingCode struct {
	nonce, challenge, redirect string
}

// New starts a provider.
func New() *Provider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	p := &Provider{Key: key, KeyID: "test-key", codes: map[string]pendingCode{}, ClientID: "gate-ui"}
	p.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.KeyID))
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.URL,
			"jwks_uri":               p.URL + "/jwks",
			"authorization_endpoint": p.URL + "/authorize",
			"token_endpoint":         p.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: p.KeyID, Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	return p
}

// Sign returns a signed JWT with the given claims; iss, iat and exp are
// filled when absent.
func (p *Provider) Sign(claims map[string]any) string {
	c := map[string]any{"iss": p.URL, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		c[k] = v
	}
	s, err := jwt.Signed(p.signer).Claims(c).Serialize()
	if err != nil {
		panic(err)
	}
	return s
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	p.codes[code] = pendingCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	pc, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge || r.PostForm.Get("redirect_uri") != pc.redirect {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	claims := map[string]any{"aud": p.ClientID, "nonce": pc.nonce}
	for k, v := range p.LoginClaims {
		claims[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id_token": p.Sign(claims), "access_token": "x", "token_type": "Bearer"})
}

func randomString() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
