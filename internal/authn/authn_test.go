package authn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/oidctest"
)

func setup(t *testing.T) (*Authenticator, *oidctest.Provider) {
	t.Helper()
	p := oidctest.New()
	t.Cleanup(p.Close)
	sum := sha256.Sum256([]byte("vk-secret"))
	exp := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	c := &config.Config{
		Listen: config.Listen{TrustedProxies: []string{"10.0.0.0/8"}},
		Issuers: []config.Issuer{{
			Name: "ci", Issuer: p.URL, Audiences: []string{"eurodns-gate"},
			BoundClaims: map[string]config.StringList{"repository_owner": {"acme"}},
			NameClaim:   "workflow", TeamClaim: "teams", Category: "pipeline",
			Algorithms: config.DefaultAlgorithms, ClockSkew: config.Duration(time.Minute),
		}},
		Roles: map[string]config.Role{"writer": {}, "acme-solver": {}},
		Bindings: []config.Binding{{
			Role: "writer", Team: "web",
			Subjects: []config.Subject{{Issuer: "ci", Claims: map[string]config.StringList{"sub": {"repo:acme/web:*"}}}},
		}},
		VirtualKeys: []config.VirtualKey{
			{ID: "caddy", AppID: "vk-caddy", KeySHA256: hex.EncodeToString(sum[:]), Roles: []string{"acme-solver"}, Teams: []string{"platform"}, ExpiresAt: &exp, AllowedCIDRs: []string{"192.0.2.0/24"}},
			{ID: "old", AppID: "vk-old", KeySHA256: hex.EncodeToString(sum[:]), Roles: []string{"acme-solver"}, ExpiresAt: &past},
		},
	}
	a, err := New(c, p.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, p
}

func bearer(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/dns-zones/example.com", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func good() map[string]any {
	return map[string]any{"sub": "repo:acme/web:ref:refs/heads/main", "aud": "eurodns-gate", "repository_owner": "acme", "workflow": "deploy", "teams": []any{"Edge"}}
}

func status(err error) int {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

func TestBearerOK(t *testing.T) {
	a, p := setup(t)
	s, err := a.Authenticate(bearer(p.Sign(good())))
	if err != nil {
		t.Fatal(err)
	}
	if s.Issuer != "ci" || s.Name != "deploy" || s.Category != identity.CategoryPipeline || s.Kind != identity.KindOIDC {
		t.Fatalf("subject %+v", s)
	}
	if len(s.Roles) != 1 || s.Roles[0] != "writer" || strings.Join(s.Teams, ",") != "web,edge" {
		t.Fatalf("binding %+v %+v", s.Roles, s.Teams)
	}
	if s.String() != "ci:repo:acme/web:ref:refs/heads/main" {
		t.Fatal(s.String())
	}
}

func TestBearerRejected(t *testing.T) {
	a, p := setup(t)
	mod := func(f func(map[string]any)) string {
		c := good()
		f(c)
		return p.Sign(c)
	}
	cases := map[string]struct {
		tok  string
		want int
	}{
		"wrong audience": {mod(func(c map[string]any) { c["aud"] = "other" }), 401},
		"expired":        {mod(func(c map[string]any) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() }), 401},
		"not yet valid":  {mod(func(c map[string]any) { c["nbf"] = time.Now().Add(10 * time.Minute).Unix() }), 401},
		"untrusted iss":  {mod(func(c map[string]any) { c["iss"] = "https://evil.example.net" }), 401},
		"bound claims":   {mod(func(c map[string]any) { c["repository_owner"] = "evil" }), 403},
		"no binding":     {mod(func(c map[string]any) { c["sub"] = "repo:acme/other:ref:main" }), 403},
		"garbage":        {"not.a.jwt", 401},
	}
	for name, c := range cases {
		if _, err := a.Authenticate(bearer(c.tok)); status(err) != c.want {
			t.Errorf("%s: got %v, want %d", name, err, c.want)
		}
	}
}

func TestHMACTokenRefused(t *testing.T) {
	a, p := setup(t)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	c := good()
	c["iss"] = p.URL
	c["exp"] = time.Now().Add(time.Hour).Unix()
	tok, _ := jwt.Signed(signer).Claims(c).Serialize()
	if _, err := a.Authenticate(bearer(tok)); status(err) != 401 {
		t.Fatalf("HS256 must be refused: %v", err)
	}
}

func TestForeignKeyRefused(t *testing.T) {
	a, _ := setup(t)
	other := oidctest.New()
	defer other.Close()
	// Trusted issuer claim, signed by an unknown key.
	c := good()
	c["iss"] = a.byName["ci"].cfg.Issuer
	if _, err := a.Authenticate(bearer(other.Sign(c))); status(err) != 401 {
		t.Fatalf("token signed by an unknown key must be refused: %v", err)
	}
}

func vkRequest(app, key, remote string) *http.Request {
	r := httptest.NewRequest("GET", "/dns-zones/example.com", nil)
	r.Header.Set("X-APP-ID", app)
	r.Header.Set("X-API-KEY", key)
	r.RemoteAddr = remote
	return r
}

func TestVirtualKeys(t *testing.T) {
	a, _ := setup(t)
	s, err := a.Authenticate(vkRequest("vk-caddy", "vk-secret", "192.0.2.10:1234"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Category != identity.CategoryKey || s.Name != "caddy" || s.Teams[0] != "platform" || s.Kind != identity.KindVirtualKey {
		t.Fatalf("subject %+v", s)
	}
	if _, err := a.Authenticate(vkRequest("vk-caddy", "wrong", "192.0.2.10:1")); status(err) != 401 {
		t.Error("wrong key accepted")
	}
	if _, err := a.Authenticate(vkRequest("vk-old", "vk-secret", "192.0.2.10:1")); status(err) != 401 {
		t.Error("expired key accepted")
	}
	if _, err := a.Authenticate(vkRequest("vk-caddy", "vk-secret", "198.51.100.1:1")); status(err) != 403 {
		t.Error("key accepted from a disallowed address")
	}
	// Through a trusted proxy, the forwarded address is used.
	r := vkRequest("vk-caddy", "vk-secret", "10.1.2.3:1")
	r.Header.Set("X-Forwarded-For", "192.0.2.77, 10.9.9.9")
	if _, err := a.Authenticate(r); err != nil {
		t.Errorf("forwarded address not honoured: %v", err)
	}
	// From an untrusted peer, X-Forwarded-For is ignored.
	r = vkRequest("vk-caddy", "vk-secret", "198.51.100.1:1")
	r.Header.Set("X-Forwarded-For", "192.0.2.77")
	if _, err := a.Authenticate(r); status(err) != 403 {
		t.Error("spoofed X-Forwarded-For honoured")
	}
}

func TestMixedCredentialsRefused(t *testing.T) {
	a, p := setup(t)
	r := bearer(p.Sign(good()))
	r.Header.Set("X-API-KEY", "x")
	if _, err := a.Authenticate(r); status(err) != 401 {
		t.Fatal("mixed credentials accepted")
	}
}

func TestMiddlewareStripsCredentials(t *testing.T) {
	a, p := setup(t)
	var seen http.Header
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		if identity.From(r.Context()) == nil {
			t.Error("subject missing")
		}
	}), func(w http.ResponseWriter, r *http.Request, e *Error) { w.WriteHeader(e.Status) })
	r := bearer(p.Sign(good()))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen.Get("Authorization") != "" {
		t.Fatal("Authorization forwarded")
	}
}

func TestSubjectFromClaims(t *testing.T) {
	a, _ := setup(t)
	s, err := a.SubjectFromClaims("ci", good(), identity.CategoryHuman)
	if err != nil || s.Category != identity.CategoryHuman {
		t.Fatalf("%v %+v", err, s)
	}
	c := good()
	c["repository_owner"] = "evil"
	if _, err := a.SubjectFromClaims("ci", c, ""); status(err) != 403 {
		t.Fatal("bound claims not enforced on UI subjects")
	}
}
