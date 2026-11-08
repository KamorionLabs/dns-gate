package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

func oauthSetup(t *testing.T) (*Authenticator, *config.Config, store.Store) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	c := &config.Config{
		Issuers: []config.Issuer{{
			Name: "gate", Self: true, Issuer: "https://dns.example.com", Audiences: []string{"https://dns.example.com"},
			Category: "human", Algorithms: config.DefaultAlgorithms, ClockSkew: config.Duration(time.Minute),
			TokenTTL: config.Duration(time.Hour), SigningKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		}},
		UI:    config.UI{SAML: &config.UISAML{Issuer: "identity-center"}},
		Roles: map[string]config.Role{"writer": {}},
		Bindings: []config.Binding{{Role: "writer", Team: "web",
			Subjects: []config.Subject{{Issuer: "identity-center", Claims: map[string]config.StringList{"groups": {"DNS-Writers"}}}}}},
		OAuth: config.OAuth{Clients: []config.OAuthClient{
			{ID: "skopea", Name: "Skopea", Scopes: []string{scope.DNSRead, scope.DNSWrite}, Surfaces: []string{scope.SurfaceAPI}, Zones: []string{"example.com"},
				AuthMethod: config.OAuthClientSecretPost, Secret: "0123456789abcdef0123456789abcdef", WriteMaxAge: config.Duration(time.Hour)},
			{ID: "spa", Type: config.OAuthPublic, AuthMethod: config.OAuthNone, Scopes: []string{scope.DNSRead}, Surfaces: []string{scope.SurfaceAPI}},
		}},
	}
	a, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	a.SetOAuthGrants(st)
	return a, c, st
}

func TestDelegatedGateToken(t *testing.T) {
	a, c, st := oauthSetup(t)
	ctx := context.Background()
	now := time.Now()
	grant := store.OAuthGrant{ID: "g-1", ClientID: "skopea", Subject: "identity-center:alice@example.com", Issuer: "identity-center",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.CreateOAuthGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	issue := func(client, grant string, scopes []string, claims map[string]any) string {
		if claims == nil {
			claims = map[string]any{}
		}
		claims["groups"] = []any{"DNS-Writers"}
		tok, err := a.TokenIssuer().Issue(TokenRequest{Origin: "identity-center", Subject: "alice@example.com", Category: "human", Claims: claims,
			AuthTime: now.Unix(), Client: client, Scopes: scopes, Grant: grant}, now)
		if err != nil {
			t.Fatal(err)
		}
		return tok.Raw
	}
	tok := issue("skopea", "g-1", []string{scope.DNSRead, scope.DNSWrite, scope.DNSAdopt}, nil)
	r := bearer(tok)
	rctx := audit.WithRequest(r.Context(), audit.Request{})
	s, err := a.AuthenticateFor(r.WithContext(rctx), scope.SurfaceAPI)
	if err != nil {
		t.Fatal(err)
	}
	if s.Client == nil || s.Client.ID != "skopea" || s.Client.Grant != "g-1" || s.Client.WriteMaxAge != time.Hour || !slices.Equal(s.Scopes, []string{scope.DNSRead, scope.DNSWrite}) || s.String() != "identity-center:alice@example.com" {
		t.Fatalf("subject: %+v %+v", s, s.Client)
	}
	ev := audit.Event{}
	audit.Prepare(rctx, &ev)
	if ev.AuthMethod != audit.AuthOAuthDelegated || ev.ClientID != "skopea" || ev.Extra["grant_id"] != "g-1" {
		t.Fatalf("audit: %+v", ev)
	}
	if _, err := a.Authenticate(bearer(tok)); reasonOf(err) != "not_delegable" {
		t.Fatalf("surface-less endpoint: %v", err)
	}
	if _, err := a.AuthenticateFor(bearer(tok), scope.SurfaceMCP); reasonOf(err) != "not_delegable" {
		t.Fatalf("other surface: %v", err)
	}
	c.OAuth.Clients[0].Scopes = []string{scope.DNSRead}
	if s, _ := a.AuthenticateFor(bearer(tok), scope.SurfaceAPI); s == nil || !slices.Equal(s.Scopes, []string{scope.DNSRead}) {
		t.Fatalf("ceiling lowered in the configuration: %+v", s)
	}
	rb, err := a.Rebind(s)
	if err != nil || rb.Client == nil || rb.Client.Grant != "g-1" || !slices.Equal(rb.Scopes, []string{scope.DNSRead}) {
		t.Fatalf("rebind: %+v %v", rb, err)
	}

	cases := map[string]string{
		"unknown client":   issue("other", "g-1", []string{scope.DNSRead}, nil),
		"unknown grant":    issue("skopea", "g-2", []string{scope.DNSRead}, nil),
		"grant of another": issue("spa", "g-1", []string{scope.DNSRead}, nil),
		"other subject":    issue("skopea", "g-1", []string{scope.DNSRead}, map[string]any{"sub": "bob@example.com"}),
	}
	for name, raw := range cases {
		if _, err := a.AuthenticateFor(bearer(raw), scope.SurfaceAPI); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	c.OAuth.Clients[0].Disabled = true
	if _, err := a.AuthenticateFor(bearer(tok), scope.SurfaceAPI); status(err) != 401 {
		t.Fatalf("disabled client: %v", err)
	}
	if _, err := a.Rebind(s); err == nil {
		t.Fatal("rebind of a disabled client")
	}
	c.OAuth.Clients[0].Disabled = false

	g, _ := st.GetOAuthGrant(ctx, "g-1")
	rev := now
	g.RevokedAt = &rev
	if err := st.UpdateOAuthGrant(ctx, *g); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthenticateFor(bearer(tok), scope.SurfaceAPI); err != nil {
		t.Fatalf("cached grant: %v", err)
	}
	a.SetClock(func() time.Time { return now.Add(GrantCacheTTL + time.Second) })
	if _, err := a.AuthenticateFor(bearer(tok), scope.SurfaceAPI); status(err) != 401 {
		t.Fatalf("revoked grant after the cache: %v", err)
	}
}

func TestSessionClaimsNeverMakeAClientToken(t *testing.T) {
	a, _, _ := oauthSetup(t)
	now := time.Now()
	claims := map[string]any{"groups": []any{"DNS-Writers"}, "client_id": "skopea", "scope": "dns.write", "gate_grant": "g-1", "act": map[string]any{"sub": "x"}}
	tok, err := a.TokenIssuer().Issue(TokenRequest{Origin: "identity-center", Subject: "alice@example.com", Category: "human", Claims: claims}, now)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Authenticate(bearer(tok.Raw))
	if err != nil || s.Client != nil || s.Claims["client_id"] != nil || s.Claims["scope"] != nil {
		t.Fatalf("session claims copied: %+v %v", s, err)
	}
	if _, err := a.TokenIssuer().Issue(TokenRequest{Origin: "identity-center", Subject: "alice", Client: "skopea"}, now); err == nil {
		t.Fatal("client token without a grant")
	}
}

func TestAuthenticateClient(t *testing.T) {
	a, _, _ := oauthSetup(t)
	log := &recordAudit{}
	a.SetAuditLog(log)
	noJTI := func(context.Context, string, time.Time) error { return errors.New("unused") }
	call := func(f url.Values, user, pass string) (string, *ClientError) {
		r := httptest.NewRequest("POST", "/oauth/token", nil)
		if user != "" {
			r.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
		}
		oc, err := a.AuthenticateClient(r, f, []string{"https://dns.example.com/oauth/token"}, noJTI)
		if oc == nil {
			return "", err
		}
		return oc.ID, err
	}
	secret := "0123456789abcdef0123456789abcdef"
	if id, err := call(url.Values{"client_id": {"skopea"}, "client_secret": {secret}}, "", ""); id != "skopea" || err != nil {
		t.Fatalf("post: %s %v", id, err)
	}
	if id, err := call(url.Values{}, "skopea", secret); id != "skopea" || err != nil {
		t.Fatalf("basic: %s %v", id, err)
	}
	if id, err := call(url.Values{"client_id": {"spa"}}, "", ""); id != "spa" || err != nil {
		t.Fatalf("public: %s %v", id, err)
	}
	bad := map[string]struct {
		f          url.Values
		user, pass string
		code       string
	}{
		"wrong secret":      {url.Values{"client_id": {"skopea"}, "client_secret": {"x"}}, "", "", "invalid_client"},
		"no secret":         {url.Values{"client_id": {"skopea"}}, "", "", "invalid_client"},
		"both methods":      {url.Values{"client_secret": {secret}}, "skopea", secret, "invalid_request"},
		"other client_id":   {url.Values{"client_id": {"spa"}}, "skopea", secret, "invalid_request"},
		"unknown client":    {url.Values{"client_id": {"nope"}, "client_secret": {secret}}, "", "", "invalid_client"},
		"public w/ secret":  {url.Values{"client_id": {"spa"}, "client_secret": {"x"}}, "", "", "invalid_client"},
		"assertion type":    {url.Values{"client_id": {"skopea"}, "client_assertion": {"x"}, "client_assertion_type": {"other"}}, "", "", "invalid_client"},
		"assertion of a pw": {url.Values{"client_id": {"skopea"}, "client_assertion": {"x.y.z"}, "client_assertion_type": {ClientAssertionType}}, "", "", "invalid_client"},
	}
	for name, tc := range bad {
		if _, err := call(tc.f, tc.user, tc.pass); err == nil || err.Code != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(log.events); n == 0 || n > len(bad) {
		t.Fatalf("client failures audited: %d", n)
	}
	for i := 0; i < 20; i++ {
		_, _ = call(url.Values{"client_id": {"skopea"}, "client_secret": {"x"}}, "", "")
	}
	if n := len(log.events); n > len(bad) {
		t.Fatalf("client failures not aggregated: %d", n)
	}
}

type recordAudit struct{ events []audit.Event }

func (r *recordAudit) Log(_ context.Context, e audit.Event) { r.events = append(r.events, e) }
