package authn

import (
	"testing"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/oidctest"
)

const (
	tid      = "11111111-2222-3333-4444-555555555555"
	gateApp  = "99999999-8888-7777-6666-555555555555"
	miOID    = "aaaaaaaa-0000-0000-0000-000000000001"
	adoOID   = "aaaaaaaa-0000-0000-0000-000000000002"
	userOID  = "aaaaaaaa-0000-0000-0000-000000000003"
	miAppID  = "bbbbbbbb-0000-0000-0000-000000000001"
	adoAppID = "bbbbbbbb-0000-0000-0000-000000000002"
)

// entraSetup simulates an Entra tenant: the local provider plays the
// issuer, tokens carry Entra claims (tid, oid, azp/appid, roles, idtyp).
func entraSetup(t *testing.T) (*Authenticator, *oidctest.Provider) {
	t.Helper()
	p := oidctest.New()
	t.Cleanup(p.Close)
	c := &config.Config{
		Issuers: []config.Issuer{{
			Name: "entra", Issuer: p.URL, Audiences: []string{"api://eurodns-gate", gateApp},
			SubjectTemplate: "{{tid}}/{{oid}}",
			BoundClaims:     map[string]config.StringList{"tid": {tid}},
			CategoryClaim:   "idtyp", CategoryMap: map[string]string{"app": "pipeline", "user": "human"},
			Category: "pipeline", NameClaim: "name",
			Algorithms: config.DefaultAlgorithms, ClockSkew: config.Duration(time.Minute),
		}},
		Roles: map[string]config.Role{"writer": {}, "reader": {}, "admin": {}},
		Bindings: []config.Binding{
			// Managed identity, by object id.
			{Role: "writer", Team: "web", Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"oid": {miOID}}}}},
			// Any app holding the Entra app role DNS.Write.
			{Role: "writer", Team: "platform", Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"roles": {"DNS.Write"}, "idtyp": {"app"}}}}},
			// Humans with the DNS.Admin app role.
			{Role: "admin", Team: "dns", Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"roles": {"DNS.Admin"}, "idtyp": {"user"}}}}},
			{Role: "reader", Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"roles": {"DNS.Read*"}}}}},
		},
	}
	a, err := New(c, p.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, p
}

func TestEntraV2AppToken(t *testing.T) {
	a, p := entraSetup(t)
	tok := p.Sign(map[string]any{
		"ver": "2.0", "aud": gateApp, "tid": tid, "oid": adoOID, "sub": adoOID,
		"azp": adoAppID, "idtyp": "app", "roles": []any{"DNS.Reader", "DNS.Write"},
	})
	s, err := a.Authenticate(bearer(tok))
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != tid+"/"+adoOID || s.Category != identity.CategoryPipeline {
		t.Fatalf("subject %+v", s)
	}
	if len(s.Roles) != 2 || s.Roles[0] != "reader" || s.Roles[1] != "writer" || s.Teams[0] != "platform" {
		t.Fatalf("roles %v teams %v", s.Roles, s.Teams)
	}
}

func TestEntraV1ManagedIdentity(t *testing.T) {
	a, p := entraSetup(t)
	tok := p.Sign(map[string]any{
		"ver": "1.0", "aud": "api://eurodns-gate", "tid": tid, "oid": miOID, "sub": miOID,
		"appid": miAppID, "idtyp": "app",
	})
	s, err := a.Authenticate(bearer(tok))
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != tid+"/"+miOID || s.Roles[0] != "writer" || s.Teams[0] != "web" {
		t.Fatalf("subject %+v", s)
	}
}

func TestEntraUserToken(t *testing.T) {
	a, p := entraSetup(t)
	tok := p.Sign(map[string]any{
		"aud": gateApp, "tid": tid, "oid": userOID, "sub": "pairwise-sub", "idtyp": "user",
		"name": "Alice", "roles": []any{"DNS.Admin"},
	})
	s, err := a.Authenticate(bearer(tok))
	if err != nil {
		t.Fatal(err)
	}
	if s.Category != identity.CategoryHuman || s.Name != "Alice" || s.Roles[0] != "admin" {
		t.Fatalf("subject %+v", s)
	}
	// The same app role on an app token does not grant admin (idtyp bound).
	tok = p.Sign(map[string]any{"aud": gateApp, "tid": tid, "oid": adoOID, "idtyp": "app", "roles": []any{"DNS.Admin"}})
	if _, err := a.Authenticate(bearer(tok)); status(err) != 403 {
		t.Fatalf("app token got the user binding: %v", err)
	}
}

func TestEntraRejections(t *testing.T) {
	a, p := entraSetup(t)
	cases := map[string]struct {
		claims map[string]any
		want   int
	}{
		"other tenant":   {map[string]any{"aud": gateApp, "tid": "00000000-0000-0000-0000-000000000000", "oid": miOID}, 403},
		"missing oid":    {map[string]any{"aud": gateApp, "tid": tid, "sub": miOID}, 401},
		"exchange aud":   {map[string]any{"aud": "api://AzureADTokenExchange", "tid": tid, "oid": miOID}, 401},
		"roles mismatch": {map[string]any{"aud": gateApp, "tid": tid, "oid": adoOID, "idtyp": "app", "roles": []any{"DNS.Writer"}}, 403},
		"roles scalar":   {map[string]any{"aud": gateApp, "tid": tid, "oid": adoOID, "idtyp": "app", "roles": "DNS.Write"}, 0},
	}
	for name, c := range cases {
		_, err := a.Authenticate(bearer(p.Sign(c.claims)))
		if status(err) != c.want {
			t.Errorf("%s: got %v, want %d", name, err, c.want)
		}
	}
}

func TestClaimMatchesArrays(t *testing.T) {
	cases := []struct {
		v        any
		patterns []string
		want     bool
	}{
		{[]any{"DNS.Read", "DNS.Write"}, []string{"DNS.Write"}, true},
		{[]any{"DNS.Read"}, []string{"DNS.Write", "DNS.R*"}, true},
		{[]any{}, []string{"*"}, false},
		{[]any{42.0, "x"}, []string{"42"}, false},
		{nil, []string{"*"}, false},
		{"single", []string{"sing*"}, true},
		{true, []string{"true"}, true},
	}
	for _, c := range cases {
		if got := claimMatches(c.v, c.patterns); got != c.want {
			t.Errorf("claimMatches(%v, %v) = %v", c.v, c.patterns, got)
		}
	}
}
