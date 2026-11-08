package authn

import (
	"context"
	"errors"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/scope"
)

func delegatedSetup(t *testing.T, requireKnown bool) (*Authenticator, func(map[string]any) string) {
	a, p := setupWith(t, func(c *config.Config) {
		c.Issuers[0].TokenExchange = true
		c.Issuers[0].RequireKnownClient = requireKnown
		c.Issuers[0].DelegatedClients = []config.DelegatedClient{
			{ID: "copilot", Name: "Copilot", AZP: config.StringList{"COPILOT-App"}, Scopes: []string{scope.DNSRead}, Zones: []string{"example.com"}, Surfaces: []string{scope.SurfaceMCP}},
			{ID: "v1", AppID: config.StringList{"v1-app"}, Scopes: []string{scope.DNSPlan, scope.DNSRead}, Surfaces: []string{scope.SurfaceAPI}},
		}
	})
	return a, func(extra map[string]any) string {
		c := map[string]any{"sub": "repo:acme/web:ref:refs/heads/main", "aud": "dns-gate", "repository_owner": "acme", "workflow": "deploy"}
		for k, v := range extra {
			c[k] = v
		}
		return p.Sign(c)
	}
}

func reasonOf(err error) string {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ""
}

func TestDelegatedClientMatch(t *testing.T) {
	a, sign := delegatedSetup(t, false)

	r := bearer(sign(map[string]any{"azp": "copilot-app"}))
	ctx := audit.WithRequest(r.Context(), audit.Request{})
	r = r.WithContext(ctx)
	s, err := a.AuthenticateFor(r, scope.SurfaceMCP)
	if err != nil || s.Client == nil || s.Client.ID != "copilot" || s.Client.Name != "Copilot" || len(s.Scopes) != 1 || s.String() != "ci:repo:acme/web:ref:refs/heads/main" {
		t.Fatalf("azp client: %+v %v", s, err)
	}
	if audit.AuthMethodFrom(ctx) != audit.AuthOAuthDelegated {
		t.Fatalf("auth method: %q", audit.AuthMethodFrom(ctx))
	}
	e := audit.Event{}
	audit.Prepare(ctx, &e)
	if e.ClientID != "copilot" || e.Actor == nil || e.Actor.Name != "Copilot" || e.Actor.Type != audit.ActorOAuthClient {
		t.Fatalf("audit client: %+v", e)
	}

	if _, err := a.AuthenticateFor(bearer(sign(map[string]any{"azp": "copilot-app"})), scope.SurfaceAPI); reasonOf(err) != "not_delegable" {
		t.Fatalf("surface: %v", err)
	}
	if _, err := a.Authenticate(bearer(sign(map[string]any{"azp": "copilot-app"}))); reasonOf(err) != "not_delegable" {
		t.Fatalf("Authenticate refuses delegated clients: %v", err)
	}
	s, err = a.AuthenticateFor(bearer(sign(map[string]any{"appid": "v1-app"})), scope.SurfaceAPI)
	if err != nil || s.ClientID() != "v1" {
		t.Fatalf("appid client: %+v %v", s, err)
	}
	if s, err := a.AuthenticateFor(bearer(sign(map[string]any{"azp": "V1-APP"})), scope.SurfaceAPI); err != nil || s.ClientID() != "v1" {
		t.Fatalf("client ids match on azp or appid, ignoring case: %+v %v", s, err)
	}
	if s, err := a.AuthenticateFor(bearer(sign(map[string]any{"appid": "copilot-app"})), scope.SurfaceMCP); err != nil || s.ClientID() != "copilot" {
		t.Fatalf("a v1 token of an azp client: %+v %v", s, err)
	}
	if s, err := a.AuthenticateFor(bearer(sign(map[string]any{"azp": "other", "appid": "v1-app"})), scope.SurfaceAPI); err != nil || s.Client != nil {
		t.Fatalf("azp wins over appid: %+v %v", s, err)
	}
	if s, err := a.Authenticate(bearer(sign(nil))); err != nil || s.Client != nil {
		t.Fatalf("no client: %+v %v", s, err)
	}

	if _, err := a.ExchangeToken(context.Background(), sign(map[string]any{"azp": "copilot-app"})); reasonOf(err) != "not_delegable" {
		t.Fatalf("token exchange of a delegated token: %v", err)
	}
	if x, err := a.ExchangeToken(context.Background(), sign(map[string]any{"azp": "unknown"})); err != nil || x.Subject.Client != nil {
		t.Fatalf("token exchange without client: %v", err)
	}
	r = bearer("")
	if _, err := a.AuthenticateBearer(r, sign(map[string]any{"azp": "copilot-app"})); reasonOf(err) != "not_delegable" {
		t.Fatalf("ACME bearer: %v", err)
	}
}

func TestRequireKnownClientAuthn(t *testing.T) {
	a, sign := delegatedSetup(t, true)
	for name, tok := range map[string]string{"unknown": sign(map[string]any{"azp": "x"}), "none": sign(nil)} {
		if _, err := a.AuthenticateFor(bearer(tok), scope.SurfaceAPI); reasonOf(err) != "unknown_client" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := a.ExchangeToken(context.Background(), sign(nil)); reasonOf(err) != "unknown_client" {
		t.Errorf("exchange: %v", err)
	}
}

func TestRebindDelegated(t *testing.T) {
	a, sign := delegatedSetup(t, true)
	s, err := a.AuthenticateFor(bearer(sign(map[string]any{"appid": "v1-app"})), scope.SurfaceAPI)
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.Rebind(s)
	if err != nil || b.ClientID() != "v1" || len(b.Scopes) != 2 {
		t.Fatalf("rebind: %+v %v", b, err)
	}
	s.Client.ID = "gone"
	if _, err := a.Rebind(s); err == nil {
		t.Fatal("rebind of a removed client")
	}
}
