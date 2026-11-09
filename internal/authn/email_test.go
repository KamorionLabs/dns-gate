package authn

import (
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

func TestSubjectEmail(t *testing.T) {
	yes, no := true, false
	oidc := config.Issuer{Name: "idp"}
	entra := config.Issuer{Name: "entra", EmailVerifiedClaim: "xms_edov"}
	upn := config.Issuer{Name: "entra", EmailClaim: "upn", EmailTrusted: &yes}
	saml := config.Issuer{Name: "identity-center", SAML: true}
	cases := map[string]struct {
		ic     config.Issuer
		claims map[string]any
		want   string
	}{
		"verified":                       {oidc, map[string]any{"email": "alice@example.com", "email_verified": true}, "alice@example.com"},
		"verified as text":               {oidc, map[string]any{"email": "alice@example.com", "email_verified": "TRUE"}, "alice@example.com"},
		"unverified":                     {oidc, map[string]any{"email": "alice@example.com", "email_verified": false}, ""},
		"verification of another type":   {oidc, map[string]any{"email": "alice@example.com", "email_verified": 1}, ""},
		"no verification claim":          {oidc, map[string]any{"email": "alice@example.com"}, ""},
		"trusted without verification":   {config.Issuer{EmailTrusted: &yes}, map[string]any{"email": "alice@example.com"}, "alice@example.com"},
		"trusted but unverified":         {config.Issuer{EmailTrusted: &yes}, map[string]any{"email": "alice@example.com", "email_verified": false}, ""},
		"untrusted although verified":    {config.Issuer{EmailTrusted: &no}, map[string]any{"email": "alice@example.com", "email_verified": true}, ""},
		"entra xms_edov":                 {entra, map[string]any{"email": "alice@contoso.com", "xms_edov": true}, "alice@contoso.com"},
		"entra without xms_edov":         {entra, map[string]any{"email": "alice@contoso.com", "email_verified": true}, ""},
		"entra upn vouched by the admin": {upn, map[string]any{"upn": "alice@contoso.com", "email": "other@example.net", "preferred_username": "x"}, "alice@contoso.com"},
		"entra upn missing":              {upn, map[string]any{"email": "alice@contoso.com"}, ""},
		"not an address":                 {config.Issuer{EmailTrusted: &yes}, map[string]any{"email": "Alice Doe"}, ""},
		"display name form":              {config.Issuer{EmailTrusted: &yes}, map[string]any{"email": "Alice <alice@example.com>"}, ""},
		"padded":                         {config.Issuer{EmailTrusted: &yes}, map[string]any{"email": " alice@example.com"}, ""},
		"list":                           {config.Issuer{EmailTrusted: &yes}, map[string]any{"email": []any{"alice@example.com"}}, ""},
		"gate token past claims_max_age": {oidc, map[string]any{"email": "alice@example.com", "email_verified": true, ClaimNoEmail: true}, ""},
		"saml attribute":                 {saml, map[string]any{"sub": "alice", "email": "alice@example.com"}, "alice@example.com"},
		"saml email NameID":              {saml, map[string]any{"sub": "alice@example.com", ClaimNameIDFormat: "email"}, "alice@example.com"},
		"saml attribute first":           {saml, map[string]any{"sub": "a@example.com", "email": "alice@example.com", ClaimNameIDFormat: "email"}, "alice@example.com"},
		"saml persistent NameID":         {saml, map[string]any{"sub": "alice@example.com"}, ""},
		"saml unverified attribute":      {saml, map[string]any{"sub": "alice@example.com", "email": "alice@example.com", "email_verified": "false", ClaimNameIDFormat: "email"}, ""},
		"saml past claims_max_age":       {saml, map[string]any{"sub": "alice@example.com", "email": "alice@example.com", ClaimNoEmail: true}, ""},
	}
	for name, c := range cases {
		if got := subjectEmail(c.ic, c.claims); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestBearerEmail(t *testing.T) {
	a, p := entraSetup(t)
	claims := map[string]any{"aud": gateApp, "tid": tid, "oid": userOID, "idtyp": "user", "roles": []any{"DNS.Admin"}, "email": "alice@contoso.com"}
	s, err := a.Authenticate(bearer(p.Sign(claims)))
	if err != nil || s.Email != "" {
		t.Fatalf("Entra email without a verification claim: %v %+v", err, s)
	}
	a.byName["entra"].cfg.EmailVerifiedClaim = "xms_edov"
	claims["xms_edov"] = true
	if s, err = a.Authenticate(bearer(p.Sign(claims))); err != nil || s.Email != "alice@contoso.com" {
		t.Fatalf("Entra email with xms_edov: %v %+v", err, s)
	}
	s, err = a.SubjectFromClaims("entra", claims, "human")
	if err != nil || s.Email != "alice@contoso.com" {
		t.Fatalf("session: %v %+v", err, s)
	}
}
