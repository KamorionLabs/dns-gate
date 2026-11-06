package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
)

func gateSetup(t *testing.T) (*Authenticator, ed25519.PrivateKey) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	c := &config.Config{
		Issuers: []config.Issuer{{
			Name: "gate", Self: true, Issuer: "https://dns.example.com", Audiences: []string{"https://dns.example.com"},
			Category: "human", Algorithms: config.DefaultAlgorithms, ClockSkew: config.Duration(time.Minute),
			TokenTTL: config.Duration(time.Hour), SigningKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		}},
		UI:    config.UI{SAML: &config.UISAML{Issuer: "identity-center", TeamClaim: "team"}},
		Roles: map[string]config.Role{"writer": {}},
		Bindings: []config.Binding{{
			Role: "writer", Team: "web",
			Subjects: []config.Subject{{Issuer: "identity-center", Claims: map[string]config.StringList{"groups": {"DNS-Writers"}}}},
		}},
	}
	a, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, key
}

func TestGateTokenRoundTrip(t *testing.T) {
	a, key := gateSetup(t)
	ti := a.TokenIssuer()
	if ti == nil || ti.URL() != "https://dns.example.com" || len(ti.JWKS().Keys) != 1 || ti.JWKS().Keys[0].Algorithm != "EdDSA" {
		t.Fatalf("issuer: %+v", ti)
	}
	now := time.Now()
	claims := map[string]any{"sub": "alice@example.com", "groups": []any{"DNS-Writers"}, "name": "Alice", "team": "Edge", "iss": "spoofed", "exp": 1}
	tok, err := ti.Issue(TokenRequest{Origin: "identity-center", Subject: "alice@example.com", Category: "human", Claims: claims, AuthTime: now.Unix(), AMR: []string{"mfa"}, MaxExpiry: now.Add(30 * time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := tok.Expires.Sub(now); d != 30*time.Minute {
		t.Fatalf("lifetime not capped by the session: %v", d)
	}
	s, err := a.Authenticate(bearer(tok.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if s.Issuer != "identity-center" || s.ID != "alice@example.com" || s.Name != "Alice" || s.Category != identity.CategoryHuman || len(s.Roles) != 1 || len(s.Teams) != 2 || s.Claims["auth_time"] == nil {
		t.Fatalf("subject: %+v", s)
	}

	sign := func(k any, kid string, c map[string]any) string {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: k, KeyID: kid}}, nil)
		raw, _ := jwt.Signed(signer).Claims(c).Serialize()
		return raw
	}
	kid := ti.JWKS().Keys[0].KeyID
	valid := func() map[string]any {
		return map[string]any{"iss": "https://dns.example.com", "aud": "https://dns.example.com", "sub": "alice@example.com", "gate_iss": "identity-center", "groups": []string{"DNS-Writers"}, "exp": now.Add(time.Hour).Unix()}
	}
	if _, err := a.Authenticate(bearer(sign(key, kid, valid()))); err != nil {
		t.Fatalf("hand-made token: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]string{
		"foreign key":     sign(other, kid, valid()),
		"unknown kid":     sign(key, "other", valid()),
		"gate as origin":  sign(key, kid, func() map[string]any { c := valid(); c["gate_iss"] = "gate"; return c }()),
		"no origin":       sign(key, kid, func() map[string]any { c := valid(); delete(c, "gate_iss"); return c }()),
		"wrong audience":  sign(key, kid, func() map[string]any { c := valid(); c["aud"] = "other"; return c }()),
		"expired":         sign(key, kid, func() map[string]any { c := valid(); c["exp"] = now.Add(-time.Hour).Unix(); return c }()),
		"unbound subject": sign(key, kid, func() map[string]any { c := valid(); c["groups"] = []string{"Other"}; return c }()),
	}
	for name, raw := range cases {
		if _, err := a.Authenticate(bearer(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := a.VerifyToken(t.Context(), "identity-center", tok.Raw, []string{"x"}); err == nil {
		t.Fatal("SAML issuer used to verify a token")
	}
	if _, err := ti.Issue(TokenRequest{Origin: "identity-center", Claims: map[string]any{}}, now); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("token without subject: %v", err)
	}
}
