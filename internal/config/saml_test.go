package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

const samlBase = base + `  - role: writer
    team: web
    subjects:
      - issuer: identity-center
        claims: {groups: [DNS-Writers]}
ui:
  enabled: true
  saml:
    issuer: identity-center
    entity_id: dns-gate
    acs_url: https://dns.example.com/auth/saml/acs
    idp_metadata_url: https://portal.sso.eu-west-3.amazonaws.com/saml/metadata/abc
    groups_from_identity_store:
      identity_store_id: d-1234567890
      region: eu-west-3
      assume_role_arn: arn:aws:iam::123456789012:role/dns-gate-identity-store
`

const gateIssuer = `  - name: gate
    self: true
    issuer: https://dns.example.com
`

func ecPEM(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func samlEnvVars(t *testing.T) map[string]string {
	return map[string]string{"EURODNS_API_KEY": "k", "DNS_GATE_SESSION_KEY": strings.Repeat("ab", 32), "DNS_GATE_TOKEN_SIGNING_KEY": ecPEM(t)}
}

func withGate(doc string) string {
	return strings.Replace(doc, "roles:\n", gateIssuer+"roles:\n", 1)
}

func TestSAMLAndGateIssuer(t *testing.T) {
	c, err := Parse([]byte(withGate(samlBase)), env(samlEnvVars(t)))
	if err != nil {
		t.Fatal(err)
	}
	s := c.UI.SAML
	if s.NameIDFormat != "unspecified" || s.GroupsFromIdentityStore.UserAttribute != "userName" || s.GroupsFromIdentityStore.UserClaim != "sub" || s.GroupsFromIdentityStore.CacheTTL.D() != 5*time.Minute {
		t.Fatalf("saml defaults: %+v %+v", s, s.GroupsFromIdentityStore)
	}
	g := c.SelfIssuer()
	if g == nil || g.Audiences[0] != "https://dns.example.com" || g.TokenTTL.D() != time.Hour || g.Category != "human" || len(g.SigningKey) == 0 {
		t.Fatalf("gate issuer: %+v", g)
	}
	all := c.AllIssuers()
	if last := all[len(all)-1]; !last.SAML || last.Name != "identity-center" || last.Category != "human" {
		t.Fatalf("saml issuer: %+v", last)
	}
	if attrs := s.SAMLAttributes(); attrs["groups"] != "groups" || attrs["email"] != "email" {
		t.Fatalf("attributes: %v", attrs)
	}
}

func TestSAMLValidation(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"oidc and saml":        {strings.Replace(samlBase, "  saml:\n", "  client_id: x\n  saml:\n", 1), "exclusive"},
		"acs path":             {strings.Replace(samlBase, "/auth/saml/acs", "/acs", 1), "path must be /auth/saml/acs"},
		"no metadata":          {strings.Replace(samlBase, "    idp_metadata_url: https://portal.sso.eu-west-3.amazonaws.com/saml/metadata/abc\n", "", 1), "exactly one of"},
		"both metadata":        {strings.Replace(samlBase, "    groups_from", "    idp_metadata: <x/>\n    groups_from", 1), "exactly one of"},
		"http metadata":        {strings.Replace(samlBase, "https://portal", "http://portal", 1), "idp_metadata_url"},
		"name id format":       {strings.Replace(samlBase, "    entity_id", "    name_id_format: x509\n    entity_id", 1), "name_id_format"},
		"store id":             {strings.Replace(samlBase, "d-1234567890", "1234567890", 1), "identity_store_id"},
		"role arn":             {strings.Replace(samlBase, "arn:aws:iam::123456789012:role/", "arn:aws:iam::1234:user/", 1), "assume_role_arn"},
		"issuer clash":         {strings.Replace(samlBase, "    issuer: identity-center\n    entity_id", "    issuer: ci\n    entity_id", 1), "already the name of a token issuer"},
		"sub attribute":        {strings.Replace(samlBase, "    entity_id", "    attributes: {sub: email}\n    entity_id", 1), "attributes"},
		"unknown binding name": {strings.Replace(samlBase, "      - issuer: identity-center", "      - issuer: nobody", 1), "unknown issuer"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc), env(samlEnvVars(t)))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
	vars := samlEnvVars(t)
	vars["DNS_GATE_SAML_SP_KEY"] = "x"
	if _, err := Parse([]byte(samlBase), env(vars)); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("SP key without certificate: %v", err)
	}
}

func TestGateIssuerValidation(t *testing.T) {
	vars := samlEnvVars(t)
	cases := map[string]struct {
		doc  string
		vars map[string]string
		want string
	}{
		"missing key":   {withGate(base), map[string]string{"EURODNS_API_KEY": "k"}, "signing key missing"},
		"rsa key":       {withGate(base), map[string]string{"EURODNS_API_KEY": "k", "DNS_GATE_TOKEN_SIGNING_KEY": "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"}, "unsupported PEM block"},
		"path":          {strings.Replace(withGate(base), "issuer: https://dns.example.com", "issuer: https://dns.example.com/gate", 1), vars, "without a path"},
		"ttl":           {strings.Replace(withGate(base), "    self: true\n", "    self: true\n    token_ttl: 48h\n", 1), vars, "token_ttl"},
		"ttl on oidc":   {strings.Replace(base, "audiences: [dns-gate]", "audiences: [dns-gate]\n    token_ttl: 1h", 1), vars, "only for the gate issuer"},
		"two gates":     {strings.Replace(withGate(base), "roles:\n", strings.ReplaceAll(gateIssuer, "name: gate", "name: gate2")+"roles:\n", 1), vars, "only one gate issuer"},
		"bound as gate": {strings.Replace(withGate(base), "      - issuer: ci", "      - issuer: gate", 1), vars, "unknown issuer \"gate\""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc), env(c.vars))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestParseTokenSigningKey(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(edKey)
	if _, err := ParseTokenSigningKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalECPrivateKey(p384)
	if _, err := ParseTokenSigningKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("P-384 accepted")
	}
}
