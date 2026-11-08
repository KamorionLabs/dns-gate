package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const jwksBlock = `      jwks:
        keys:
          - {kty: EC, crv: P-256, kid: k1, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", use: sig, alg: ES256}
`

const oauthClients = `oauth:
  clients:
    - id: skopea-acme
      name: "Skopea — Acme"
      auth_method: private_key_jwt
` + jwksBlock + `      redirect_uris: [https://app.skopea.example/api/v1/orgs/acme/dns/oauth/callback]
      scopes: [dns.read, dns.plan, dns.write]
      write_max_age: 12h
    - id: copilot
      auth_method: client_secret_basic
      redirect_uris: [https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect]
      scopes: [dns.read]
      surfaces: [mcp]
      refresh_max_ttl: 30d
`

func oauthDoc() string {
	return withGate(samlBase) + "store: {type: sqlite, sqlite: {path: /var/lib/dns-gate/gate.db}}\n" + oauthClients
}

func oauthVars(t *testing.T) map[string]string {
	v := samlEnvVars(t)
	v["DNS_GATE_OAUTH_CLIENT_COPILOT_SECRET"] = strings.Repeat("s", 40)
	return v
}

func TestOAuthClients(t *testing.T) {
	c, err := Parse([]byte(oauthDoc()), env(oauthVars(t)))
	if err != nil {
		t.Fatal(err)
	}
	sk, cp := c.OAuthClient("skopea-acme"), c.OAuthClient("copilot")
	if sk == nil || cp == nil || sk.KeySet == nil || len(sk.KeySet.Keys) != 1 || sk.Type != OAuthConfidential || !slices.Equal(sk.DefaultScopes, []string{"dns.read"}) ||
		!slices.Equal(sk.Surfaces, []string{"api"}) || sk.AccessTokenTTL.D() != 10*time.Minute || sk.RefreshIdleTTL.D() != 14*24*time.Hour ||
		sk.RefreshMaxTTL.D() != 90*24*time.Hour || sk.ClaimsMaxAge.D() != 7*24*time.Hour || sk.WriteMaxAge.D() != 12*time.Hour {
		t.Fatalf("skopea: %+v", sk)
	}
	if cp.Secret != strings.Repeat("s", 40) || cp.Name != "copilot" || cp.RefreshMaxTTL.D() != 30*24*time.Hour || cp.SecretEnv() != "DNS_GATE_OAUTH_CLIENT_COPILOT_SECRET" {
		t.Fatalf("copilot: %+v", cp)
	}

	vars := oauthVars(t)
	cases := map[string]struct{ from, to, want string }{
		"relay id":            {"id: copilot", "id: dns-gate-relay", "built-in client"},
		"duplicate id":        {"id: copilot", "id: skopea-acme", "duplicated"},
		"http redirect":       {"https://teams.microsoft.com", "http://teams.microsoft.com", "https required"},
		"fragment":            {"oAuthRedirect]", "oAuthRedirect#x]", "no fragment"},
		"wildcard":            {"https://teams.microsoft.com", "https://*.microsoft.com", "wildcard"},
		"relative redirect":   {"[https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect]", "[/callback]", "absolute URI"},
		"unknown scope":       {"scopes: [dns.read]\n", "scopes: [dns.read, dns.zone.admin]\n", "unknown scope"},
		"never delegable":     {"scopes: [dns.read]\n", "scopes: [gate.apikey.manage]\n", "unknown scope"},
		"default not granted": {"scopes: [dns.read]\n", "scopes: [dns.read]\n      default_scopes: [dns.write]\n", "default_scopes"},
		"max ttl above 180d":  {"refresh_max_ttl: 30d", "refresh_max_ttl: 181d", "refresh_max_ttl"},
		"idle above max":      {"refresh_max_ttl: 30d", "refresh_max_ttl: 30d\n      refresh_idle_ttl: 31d", "refresh_idle_ttl"},
		"access ttl":          {"refresh_max_ttl: 30d", "refresh_max_ttl: 30d\n      access_token_ttl: 2h", "access_token_ttl"},
		"pkce off":            {"refresh_max_ttl: 30d", "refresh_max_ttl: 30d\n      require_pkce: false", "PKCE is always required"},
		"no auth method":      {"auth_method: client_secret_basic\n", "type: confidential\n", "auth_method: required"},
		"unknown method":      {"auth_method: client_secret_basic", "auth_method: tls_client_auth", "auth_method"},
		"public with secret":  {"auth_method: client_secret_basic", "type: public\n      auth_method: client_secret_basic", "public client uses none"},
		"jwks and jwks_uri":   {"auth_method: private_key_jwt\n", "auth_method: private_key_jwt\n      jwks_uri: https://app.skopea.example/jwks.json\n", "one of them"},
		"jwks for a secret":   {"auth_method: client_secret_basic\n", "auth_method: client_secret_basic\n      jwks_uri: https://x.example/jwks\n", "private_key_jwt only"},
		"http jwks_uri":       {jwksBlock, "      jwks_uri: http://app.skopea.example/jwks.json\n", "jwks_uri: https URL required"},
		"private jwk":         {`use: sig, alg: ES256}`, `d: "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", use: sig, alg: ES256}`, "public signature keys only"},
		"bad zone":            {"surfaces: [mcp]", "surfaces: [mcp]\n      zones: [Example.com]", "zones"},
		"bad surface":         {"surfaces: [mcp]", "surfaces: [ui]", "unknown surface"},
		"memory store":        {"store: {type: sqlite, sqlite: {path: /var/lib/dns-gate/gate.db}}", "store: {type: memory}", "persistent store"},
		"no gate issuer":      {gateIssuer, "", "gate issuer"},
	}
	for name, tc := range cases {
		doc := strings.Replace(oauthDoc(), tc.from, tc.to, 1)
		if doc == oauthDoc() {
			t.Fatalf("%s: replacement of %q did not apply", name, tc.from)
		}
		_, err := Parse([]byte(doc), env(vars))
		if err == nil || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}

	short := oauthVars(t)
	short["DNS_GATE_OAUTH_CLIENT_COPILOT_SECRET"] = "short"
	if _, err := Parse([]byte(oauthDoc()), env(short)); err == nil || !strings.Contains(err.Error(), "client secret missing or shorter") {
		t.Errorf("short secret: %v", err)
	}
	stray := oauthVars(t)
	stray["DNS_GATE_OAUTH_CLIENT_SKOPEA_ACME_SECRET"] = strings.Repeat("s", 40)
	if _, err := Parse([]byte(oauthDoc()), env(stray)); err == nil || !strings.Contains(err.Error(), "does not use a client secret") {
		t.Errorf("secret of a key client: %v", err)
	}
	clash := strings.Replace(oauthDoc(), "    - id: copilot\n", "    - id: a.b\n      auth_method: private_key_jwt\n      jwks_uri: https://a.example/jwks\n      redirect_uris: [https://a.example/cb]\n      scopes: [dns.read]\n    - id: a-b\n      auth_method: private_key_jwt\n      jwks_uri: https://a.example/jwks\n      redirect_uris: [https://a.example/cb]\n      scopes: [dns.read]\n    - id: copilot\n", 1)
	if _, err := Parse([]byte(clash), env(vars)); err == nil || !strings.Contains(err.Error(), "share the secret variable") {
		t.Errorf("two clients, one secret variable: %v", err)
	}
	doc := strings.Replace(oauthDoc(), "issuers:\n", "issuers:\n  - name: entra\n    issuer: https://login.example.net\n    audiences: [x]\n    delegated_clients: [{id: copilot, azp: abc, scopes: [dns.read]}]\n", 1)
	if _, err := Parse([]byte(doc), env(vars)); err == nil || !strings.Contains(err.Error(), "already a delegated client") {
		t.Errorf("id of a delegated client: %v", err)
	}
}

func TestDurationDays(t *testing.T) {
	for in, want := range map[string]time.Duration{"14d": 14 * 24 * time.Hour, "1d": 24 * time.Hour, "90m": 90 * time.Minute, "36h": 36 * time.Hour} {
		if d, err := ParseDuration(in); err != nil || d != want {
			t.Errorf("%s: %v %v", in, d, err)
		}
	}
	for _, in := range []string{"d", "1.5d", "-1d", "99999d", "1d2h"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}
