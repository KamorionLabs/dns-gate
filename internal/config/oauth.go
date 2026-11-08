package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/KamorionLabs/dns-gate/internal/scope"
)

// OAuth configures the applications the gate authorization server signs
// users in for (oauth.clients).
type OAuth struct {
	Clients []OAuthClient `yaml:"clients"`
}

// OAuth client types and authentication methods.
const (
	OAuthConfidential = "confidential"
	OAuthPublic       = "public"

	OAuthPrivateKeyJWT     = "private_key_jwt"
	OAuthClientSecretPost  = "client_secret_post"
	OAuthClientSecretBasic = "client_secret_basic"
	OAuthNone              = "none"
)

// RelayClientID is the built-in public client of the Claude Desktop
// extension; no declared client may use it.
const RelayClientID = "dns-gate-relay"

// Defaults and bounds of declared OAuth clients.
const (
	DefaultOAuthAccessTTL   = 10 * time.Minute
	DefaultOAuthRefreshIdle = 14 * 24 * time.Hour
	DefaultOAuthRefreshMax  = 90 * 24 * time.Hour
	MaxOAuthRefreshTTL      = 180 * 24 * time.Hour
	DefaultOAuthClaimsAge   = 7 * 24 * time.Hour
	minOAuthSecretLen       = 32
)

// OAuthClient is an application declared at the gate authorization server:
// it obtains, with the consent of a signed-in user, gate tokens that hold
// the rights of the user capped by Scopes, Zones and Surfaces.
type OAuthClient struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	AuthMethod string `yaml:"auth_method"`
	JWKSURI    string `yaml:"jwks_uri"`
	// JWKS is an inline public key set (private_key_jwt), as YAML.
	JWKS          map[string]any `yaml:"jwks"`
	RedirectURIs  []string       `yaml:"redirect_uris"`
	Scopes        []string       `yaml:"scopes"`
	DefaultScopes []string       `yaml:"default_scopes"`
	Zones         []string       `yaml:"zones"`
	Surfaces      []string       `yaml:"surfaces"`

	AccessTokenTTL Duration `yaml:"access_token_ttl"`
	RefreshIdleTTL Duration `yaml:"refresh_idle_ttl"`
	RefreshMaxTTL  Duration `yaml:"refresh_max_ttl"`
	ClaimsMaxAge   Duration `yaml:"claims_max_age"`
	WriteMaxAge    Duration `yaml:"write_max_age"`
	RequirePKCE    *bool    `yaml:"require_pkce"`
	Disabled       bool     `yaml:"disabled"`

	// Secret is the client secret of the client_secret_* methods:
	// DNS_GATE_OAUTH_CLIENT_<ID>_SECRET(_FILE), never in the file.
	Secret string `yaml:"-"`
	// KeySet is the parsed inline JWKS.
	KeySet *jose.JSONWebKeySet `yaml:"-"`
}

// SecretEnv is the environment variable holding the secret of a client.
func (c OAuthClient) SecretEnv() string { return "DNS_GATE_OAUTH_CLIENT_" + envName(c.ID) + "_SECRET" }

// Confidential reports whether the client authenticates at the token
// endpoint.
func (c OAuthClient) Confidential() bool { return c.Type != OAuthPublic }

// UsesSecret reports whether the client authenticates with a secret.
func (c OAuthClient) UsesSecret() bool {
	return c.AuthMethod == OAuthClientSecretPost || c.AuthMethod == OAuthClientSecretBasic
}

// OAuthClient returns the declared client id, nil when unknown.
func (c *Config) OAuthClient(id string) *OAuthClient {
	for i := range c.OAuth.Clients {
		if c.OAuth.Clients[i].ID == id {
			return &c.OAuth.Clients[i]
		}
	}
	return nil
}

func (c *Config) applyOAuthEnv(read func(string) (string, error)) error {
	for i := range c.OAuth.Clients {
		oc := &c.OAuth.Clients[i]
		v, err := read(oc.SecretEnv())
		if err != nil {
			return err
		}
		oc.Secret = v
	}
	return nil
}

func (c *Config) oauthDefaults() {
	for i := range c.OAuth.Clients {
		oc := &c.OAuth.Clients[i]
		if oc.Name == "" {
			oc.Name = oc.ID
		}
		if oc.Type == "" {
			oc.Type = OAuthConfidential
		}
		if oc.AuthMethod == "" && oc.Type == OAuthPublic {
			oc.AuthMethod = OAuthNone
		}
		if len(oc.Surfaces) == 0 {
			oc.Surfaces = []string{scope.SurfaceAPI}
		}
		if oc.DefaultScopes == nil && slices.Contains(oc.Scopes, scope.DNSRead) {
			oc.DefaultScopes = []string{scope.DNSRead}
		}
		if oc.AccessTokenTTL == 0 {
			oc.AccessTokenTTL = Duration(DefaultOAuthAccessTTL)
		}
		if oc.RefreshIdleTTL == 0 {
			oc.RefreshIdleTTL = Duration(DefaultOAuthRefreshIdle)
		}
		if oc.RefreshMaxTTL == 0 {
			oc.RefreshMaxTTL = Duration(DefaultOAuthRefreshMax)
		}
		if oc.ClaimsMaxAge == 0 {
			oc.ClaimsMaxAge = Duration(DefaultOAuthClaimsAge)
		}
	}
}

// validateOAuth checks oauth.clients.
func (c *Config) validateOAuth(add func(string, ...any)) {
	if len(c.OAuth.Clients) == 0 {
		return
	}
	self := c.SelfIssuer()
	if self == nil {
		add("oauth.clients: needs the gate issuer (an issuer with self: true) to sign the delegated tokens")
	}
	if !c.UI.Enabled {
		add("oauth.clients: needs the UI login (ui.enabled), where users sign in and consent")
	}
	if c.Store.Type == "memory" {
		add("oauth.clients: needs a persistent store (sqlite, postgres or dynamodb): grants, codes and client assertions are kept in the store")
	}
	if err := c.parseOAuthKeys(); err != nil {
		add("%v", err)
	}
	delegated := map[string]string{}
	for _, is := range c.Issuers {
		for _, dc := range is.DelegatedClients {
			delegated[dc.ID] = is.Name
		}
	}
	ids := map[string]bool{}
	for i, oc := range c.OAuth.Clients {
		at := fmt.Sprintf("oauth.clients[%d]", i)
		switch {
		case !nameRe.MatchString(oc.ID):
			add("%s.id: %q must be a lowercase identifier", at, oc.ID)
		case oc.ID == RelayClientID:
			add("%s.id: %q is the built-in client of the Claude Desktop extension", at, oc.ID)
		case ids[oc.ID]:
			add("%s.id: %q duplicated", at, oc.ID)
		case delegated[oc.ID] != "":
			add("%s.id: %q is already a delegated client of issuer %s", at, oc.ID, delegated[oc.ID])
		}
		ids[oc.ID] = true
		if len(oc.Name) > 128 || strings.ContainsAny(oc.Name, "\r\n") {
			add("%s.name: one line, up to 128 characters", at)
		}
		c.validateOAuthAuth(at, oc, add)
		if len(oc.RedirectURIs) == 0 {
			add("%s.redirect_uris: at least one redirect URI is required", at)
		}
		seen := map[string]bool{}
		for _, ru := range oc.RedirectURIs {
			if err := ValidateRedirectURI(ru); err != nil {
				add("%s.redirect_uris: %q: %v", at, ru, err)
			}
			if seen[ru] {
				add("%s.redirect_uris: %q duplicated", at, ru)
			}
			seen[ru] = true
		}
		if len(oc.Scopes) == 0 {
			add("%s.scopes: at least one scope is required (%s)", at, strings.Join(scope.All, ", "))
		}
		for _, sc := range oc.Scopes {
			if !scope.Valid(sc) {
				add("%s.scopes: unknown scope %q (%s)", at, sc, strings.Join(scope.All, ", "))
			}
		}
		for _, sc := range oc.DefaultScopes {
			if !slices.Contains(oc.Scopes, sc) {
				add("%s.default_scopes: %q is not in scopes", at, sc)
			}
		}
		for _, z := range oc.Zones {
			if z == "" || z != strings.ToLower(z) || strings.HasSuffix(z, ".") || strings.Contains(z, "?") {
				add("%s.zones: %q must be a lowercase zone glob without trailing dot (* wildcards only)", at, z)
			}
		}
		for _, sf := range oc.Surfaces {
			if !scope.ValidSurface(sf) {
				add("%s.surfaces: unknown surface %q (%s)", at, sf, strings.Join(scope.Surfaces, ", "))
			}
		}
		if oc.RequirePKCE != nil && !*oc.RequirePKCE {
			add("%s.require_pkce: PKCE is always required", at)
		}
		maxAccess := DefaultTokenTTL
		if self != nil && self.TokenTTL > 0 {
			maxAccess = self.TokenTTL.D()
		}
		if d := oc.AccessTokenTTL.D(); d < time.Minute || d > maxAccess {
			add("%s.access_token_ttl: between 1m and the token_ttl of the gate issuer (%s)", at, maxAccess)
		}
		if d := oc.RefreshMaxTTL.D(); d < time.Hour || d > MaxOAuthRefreshTTL {
			add("%s.refresh_max_ttl: between 1h and 180d", at)
		}
		if d := oc.RefreshIdleTTL.D(); d < time.Hour || d > oc.RefreshMaxTTL.D() {
			add("%s.refresh_idle_ttl: between 1h and refresh_max_ttl", at)
		}
		if d := oc.ClaimsMaxAge.D(); d < time.Hour || d > oc.RefreshMaxTTL.D() {
			add("%s.claims_max_age: between 1h and refresh_max_ttl", at)
		}
		if d := oc.WriteMaxAge.D(); d != 0 && (d < time.Minute || d > oc.RefreshMaxTTL.D()) {
			add("%s.write_max_age: between 1m and refresh_max_ttl (0: none)", at)
		}
	}
}

func (c *Config) validateOAuthAuth(at string, oc OAuthClient, add func(string, ...any)) {
	switch oc.Type {
	case OAuthConfidential:
		switch oc.AuthMethod {
		case OAuthPrivateKeyJWT, OAuthClientSecretPost, OAuthClientSecretBasic:
		case "":
			add("%s.auth_method: required for a confidential client (%s, %s or %s)", at, OAuthPrivateKeyJWT, OAuthClientSecretPost, OAuthClientSecretBasic)
		default:
			add("%s.auth_method: %q (expected %s, %s or %s)", at, oc.AuthMethod, OAuthPrivateKeyJWT, OAuthClientSecretPost, OAuthClientSecretBasic)
		}
	case OAuthPublic:
		if oc.AuthMethod != OAuthNone {
			add("%s.auth_method: a public client uses none", at)
		}
	default:
		add("%s.type: %q (expected confidential or public)", at, oc.Type)
	}
	keyed := oc.JWKSURI != "" || len(oc.JWKS) > 0
	if oc.AuthMethod == OAuthPrivateKeyJWT {
		if (oc.JWKSURI != "") == (len(oc.JWKS) > 0) {
			add("%s: private_key_jwt needs jwks_uri or jwks (one of them)", at)
		}
		if oc.JWKSURI != "" {
			if u, err := url.Parse(oc.JWKSURI); err != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" {
				if !(err == nil && u.Scheme == "http" && isLoopback(u.Hostname())) {
					add("%s.jwks_uri: https URL required", at)
				}
			}
		}
	} else if keyed {
		add("%s: jwks_uri and jwks are for private_key_jwt only", at)
	}
	if oc.UsesSecret() {
		if len(oc.Secret) < minOAuthSecretLen {
			add("%s: client secret missing or shorter than %d characters (%s or %s_FILE)", at, minOAuthSecretLen, oc.SecretEnv(), oc.SecretEnv())
		}
	} else if oc.Secret != "" {
		add("%s: %s is set but the client does not use a client secret", at, oc.SecretEnv())
	}
}

// parseOAuthKeys parses the inline JWKS of the clients: public signature
// keys only.
func (c *Config) parseOAuthKeys() error {
	for i := range c.OAuth.Clients {
		oc := &c.OAuth.Clients[i]
		if len(oc.JWKS) == 0 {
			continue
		}
		raw, err := json.Marshal(oc.JWKS)
		if err != nil {
			return fmt.Errorf("oauth.clients[%d].jwks: %w", i, err)
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(raw, &set); err != nil {
			return fmt.Errorf("oauth.clients[%d].jwks: %w", i, err)
		}
		if len(set.Keys) == 0 {
			return fmt.Errorf("oauth.clients[%d].jwks: no key", i)
		}
		for _, k := range set.Keys {
			if !k.IsPublic() || !k.Valid() || (k.Use != "" && k.Use != "sig") {
				return fmt.Errorf("oauth.clients[%d].jwks: public signature keys only", i)
			}
			if _, symmetric := k.Key.([]byte); symmetric {
				return fmt.Errorf("oauth.clients[%d].jwks: public signature keys only", i)
			}
		}
		oc.KeySet = &set
	}
	return nil
}

// ValidateRedirectURI checks a redirect URI of a declared client: an
// absolute https URI without user information, fragment or wildcard.
func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "":
		return fmt.Errorf("absolute URI required")
	case u.Scheme != "https":
		return fmt.Errorf("https required")
	case u.User != nil:
		return fmt.Errorf("no user information")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return fmt.Errorf("no fragment")
	case strings.Contains(raw, "*"):
		return fmt.Errorf("no wildcard: redirect URIs match exactly")
	case strings.ContainsAny(raw, " \t\r\n;,'\"<>\\"):
		return fmt.Errorf("no space, quote or ; , < > \\ characters")
	case len(raw) > 2048:
		return fmt.Errorf("too long")
	}
	return nil
}
