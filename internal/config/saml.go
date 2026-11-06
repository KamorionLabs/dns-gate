package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// UISAML configures the SAML 2.0 login of the UI, an alternative to the
// OIDC login (AWS IAM Identity Center custom SAML applications, for
// instance). The gate is the service provider; sessions keep the NameID as
// "sub" and the mapped attributes as claims, matched by bindings under
// Issuer exactly like OIDC claims. The optional SP key and certificate come
// from the environment.
type UISAML struct {
	// Issuer is the name bindings and groups use for SAML subjects, e.g.
	// identity-center. It must not be the name of a token issuer.
	Issuer string `yaml:"issuer"`
	// EntityID is the SP entity id, the audience the IdP puts in the
	// assertion (Identity Center: "Application SAML audience").
	EntityID string `yaml:"entity_id"`
	// ACSURL is the public URL of the assertion consumer service, ending in
	// /auth/saml/acs; its origin is the origin of the UI.
	ACSURL string `yaml:"acs_url"`
	// IDPMetadataURL or IDPMetadata (inline XML) describes the IdP.
	IDPMetadataURL string `yaml:"idp_metadata_url"`
	IDPMetadata    string `yaml:"idp_metadata"`
	// NameIDFormat requested from the IdP: unspecified (default), email,
	// persistent or transient.
	NameIDFormat string `yaml:"name_id_format"`
	// Attributes maps claim names to SAML attribute names (Name or
	// FriendlyName). Defaults: email, name and groups to the attributes of
	// the same name.
	Attributes map[string]string `yaml:"attributes"`
	// TeamClaim derives teams from a claim, as for OIDC issuers.
	TeamClaim string `yaml:"team_claim"`
	// GroupsFromIdentityStore resolves the "groups" claim server-side when
	// the IdP does not send group membership.
	GroupsFromIdentityStore *IdentityStoreGroups `yaml:"groups_from_identity_store"`

	SPKey  string `yaml:"-"` // DNS_GATE_SAML_SP_KEY(_FILE), PEM, optional
	SPCert string `yaml:"-"` // DNS_GATE_SAML_SP_CERT(_FILE), PEM, with SPKey
}

// IdentityStoreGroups configures the group lookup in an AWS IAM Identity
// Center identity store: the user is found by UserAttribute equal to the
// value of UserClaim, and the display names of the groups they belong to
// become the "groups" claim.
type IdentityStoreGroups struct {
	IdentityStoreID string `yaml:"identity_store_id"`
	Region          string `yaml:"region"`
	// AssumeRoleARN is assumed before the calls, typically a role of the
	// account that holds the identity store (management or delegated
	// administrator account).
	AssumeRoleARN string `yaml:"assume_role_arn"`
	// UserAttribute is userName (default) or email.
	UserAttribute string `yaml:"user_attribute"`
	// UserClaim is the claim holding the looked up value (default sub, the
	// NameID).
	UserClaim string `yaml:"user_claim"`
	// CacheTTL is how long the groups of a user are cached per instance
	// (default 5m, at most 1h).
	CacheTTL Duration `yaml:"cache_ttl"`
}

// SAML name id formats accepted in ui.saml.name_id_format.
var samlNameIDFormats = map[string]bool{"unspecified": true, "email": true, "persistent": true, "transient": true}

// DefaultSAMLAttributes are the attribute mappings used when ui.saml does
// not set them.
var DefaultSAMLAttributes = map[string]string{"email": "email", "name": "name", "groups": "groups"}

// SAMLACSPath and SAMLMetadataPath are the SAML endpoints of the gate.
const (
	SAMLACSPath      = "/auth/saml/acs"
	SAMLMetadataPath = "/auth/saml/metadata"
)

// DefaultTokenTTL is the lifetime of gate-issued tokens.
const DefaultTokenTTL = time.Hour

var (
	identityStoreIDRe = regexp.MustCompile(`^d-[0-9a-f]{10}$`)
	claimNameRe       = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

// AllIssuers returns the configured token issuers followed by the subject
// issuer of the SAML login, if any: every issuer name bindings may use.
func (c *Config) AllIssuers() []Issuer {
	out := append([]Issuer(nil), c.Issuers...)
	if s := c.UI.SAML; s != nil && s.Issuer != "" {
		for _, is := range c.Issuers {
			if is.Name == s.Issuer {
				return out
			}
		}
		out = append(out, Issuer{
			Name: s.Issuer, Category: "human", SubjectClaim: "sub", NameClaim: "name",
			TeamClaim: s.TeamClaim, SAML: true,
		})
	}
	return out
}

// SelfIssuer returns the gate's own token issuer, nil when none is configured.
func (c *Config) SelfIssuer() *Issuer {
	for i := range c.Issuers {
		if c.Issuers[i].Self {
			return &c.Issuers[i]
		}
	}
	return nil
}

// SAMLAttributes returns the claim to attribute mapping of the SAML login.
func (s *UISAML) SAMLAttributes() map[string]string {
	out := map[string]string{}
	for k, v := range DefaultSAMLAttributes {
		out[k] = v
	}
	for k, v := range s.Attributes {
		out[k] = v
	}
	return out
}

// ParseTokenSigningKey parses the PEM signing key of gate-issued tokens: an
// EC P-256 key (SEC 1 or PKCS #8) or an Ed25519 key (PKCS #8).
func ParseTokenSigningKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block expected")
	}
	var key any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("EC key must use the P-256 curve")
		}
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("EC P-256 or Ed25519 key expected")
	}
}

func (c *Config) applySAMLEnv(read func(string) (string, error)) error {
	var err error
	if s := c.UI.SAML; s != nil {
		if s.SPKey, err = read("DNS_GATE_SAML_SP_KEY"); err != nil {
			return err
		}
		if s.SPCert, err = read("DNS_GATE_SAML_SP_CERT"); err != nil {
			return err
		}
	}
	if is := c.SelfIssuer(); is != nil {
		k, err := read("DNS_GATE_TOKEN_SIGNING_KEY")
		if err != nil {
			return err
		}
		is.SigningKey = []byte(k)
	}
	return nil
}

func (c *Config) samlDefaults() {
	if s := c.UI.SAML; s != nil {
		if s.NameIDFormat == "" {
			s.NameIDFormat = "unspecified"
		}
		if g := s.GroupsFromIdentityStore; g != nil {
			if g.UserAttribute == "" {
				g.UserAttribute = "userName"
			}
			if g.UserClaim == "" {
				g.UserClaim = "sub"
			}
			if g.CacheTTL == 0 {
				g.CacheTTL = Duration(5 * time.Minute)
			}
		}
	}
	for i := range c.Issuers {
		is := &c.Issuers[i]
		if !is.Self {
			continue
		}
		is.Issuer = strings.TrimSuffix(is.Issuer, "/")
		if len(is.Audiences) == 0 && is.Issuer != "" {
			is.Audiences = []string{is.Issuer}
		}
		if is.Category == "" {
			is.Category = "human"
		}
		if is.TokenTTL == 0 {
			is.TokenTTL = Duration(DefaultTokenTTL)
		}
	}
}

// validateSelfIssuer checks the gate's own issuer.
func validateSelfIssuer(at string, is Issuer) []string {
	var errs []string
	if u, err := url.Parse(is.Issuer); err == nil && u.Path != "" && u.Path != "/" {
		errs = append(errs, at+".issuer: the gate issuer is its public origin, without a path")
	}
	if is.JWKSURL != "" {
		errs = append(errs, at+".jwks_url: not used by the gate issuer")
	}
	if len(is.SigningKey) == 0 {
		errs = append(errs, at+": signing key missing (DNS_GATE_TOKEN_SIGNING_KEY or DNS_GATE_TOKEN_SIGNING_KEY_FILE)")
	} else if _, err := ParseTokenSigningKey(is.SigningKey); err != nil {
		errs = append(errs, fmt.Sprintf("%s: DNS_GATE_TOKEN_SIGNING_KEY: %v", at, err))
	}
	if d := is.TokenTTL.D(); d < time.Minute || d > 24*time.Hour {
		errs = append(errs, at+".token_ttl: must be between 1m and 24h")
	}
	return errs
}

// validateSAML checks ui.saml; issuers are the names of the token issuers.
func validateSAML(c *Config, issuers map[string]bool) []string {
	s := c.UI.SAML
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if !c.UI.Enabled {
		add("ui.saml: requires ui.enabled")
	}
	if c.UI.Issuer != "" || c.UI.ClientID != "" || c.UI.RedirectURL != "" {
		add("ui.saml: the OIDC login settings (ui.issuer, ui.client_id, ui.redirect_url) and ui.saml are exclusive")
	}
	if !nameRe.MatchString(s.Issuer) {
		add("ui.saml.issuer: %q must be a lowercase identifier", s.Issuer)
	} else if issuers[s.Issuer] {
		add("ui.saml.issuer: %q is already the name of a token issuer", s.Issuer)
	}
	if s.EntityID == "" || len(s.EntityID) > 1024 {
		add("ui.saml.entity_id: required (at most 1024 characters)")
	}
	if u, err := url.Parse(s.ACSURL); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
		add("ui.saml.acs_url: https URL required")
	} else if u.Path != SAMLACSPath || u.RawQuery != "" {
		add("ui.saml.acs_url: path must be %s", SAMLACSPath)
	}
	switch {
	case (s.IDPMetadataURL == "") == (s.IDPMetadata == ""):
		add("ui.saml: exactly one of idp_metadata_url and idp_metadata is required")
	case s.IDPMetadataURL != "":
		if u, err := url.Parse(s.IDPMetadataURL); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
			add("ui.saml.idp_metadata_url: https URL required")
		}
	}
	if !samlNameIDFormats[s.NameIDFormat] {
		add("ui.saml.name_id_format: %q (expected unspecified, email, persistent or transient)", s.NameIDFormat)
	}
	for claim, attr := range s.Attributes {
		if !claimNameRe.MatchString(claim) || claim == "sub" || attr == "" || len(attr) > 512 {
			add("ui.saml.attributes: %q: a claim name other than sub and an attribute name are required", claim)
		}
	}
	if (s.SPKey == "") != (s.SPCert == "") {
		add("ui.saml: DNS_GATE_SAML_SP_KEY and DNS_GATE_SAML_SP_CERT go together")
	}
	if g := s.GroupsFromIdentityStore; g != nil {
		if !identityStoreIDRe.MatchString(g.IdentityStoreID) {
			add("ui.saml.groups_from_identity_store.identity_store_id: d-xxxxxxxxxx expected, got %q", g.IdentityStoreID)
		}
		if !awsRegionRe.MatchString(g.Region) {
			add("ui.saml.groups_from_identity_store.region: AWS region expected, got %q", g.Region)
		}
		if g.AssumeRoleARN != "" && !roleARNRe.MatchString(g.AssumeRoleARN) {
			add("ui.saml.groups_from_identity_store.assume_role_arn: IAM role ARN expected")
		}
		if g.UserAttribute != "userName" && g.UserAttribute != "email" {
			add("ui.saml.groups_from_identity_store.user_attribute: userName or email expected, got %q", g.UserAttribute)
		}
		if !claimNameRe.MatchString(g.UserClaim) {
			add("ui.saml.groups_from_identity_store.user_claim: claim name expected")
		}
		if d := g.CacheTTL.D(); d < 0 || d > time.Hour {
			add("ui.saml.groups_from_identity_store.cache_ttl: must be between 0 and 1h")
		}
	}
	return errs
}
