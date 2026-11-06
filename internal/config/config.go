// Package config loads and validates the dns-gate configuration.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/KamorionLabs/dns-gate/internal/glob"
)

// Config is the root configuration document.
type Config struct {
	Listen            Listen           `yaml:"listen"`
	Providers         []Provider       `yaml:"providers"`
	Zones             []string         `yaml:"zones"`
	CheckOnWrite      *bool            `yaml:"check_on_write"`
	ReconcileInterval Duration         `yaml:"reconcile_interval"`
	Limits            Limits           `yaml:"limits"`
	Lock              Lock             `yaml:"lock"`
	Store             Store            `yaml:"store"`
	Issuers           []Issuer         `yaml:"issuers"`
	VirtualKeys       []VirtualKey     `yaml:"virtual_keys"`
	Roles             map[string]Role  `yaml:"roles"`
	Bindings          []Binding        `yaml:"bindings"`
	Protected         []Protected      `yaml:"protected"`
	UI                UI               `yaml:"ui"`
	Groups            map[string]Group `yaml:"groups"`
	Policy            Policy           `yaml:"policy"`
	MCP               MCP              `yaml:"mcp"`

	Hash     string    `yaml:"-"` // sha256 of the file
	LoadedAt time.Time `yaml:"-"`
}

// Provider kinds.
const (
	KindEuroDNS = "eurodns"
	KindRoute53 = "route53"
)

// Provider is one upstream DNS account. Each zone is served by exactly one
// provider: the one whose zones filter matches it and, when several match,
// whose account lists it.
type Provider struct {
	ID      string         `yaml:"id"`
	Kind    string         `yaml:"kind"` // eurodns | route53
	Zones   ProviderZones  `yaml:"zones"`
	EuroDNS *EuroDNSConfig `yaml:"eurodns"`
	Route53 *Route53Config `yaml:"route53"`
}

// ProviderZones selects the zones of the account the gate serves. The
// account is listed every Refresh: listed zones that are not managed by the
// policy are visible read-only and can be brought under management.
type ProviderZones struct {
	Include []string `yaml:"include"` // zone globs, default ["*"]
	Exclude []string `yaml:"exclude"` // zone globs, win over include
	Refresh Duration `yaml:"refresh"` // listing period, default 1h, minimum 5m
}

// Matches reports whether the zone filter of the provider selects zone.
func (p Provider) Matches(zone string) bool {
	zone = normZone(zone)
	return glob.Any(p.Zones.Include, zone) && !glob.Any(p.Zones.Exclude, zone)
}

// EuroDNSConfig configures a EuroDNS account. The API key is never read
// from the file: it comes from EURODNS_<ID>_API_KEY or EURODNS_API_KEY (or
// their _FILE variants), the app id from eurodns.app_id, EURODNS_<ID>_APP_ID
// or EURODNS_APP_ID; <ID> is the provider id in upper case, every other
// character than letters and digits replaced by "_".
type EuroDNSConfig struct {
	BaseURL    string `yaml:"base_url"`
	AppID      string `yaml:"app_id"`
	Rate       Rate   `yaml:"rate"`
	MaxRetries *int   `yaml:"max_retries"`

	APIKey string `yaml:"-"`
}

// Route53Config configures an AWS account for Route53. Credentials come
// from the default AWS chain (IRSA, instance role, environment), optionally
// assuming a role in the target account.
type Route53Config struct {
	Region        string `yaml:"region"`
	AssumeRoleARN string `yaml:"assume_role_arn"`
	ExternalID    string `yaml:"external_id"`
	// HostedZones pins zone names to hosted zone ids (needed when a name has
	// several hosted zones, or to skip listing the account).
	HostedZones    map[string]string `yaml:"hosted_zones"`
	IncludePrivate bool              `yaml:"include_private"`
}

func normZone(z string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".") }

// Group is a named set of subject matchers (an Entra app role or group
// object id, a GitHub repository, explicit users).
type Group struct {
	Description string    `yaml:"description"`
	Members     []Subject `yaml:"members"`
}

// Policy configures the managed (UI-editable) policy layer.
type Policy struct {
	Editable        bool     `yaml:"editable"`
	RequireApproval *bool    `yaml:"require_approval"`
	EditMaxAge      Duration `yaml:"edit_max_age"`
	RequireAMR      []string `yaml:"require_amr"`
	Bounds          Bounds   `yaml:"bounds"`
	// Delegations let base-trusted subjects (typically the CI pipeline that
	// creates other pipelines) manage their own roles and bindings in the
	// managed layer, within limits, without approval.
	Delegations []Delegation `yaml:"delegations"`
}

// Delegation grants the subjects it matches the right to create, change and
// delete, through the delegation API, managed roles and bindings they own,
// within Allow. Delegated changes are activated without approval.
type Delegation struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	Subjects    []Subject       `yaml:"subjects"`
	Allow       DelegationAllow `yaml:"allow"`
}

// DelegationAllow bounds the objects of a delegation, inside policy.bounds.
type DelegationAllow struct {
	// Zones are the zone globs delegated role rules may target.
	Zones []string `yaml:"zones"`
	// Actions delegated role rules may grant.
	Actions []string `yaml:"actions"`
	// Records, when set, forces delegated role rules to name hosts and/or
	// types covered by these patterns.
	Records *RecordScope `yaml:"records"`
	// BindingSubjects are the matchers a delegated binding may target: each
	// subject of a delegated binding must be covered by one of them.
	BindingSubjects []Subject `yaml:"binding_subjects"`
	// Teams a delegated binding may act for.
	Teams DelegationTeams `yaml:"teams"`
	// Roles are existing (base or managed) roles a delegated binding may
	// grant, besides the roles of the delegation itself.
	Roles []string `yaml:"roles"`
	// Groups a delegated binding may target, besides its subjects.
	Groups []string `yaml:"groups"`
	// MaxObjects caps the roles plus bindings of the delegation (default 100).
	MaxObjects int `yaml:"max_objects"`
}

// DelegationTeams lists the teams a delegated binding may use. FromSubject
// is the "team from the subject" rule: a binding either derives its team
// with exactly this team_from, or names the team this rule derives from its
// (single-valued, wildcard-free) subjects. Names are team globs a binding may
// set as a fixed team.
type DelegationTeams struct {
	FromSubject *TeamFrom `yaml:"from_subject"`
	Names       []string  `yaml:"names"`
}

// DefaultDelegationMaxObjects is the default cap of objects per delegation.
const DefaultDelegationMaxObjects = 100

// MCP configures the Model Context Protocol endpoint (/mcp).
type MCP struct {
	Enabled           bool     `yaml:"enabled"`
	AllowWrites       bool     `yaml:"allow_writes"`
	PlanTTL           Duration `yaml:"plan_ttl"`
	RequestsPerMinute int      `yaml:"requests_per_minute"` // per subject
	PublicURL         string   `yaml:"public_url"`          // base URL advertised in the resource metadata
}

// Bounds limit what the managed layer may grant.
type Bounds struct {
	Zones   []string `yaml:"zones"`
	Actions []string `yaml:"actions"`
}

// UI configures the read-only web UI and its OIDC login (authorization code
// with PKCE). The client secret and session key come from the environment.
type UI struct {
	Enabled     bool     `yaml:"enabled"`
	Issuer      string   `yaml:"issuer"` // name of a configured issuer
	ClientID    string   `yaml:"client_id"`
	RedirectURL string   `yaml:"redirect_url"`
	Scopes      []string `yaml:"scopes"`
	SessionTTL  Duration `yaml:"session_ttl"`
	// CLIScope is the OAuth scope a command-line tool requests to call the
	// gate (shown on the Connect page). Default for an Entra v2 issuer:
	// api://<client_id>/.default.
	CLIScope string `yaml:"cli_scope"`
	// SAML replaces the OIDC login with a SAML 2.0 login.
	SAML *UISAML `yaml:"saml"`

	ClientSecret string `yaml:"-"` // DNS_GATE_UI_CLIENT_SECRET(_FILE), optional (public client)
	SessionKey   []byte `yaml:"-"` // DNS_GATE_SESSION_KEY(_FILE), 32 bytes, hex or base64
}

// Listen configures the HTTP server.
type Listen struct {
	Address        string   `yaml:"address"`
	TrustedProxies []string `yaml:"trusted_proxies"` // CIDRs allowed to set X-Forwarded-For
}

// Rate is the client-side limiter towards EuroDNS (10 req / 10 s per IP).
type Rate struct {
	Every Duration `yaml:"every"`
	Burst int      `yaml:"burst"`
}

// Limits are request-level guards.
type Limits struct {
	MaxBodyBytes         int64 `yaml:"max_body_bytes"`
	MaxChangesPerRequest int   `yaml:"max_changes_per_request"`
}

// Lock configures the per-zone write lease.
type Lock struct {
	TTL  Duration `yaml:"ttl"`
	Wait Duration `yaml:"wait"`
}

// Store selects the ownership and audit backend.
type Store struct {
	Type           string   `yaml:"type"` // memory | sqlite | postgres | dynamodb
	AuditRetention Duration `yaml:"audit_retention"`
	SQLite         SQLite   `yaml:"sqlite"`
	Postgres       Postgres `yaml:"postgres"`
	DynamoDB       DynamoDB `yaml:"dynamodb"`
}

// SQLite backend settings (single replica, persistent volume).
type SQLite struct {
	Path string `yaml:"path"`
}

// Postgres backend settings. The DSN carries credentials: it is read from
// DNS_GATE_POSTGRES_DSN or DNS_GATE_POSTGRES_DSN_FILE only.
type Postgres struct {
	MaxConns int `yaml:"max_conns"`

	DSN string `yaml:"-"`
}

// DynamoDB backend settings.
type DynamoDB struct {
	Table    string `yaml:"table"`
	Region   string `yaml:"region"`
	Endpoint string `yaml:"endpoint"`
}

// Issuer is a trusted OIDC token issuer.
type Issuer struct {
	Name        string                `yaml:"name"`
	Issuer      string                `yaml:"issuer"`
	JWKSURL     string                `yaml:"jwks_url"` // empty: OIDC discovery
	Audiences   []string              `yaml:"audiences"`
	BoundClaims map[string]StringList `yaml:"bound_claims"`
	TeamClaim   string                `yaml:"team_claim"`
	NameClaim   string                `yaml:"name_claim"` // display name claim (default: the subject)
	Category    string                `yaml:"category"`   // human | pipeline (default pipeline)

	// SubjectClaim is the claim used as subject id (default "sub").
	// SubjectTemplate builds a composite id instead, e.g. "{{tid}}/{{oid}}".
	SubjectClaim    string `yaml:"subject_claim"`
	SubjectTemplate string `yaml:"subject_template"`
	// CategoryClaim and CategoryMap derive the category from a claim
	// (e.g. Entra idtyp: {app: pipeline, user: human}); unmapped values
	// fall back to Category.
	CategoryClaim string            `yaml:"category_claim"`
	CategoryMap   map[string]string `yaml:"category_map"`
	Algorithms    []string          `yaml:"algorithms"`
	ClockSkew     Duration          `yaml:"clock_skew"`

	// Self makes this issuer the gate itself: the gate signs tokens for
	// signed-in users (POST /api/v1/tokens, the Claude Desktop extension)
	// with the key of DNS_GATE_TOKEN_SIGNING_KEY. Issuer is the public
	// origin of the gate; the tokens are bound as the issuer of the session
	// they come from, so this issuer is never named in bindings.
	Self bool `yaml:"self"`
	// TokenTTL is the lifetime of gate-issued tokens (default 1h). It also
	// caps the tokens of the token exchange.
	TokenTTL Duration `yaml:"token_ttl"`
	// TokenExchange lets the tokens of this issuer be exchanged for gate
	// tokens (POST /api/v1/token-exchange, RFC 8693); needs a gate issuer.
	TokenExchange bool `yaml:"token_exchange"`
	// MaxExchangedTTL caps the lifetime of the gate tokens exchanged for
	// tokens of this issuer (default 15m).
	MaxExchangedTTL Duration `yaml:"max_exchanged_ttl"`
	SigningKey      []byte   `yaml:"-"`
	// SAML marks the subject issuer of the SAML login (AllIssuers).
	SAML bool `yaml:"-"`
}

// VirtualKey is a gate-issued key for clients that only speak the EuroDNS
// X-APP-ID / X-API-KEY scheme (ACME clients, legacy tools).
type VirtualKey struct {
	ID           string     `yaml:"id"`
	AppID        string     `yaml:"app_id"`
	KeySHA256    string     `yaml:"key_sha256"`
	Roles        []string   `yaml:"roles"`
	Teams        []string   `yaml:"teams"`
	ExpiresAt    *time.Time `yaml:"expires_at"`
	AllowedCIDRs []string   `yaml:"allowed_cidrs"`
}

// Role is a named set of rules.
type Role struct {
	Rules                []Rule   `yaml:"rules"`
	RebaseOnSave         bool     `yaml:"rebase_on_save"`
	EphemeralTTL         Duration `yaml:"ephemeral_ttl"`
	MaxChangesPerRequest int      `yaml:"max_changes_per_request"` // 0: global default, -1: unlimited
}

// Rule grants actions on zones, optionally restricted to some records.
type Rule struct {
	Zones   []string     `yaml:"zones"`
	Actions []string     `yaml:"actions"`
	Records *RecordScope `yaml:"records"`
}

// RecordScope restricts a rule to hosts (relative to the zone, "@" = apex)
// and record types.
type RecordScope struct {
	Hosts []string `yaml:"hosts"`
	Types []string `yaml:"types"`
}

// Binding grants a role to subjects, acting for a team (the owner of the
// RRsets they create). TeamFrom derives the team from a claim of each
// subject instead of a fixed Team.
type Binding struct {
	Role     string    `yaml:"role"`
	Team     string    `yaml:"team"`
	TeamFrom *TeamFrom `yaml:"team_from"`
	Groups   []string  `yaml:"groups"`
	Subjects []Subject `yaml:"subjects"`
}

// TeamFrom derives a team from a string claim: Regex (anchored, exactly one
// capture group) is matched against the claim and the team is Prefix
// followed by the lowercased capture.
type TeamFrom struct {
	Claim  string `yaml:"claim"`
	Regex  string `yaml:"regex"`
	Prefix string `yaml:"prefix"`
}

// Subject matches tokens of an issuer whose claims match all globs.
type Subject struct {
	Issuer string                `yaml:"issuer"`
	Claims map[string]StringList `yaml:"claims"`
}

// Protected lists records no role may write or adopt.
type Protected struct {
	Zones []string `yaml:"zones"`
	Hosts []string `yaml:"hosts"`
	Types []string `yaml:"types"`
}

// DefaultMaxExchangedTTL caps the lifetime of exchanged gate tokens.
const DefaultMaxExchangedTTL = 15 * time.Minute

// ReservedIssuers are issuer names of subjects the gate makes itself: API
// keys, virtual keys and the gate's own actors ("gate:reconciler"). No
// token issuer may use them; the gate issuer (self: true) may be named
// "gate", its tokens being bound as their original issuer.
var ReservedIssuers = map[string]bool{"api-key": true, "virtual-key": true, "gate": true}

// Known actions.
var knownActions = map[string]bool{
	"dns.read":           true,
	"dns.record.write":   true,
	"dns.record.adopt":   true,
	"dns.zone.admin":     true,
	"ui.read":            true,
	"policy.read":        true,
	"policy.propose":     true,
	"policy.approve":     true,
	"domain.read":        true,
	"gate.apikey.manage": true,
}

var asymmetricAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// DefaultAlgorithms are accepted when an issuer does not list any.
var DefaultAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

var (
	fqdnLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	nameRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Load reads a file, applies environment overrides and validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, os.Getenv)
}

// Parse decodes YAML strictly (unknown fields refused), applies environment
// overrides through getenv and validates.
func Parse(data []byte, getenv func(string) string) (*Config, error) {
	var c Config
	sum := sha256.Sum256(data)
	c.Hash = hex.EncodeToString(sum[:])
	c.LoadedAt = time.Now().UTC()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.applyEnv(getenv); err != nil {
		return nil, err
	}
	c.defaults()
	err := c.Validate()
	if getenv(EnvLambdaRuntime) != "" && c.Store.Type != "dynamodb" {
		err = errors.Join(err, fmt.Errorf("store.type: %q is not supported on AWS Lambda, dynamodb required", c.Store.Type))
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyEnv(getenv func(string) string) error {
	legacy := func(name string) string {
		if v := getenv(name); v != "" {
			return v
		}
		if rest, ok := strings.CutPrefix(name, "DNS_GATE_"); ok {
			return getenv("EURODNS_GATE_" + rest)
		}
		return ""
	}
	read := func(name string) (string, error) {
		if v := legacy(name); v != "" {
			return v, nil
		}
		if f := legacy(name + "_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return "", fmt.Errorf("config: %s_FILE: %w", name, err)
			}
			return strings.TrimSpace(string(b)), nil
		}
		return "", nil
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Kind != KindEuroDNS || p.EuroDNS == nil {
			continue
		}
		prefix := "EURODNS_" + envName(p.ID) + "_"
		for _, f := range []struct {
			name string
			dst  *string
		}{{"APP_ID", &p.EuroDNS.AppID}, {"API_KEY", &p.EuroDNS.APIKey}} {
			v, err := read(prefix + f.name)
			if err != nil {
				return err
			}
			if v == "" {
				if v, err = read("EURODNS_" + f.name); err != nil {
					return err
				}
			}
			if v != "" {
				*f.dst = v
			}
		}
	}
	var err error
	if c.Store.Postgres.DSN, err = read("DNS_GATE_POSTGRES_DSN"); err != nil {
		return err
	}
	if c.UI.ClientSecret, err = read("DNS_GATE_UI_CLIENT_SECRET"); err != nil {
		return err
	}
	k, err := read("DNS_GATE_SESSION_KEY")
	if err != nil {
		return err
	}
	if k != "" {
		if c.UI.SessionKey, err = decodeKey(k); err != nil {
			return fmt.Errorf("config: DNS_GATE_SESSION_KEY: %w", err)
		}
	}
	return c.applySAMLEnv(read)
}

func (c *Config) defaults() {
	if c.Listen.Address == "" {
		c.Listen.Address = ":8080"
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		p.ID, p.Kind = strings.TrimSpace(p.ID), strings.ToLower(strings.TrimSpace(p.Kind))
		if len(p.Zones.Include) == 0 {
			p.Zones.Include = []string{"*"}
		}
		for _, l := range [][]string{p.Zones.Include, p.Zones.Exclude} {
			for j := range l {
				l[j] = normZone(l[j])
			}
		}
		if p.Zones.Refresh == 0 {
			p.Zones.Refresh = Duration(time.Hour)
		}
		if e := p.EuroDNS; e != nil {
			if e.BaseURL == "" {
				e.BaseURL = "https://rest-api.eurodns.com"
			}
			if e.Rate.Every == 0 {
				e.Rate.Every = Duration(1100 * time.Millisecond)
			}
			if e.Rate.Burst == 0 {
				e.Rate.Burst = 5
			}
			if e.MaxRetries == nil {
				n := 3
				e.MaxRetries = &n
			}
		}
		if r := p.Route53; r != nil && len(r.HostedZones) > 0 {
			hz := make(map[string]string, len(r.HostedZones))
			for z, id := range r.HostedZones {
				hz[normZone(z)] = strings.TrimSpace(id)
			}
			r.HostedZones = hz
		}
	}
	if c.CheckOnWrite == nil {
		t := true
		c.CheckOnWrite = &t
	}
	if c.ReconcileInterval == 0 {
		c.ReconcileInterval = Duration(15 * time.Minute)
	}
	if c.Limits.MaxBodyBytes == 0 {
		c.Limits.MaxBodyBytes = 1 << 20
	}
	if c.Limits.MaxChangesPerRequest == 0 {
		c.Limits.MaxChangesPerRequest = 20
	}
	if c.Lock.TTL == 0 {
		c.Lock.TTL = Duration(60 * time.Second)
	}
	if c.Lock.Wait == 0 {
		c.Lock.Wait = Duration(30 * time.Second)
	}
	if c.Store.Type == "" {
		c.Store.Type = "memory"
	}
	if c.Store.AuditRetention == 0 {
		c.Store.AuditRetention = Duration(400 * 24 * time.Hour)
	}
	if c.Store.Postgres.MaxConns == 0 {
		c.Store.Postgres.MaxConns = 5
	}
	if c.Policy.RequireApproval == nil {
		t := true
		c.Policy.RequireApproval = &t
	}
	if c.Policy.EditMaxAge == 0 {
		c.Policy.EditMaxAge = Duration(15 * time.Minute)
	}
	for i := range c.Policy.Delegations {
		if c.Policy.Delegations[i].Allow.MaxObjects == 0 {
			c.Policy.Delegations[i].Allow.MaxObjects = DefaultDelegationMaxObjects
		}
	}
	if c.MCP.PlanTTL == 0 {
		c.MCP.PlanTTL = Duration(10 * time.Minute)
	}
	if c.MCP.RequestsPerMinute == 0 {
		c.MCP.RequestsPerMinute = 120
	}
	if c.UI.SessionTTL == 0 {
		c.UI.SessionTTL = Duration(8 * time.Hour)
	}
	if len(c.UI.Scopes) == 0 {
		c.UI.Scopes = []string{"openid", "profile", "email"}
	}
	if c.UI.CLIScope == "" && c.UI.ClientID != "" {
		for _, is := range c.Issuers {
			if _, entra := EntraV2Tenant(is.Issuer); entra && is.Name == c.UI.Issuer {
				c.UI.CLIScope = "api://" + c.UI.ClientID + "/.default"
			}
		}
	}
	for i := range c.Zones {
		c.Zones[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Zones[i])), ".")
	}
	c.samlDefaults()
	for i := range c.Issuers {
		if len(c.Issuers[i].Algorithms) == 0 {
			c.Issuers[i].Algorithms = DefaultAlgorithms
		}
		if c.Issuers[i].Category == "" {
			c.Issuers[i].Category = "pipeline"
		}
		if c.Issuers[i].SubjectClaim == "" && c.Issuers[i].SubjectTemplate == "" {
			c.Issuers[i].SubjectClaim = "sub"
		}
		if c.Issuers[i].JWKSURL == "" {
			if tid, ok := entraV1Tenant(c.Issuers[i].Issuer); ok {
				// Entra v1 issuers have no discovery document of their own;
				// v1 and v2 tokens are signed with the same tenant keys.
				c.Issuers[i].JWKSURL = "https://login.microsoftonline.com/" + tid + "/discovery/v2.0/keys"
			}
		}
		if c.Issuers[i].ClockSkew == 0 {
			c.Issuers[i].ClockSkew = Duration(60 * time.Second)
		}
		if c.Issuers[i].TokenExchange && c.Issuers[i].MaxExchangedTTL == 0 {
			c.Issuers[i].MaxExchangedTTL = Duration(DefaultMaxExchangedTTL)
		}
	}
}

// Validate checks the whole document and reports every error found.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if _, err := netip.ParseAddrPort(normalizeListen(c.Listen.Address)); err != nil {
		add("listen.address: %v", err)
	}
	for _, p := range c.Listen.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			add("listen.trusted_proxies: %q: %v", p, err)
		}
	}
	c.validateProviders(add)
	seenZone := map[string]bool{}
	for _, z := range c.Zones {
		if !ValidFQDN(z) {
			add("zones: %q is not a valid domain name", z)
		}
		if seenZone[z] {
			add("zones: %q listed twice", z)
		}
		seenZone[z] = true
		if len(c.Providers) > 0 && len(c.ProvidersFor(z)) == 0 {
			add("zones: %q is selected by no provider (providers[].zones include/exclude)", z)
		}
	}

	switch c.Store.Type {
	case "memory":
	case "sqlite":
		if c.Store.SQLite.Path == "" {
			add("store.sqlite.path: required")
		}
	case "postgres":
		if c.Store.Postgres.DSN == "" {
			add("store.postgres: DSN missing (DNS_GATE_POSTGRES_DSN or DNS_GATE_POSTGRES_DSN_FILE)")
		}
		if c.Store.Postgres.MaxConns < 1 || c.Store.Postgres.MaxConns > 100 {
			add("store.postgres.max_conns: must be between 1 and 100")
		}
	case "dynamodb":
		if c.Store.DynamoDB.Table == "" {
			add("store.dynamodb.table: required")
		}
	default:
		add("store.type: %q (expected memory, sqlite, postgres or dynamodb)", c.Store.Type)
	}
	if c.Store.AuditRetention.D() < 24*time.Hour {
		add("store.audit_retention: must be >= 24h")
	}
	if c.Lock.TTL.D() <= 0 || c.Lock.Wait.D() < 0 {
		add("lock: ttl must be > 0 and wait >= 0")
	}
	if c.ReconcileInterval.D() < time.Minute {
		add("reconcile_interval: must be >= 1m (EuroDNS rate limit)")
	}
	if c.Limits.MaxBodyBytes < 1024 {
		add("limits.max_body_bytes: must be >= 1024")
	}
	if c.Limits.MaxChangesPerRequest < 1 {
		add("limits.max_changes_per_request: must be >= 1")
	}

	issuers := map[string]bool{}
	selfName := ""
	for i, is := range c.Issuers {
		at := fmt.Sprintf("issuers[%d]", i)
		if !nameRe.MatchString(is.Name) {
			add("%s.name: %q must be a lowercase identifier", at, is.Name)
		}
		if issuers[is.Name] {
			add("%s.name: %q duplicated", at, is.Name)
		}
		if ReservedIssuers[is.Name] && !(is.Self && is.Name == "gate") {
			add("%s.name: %q is reserved for subjects of the gate itself", at, is.Name)
		}
		issuers[is.Name] = true
		if u, err := url.Parse(is.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
			if !(err == nil && u.Scheme == "http" && isLoopback(u.Hostname())) {
				add("%s.issuer: https URL required, got %q", at, is.Issuer)
			}
		}
		if is.JWKSURL != "" {
			if u, err := url.Parse(is.JWKSURL); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
				add("%s.jwks_url: https URL required", at)
			}
		}
		if len(is.Audiences) == 0 {
			add("%s.audiences: at least one audience is required", at)
		}
		for _, a := range is.Algorithms {
			if !asymmetricAlgs[a] {
				add("%s.algorithms: %q not allowed (asymmetric algorithms only)", at, a)
			}
		}
		if err := validateEntra(is); err != nil {
			add("%s: %v", at, err)
		}
		if is.Self {
			if selfName != "" {
				add("%s.self: only one gate issuer is allowed", at)
			}
			selfName = is.Name
			for _, e := range validateSelfIssuer(at, is) {
				add("%s", e)
			}
		} else if is.TokenTTL != 0 {
			add("%s.token_ttl: only for the gate issuer (self: true)", at)
		}
		if is.TokenExchange && is.Self {
			add("%s.token_exchange: gate tokens are never exchanged", at)
		}
		if is.MaxExchangedTTL != 0 && (!is.TokenExchange || is.MaxExchangedTTL.D() < time.Minute || is.MaxExchangedTTL.D() > 24*time.Hour) {
			add("%s.max_exchanged_ttl: between 1m and 24h, with token_exchange only", at)
		}
		if is.SubjectClaim != "" && is.SubjectTemplate != "" {
			add("%s: subject_claim and subject_template are exclusive", at)
		}
		if is.SubjectTemplate != "" {
			if err := ValidateSubjectTemplate(is.SubjectTemplate); err != nil {
				add("%s.subject_template: %v", at, err)
			}
		}
		if len(is.CategoryMap) > 0 && is.CategoryClaim == "" {
			add("%s.category_map: category_claim required", at)
		}
		for v, cat := range is.CategoryMap {
			if cat != "human" && cat != "pipeline" {
				add("%s.category_map.%s: %q (expected human or pipeline)", at, v, cat)
			}
		}
		if is.Category != "human" && is.Category != "pipeline" {
			add("%s.category: %q (expected human or pipeline)", at, is.Category)
		}
		if is.ClockSkew.D() < 0 || is.ClockSkew.D() > 5*time.Minute {
			add("%s.clock_skew: must be between 0 and 5m", at)
		}
	}
	for i, is := range c.Issuers {
		if is.TokenExchange && !is.Self && selfName == "" {
			add("issuers[%d].token_exchange: needs a gate issuer (an issuer with self: true) to sign the exchanged tokens", i)
		}
	}
	if c.UI.SAML != nil {
		for _, e := range validateSAML(c, issuers) {
			add("%s", e)
		}
		issuers[c.UI.SAML.Issuer] = true
	}
	delete(issuers, selfName)

	for name, r := range c.Roles {
		at := "roles." + name
		if !nameRe.MatchString(name) {
			add("%s: role name must be a lowercase identifier", at)
		}
		if len(r.Rules) == 0 {
			add("%s.rules: at least one rule is required", at)
		}
		for j, rule := range r.Rules {
			rat := fmt.Sprintf("%s.rules[%d]", at, j)
			if len(rule.Zones) == 0 {
				add("%s.zones: required", rat)
			}
			if len(rule.Actions) == 0 {
				add("%s.actions: required", rat)
			}
			for _, a := range rule.Actions {
				if !knownActions[a] {
					add("%s.actions: unknown action %q", rat, a)
				}
			}
			if rule.Records != nil && len(rule.Records.Hosts) == 0 && len(rule.Records.Types) == 0 {
				add("%s.records: hosts or types required when records is set", rat)
			}
		}
		if r.EphemeralTTL.D() < 0 {
			add("%s.ephemeral_ttl: must be >= 0", at)
		}
		if r.MaxChangesPerRequest < -1 {
			add("%s.max_changes_per_request: must be -1 (unlimited), 0 (default) or > 0", at)
		}
	}

	teamRe := nameRe
	for i, b := range c.Bindings {
		at := fmt.Sprintf("bindings[%d]", i)
		if _, ok := c.Roles[b.Role]; !ok {
			add("%s.role: unknown role %q", at, b.Role)
		}
		if b.Team != "" && !teamRe.MatchString(b.Team) {
			add("%s.team: %q must be a lowercase identifier", at, b.Team)
		}
		if b.TeamFrom != nil {
			if b.Team != "" {
				add("%s: team and team_from are exclusive", at)
			}
			if err := ValidateTeamFrom(b.TeamFrom.Claim, b.TeamFrom.Regex, b.TeamFrom.Prefix); err != nil {
				add("%s.team_from: %v", at, err)
			}
		}
		if len(b.Subjects) == 0 && len(b.Groups) == 0 {
			add("%s: groups or subjects required", at)
		}
		for j, g := range b.Groups {
			if _, ok := c.Groups[g]; !ok {
				add("%s.groups[%d]: unknown group %q", at, j, g)
			}
		}
		for j, s := range b.Subjects {
			if !issuers[s.Issuer] {
				add("%s.subjects[%d].issuer: unknown issuer %q", at, j, s.Issuer)
			}
			if len(s.Claims) == 0 {
				add("%s.subjects[%d].claims: at least one claim is required (\"sub\" at least)", at, j)
			}
		}
	}

	for name, g := range c.Groups {
		at := "groups." + name
		if !nameRe.MatchString(name) {
			add("%s: group name must be a lowercase identifier", at)
		}
		if len(g.Members) == 0 {
			add("%s.members: at least one member matcher is required", at)
		}
		for j, m := range g.Members {
			if !issuers[m.Issuer] {
				add("%s.members[%d].issuer: unknown issuer %q", at, j, m.Issuer)
			}
			if len(m.Claims) == 0 {
				add("%s.members[%d].claims: at least one claim is required", at, j)
			}
		}
	}

	if c.Policy.Editable {
		if len(c.Policy.Bounds.Zones) == 0 || len(c.Policy.Bounds.Actions) == 0 {
			add("policy.bounds: zones and actions are required when policy.editable is true")
		}
	}
	for _, z := range c.Policy.Bounds.Zones {
		if strings.Contains(z, "?") {
			add("policy.bounds.zones: %q: only * wildcards are supported", z)
		}
	}
	for _, a := range c.Policy.Bounds.Actions {
		if !knownActions[a] {
			add("policy.bounds.actions: unknown action %q", a)
		}
		if strings.HasPrefix(a, "policy.") {
			add("policy.bounds.actions: %q can only be granted by the base policy", a)
		}
	}
	if c.Policy.EditMaxAge.D() < time.Minute || c.Policy.EditMaxAge.D() > 24*time.Hour {
		add("policy.edit_max_age: must be between 1m and 24h")
	}
	errs = append(errs, validateDelegations(c, issuers)...)

	vkIDs, vkApps := map[string]bool{}, map[string]bool{}
	for i, vk := range c.VirtualKeys {
		at := fmt.Sprintf("virtual_keys[%d]", i)
		if !nameRe.MatchString(vk.ID) {
			add("%s.id: %q must be a lowercase identifier", at, vk.ID)
		}
		if vkIDs[vk.ID] {
			add("%s.id: %q duplicated", at, vk.ID)
		}
		vkIDs[vk.ID] = true
		if vk.AppID == "" {
			add("%s.app_id: required", at)
		}
		if vkApps[vk.AppID] {
			add("%s.app_id: %q duplicated", at, vk.AppID)
		}
		vkApps[vk.AppID] = true
		if !sha256Re.MatchString(vk.KeySHA256) {
			add("%s.key_sha256: lowercase hex sha256 required", at)
		}
		if len(vk.Roles) == 0 {
			add("%s.roles: required", at)
		}
		for _, r := range vk.Roles {
			role, ok := c.Roles[r]
			if !ok {
				add("%s.roles: unknown role %q", at, r)
			}
			for _, rule := range role.Rules {
				for _, a := range rule.Actions {
					if strings.HasPrefix(a, "policy.") {
						add("%s.roles: role %q grants %s; virtual keys cannot hold policy.* actions", at, r, a)
					}
				}
			}
		}
		for _, t := range vk.Teams {
			if !teamRe.MatchString(t) {
				add("%s.teams: %q must be a lowercase identifier", at, t)
			}
		}
		for _, p := range vk.AllowedCIDRs {
			if _, err := netip.ParsePrefix(p); err != nil {
				add("%s.allowed_cidrs: %q: %v", at, p, err)
			}
		}
	}

	for i, p := range c.Protected {
		if len(p.Zones) == 0 || len(p.Hosts) == 0 || len(p.Types) == 0 {
			add("protected[%d]: zones, hosts and types are required", i)
		}
	}

	if c.MCP.PlanTTL.D() < time.Minute || c.MCP.PlanTTL.D() > time.Hour {
		add("mcp.plan_ttl: must be between 1m and 1h")
	}
	if c.MCP.RequestsPerMinute < 1 || c.MCP.RequestsPerMinute > 6000 {
		add("mcp.requests_per_minute: must be between 1 and 6000")
	}
	if c.MCP.PublicURL != "" {
		if u, err := url.Parse(c.MCP.PublicURL); err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
			add("mcp.public_url: https base URL without path required")
		}
	}

	if c.UI.Enabled && c.UI.SAML != nil {
		if len(c.UI.SessionKey) != 32 {
			add("ui: session key missing or not 32 bytes (DNS_GATE_SESSION_KEY or DNS_GATE_SESSION_KEY_FILE)")
		}
		if c.UI.SessionTTL.D() < time.Minute || c.UI.SessionTTL.D() > 24*time.Hour {
			add("ui.session_ttl: must be between 1m and 24h")
		}
	} else if c.UI.Enabled {
		if !issuers[c.UI.Issuer] {
			add("ui.issuer: unknown issuer %q", c.UI.Issuer)
		}
		if c.UI.ClientID == "" {
			add("ui.client_id: required")
		}
		if u, err := url.Parse(c.UI.RedirectURL); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
			add("ui.redirect_url: https URL required")
		} else if u.Path != "/auth/callback" {
			add("ui.redirect_url: path must be /auth/callback")
		}
		hasOpenID := false
		for _, sc := range c.UI.Scopes {
			hasOpenID = hasOpenID || sc == "openid"
		}
		if !hasOpenID {
			add("ui.scopes: must include openid")
		}
		if len(c.UI.SessionKey) != 32 {
			add("ui: session key missing or not 32 bytes (DNS_GATE_SESSION_KEY or DNS_GATE_SESSION_KEY_FILE)")
		}
		if c.UI.SessionTTL.D() < time.Minute || c.UI.SessionTTL.D() > 24*time.Hour {
			add("ui.session_ttl: must be between 1m and 24h")
		}
	}
	if c.UI.CLIScope != "" && (len(c.UI.CLIScope) > 512 || !cliScopeRe.MatchString(c.UI.CLIScope)) {
		add("ui.cli_scope: one scope of letters, digits and . _ ~ : / %% - expected, got %q", c.UI.CLIScope)
	}

	return errors.Join(errs...)
}

// decodeKey accepts a 32-byte key encoded as hex or base64.
func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("expected 32 bytes encoded as hex or base64")
}

var (
	guidRe        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	placeholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.:-]+)\s*\}\}`)
	// cliScopeRe keeps the scope safe to paste unquoted in shell snippets.
	cliScopeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~:/%-]*$`)
)

// Placeholders returns the claim names of a subject template.
func Placeholders(tmpl string) []string {
	var out []string
	for _, m := range placeholderRe.FindAllStringSubmatch(tmpl, -1) {
		out = append(out, m[1])
	}
	return out
}

// RenderSubject renders a subject template; every claim must be a non-empty string.
func RenderSubject(tmpl string, claims map[string]any) (string, error) {
	var missing string
	out := placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := placeholderRe.FindStringSubmatch(m)[1]
		v, ok := claims[name].(string)
		if !ok || v == "" {
			missing = name
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("claim %q missing", missing)
	}
	return out, nil
}

// ValidateSubjectTemplate checks a template has placeholders and only
// literal characters that cannot be confused with claim values.
func ValidateSubjectTemplate(tmpl string) error {
	if len(Placeholders(tmpl)) == 0 {
		return errors.New("at least one {{claim}} placeholder is required")
	}
	rest := placeholderRe.ReplaceAllString(tmpl, "")
	if strings.ContainsAny(rest, "{}") || strings.ContainsAny(rest, " \t\n") {
		return errors.New("only {{claim}} placeholders and separators such as / or : are allowed")
	}
	return nil
}

// teamGlobRe is a team name glob of policy.delegations[].allow.teams.names.
var teamGlobRe = regexp.MustCompile(`^[a-z0-9*][a-z0-9._*-]{0,63}$`)

// validateDelegations checks policy.delegations: every limit stays inside
// policy.bounds and never reaches policy.* actions.
func validateDelegations(c *Config, issuers map[string]bool) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(c.Policy.Delegations) > 0 && !c.Policy.Editable {
		add("policy.delegations: requires policy.editable (delegated objects live in the managed layer)")
	}
	matcher := func(at string, m Subject) {
		if !issuers[m.Issuer] {
			add("%s.issuer: unknown issuer %q", at, m.Issuer)
		}
		if len(m.Claims) == 0 {
			add("%s.claims: at least one claim is required", at)
		}
		for name, pats := range m.Claims {
			if len(pats) == 0 {
				add("%s.claims.%s: at least one pattern is required", at, name)
			}
			for _, p := range pats {
				if p == "" || p == "*" {
					add("%s.claims.%s: pattern %q matches anyone", at, name, p)
				}
			}
		}
	}
	seen := map[string]bool{}
	for i, d := range c.Policy.Delegations {
		at := fmt.Sprintf("policy.delegations[%d]", i)
		if !nameRe.MatchString(d.Name) {
			add("%s.name: %q must be a lowercase identifier", at, d.Name)
		}
		if seen[d.Name] {
			add("%s.name: %q duplicated", at, d.Name)
		}
		seen[d.Name] = true
		if len(d.Subjects) == 0 {
			add("%s.subjects: at least one subject is required", at)
		}
		for j, m := range d.Subjects {
			matcher(fmt.Sprintf("%s.subjects[%d]", at, j), m)
		}
		al := d.Allow
		if len(al.Zones) == 0 {
			add("%s.allow.zones: at least one zone glob is required", at)
		}
		for _, z := range al.Zones {
			if !glob.Covered(c.Policy.Bounds.Zones, strings.ToLower(z)) {
				add("%s.allow.zones: %q is outside policy.bounds.zones", at, z)
			}
		}
		if len(al.Actions) == 0 {
			add("%s.allow.actions: at least one action is required", at)
		}
		for _, a := range al.Actions {
			switch {
			case strings.HasPrefix(a, "policy."):
				add("%s.allow.actions: %q can only be granted by the base policy", at, a)
			case !knownActions[a]:
				add("%s.allow.actions: unknown action %q", at, a)
			case !containsString(c.Policy.Bounds.Actions, a):
				add("%s.allow.actions: %q is outside policy.bounds.actions", at, a)
			}
		}
		if al.Records != nil && len(al.Records.Hosts) == 0 && len(al.Records.Types) == 0 {
			add("%s.allow.records: hosts or types required when records is set", at)
		}
		if len(al.BindingSubjects) == 0 {
			add("%s.allow.binding_subjects: at least one matcher is required", at)
		}
		for j, m := range al.BindingSubjects {
			matcher(fmt.Sprintf("%s.allow.binding_subjects[%d]", at, j), m)
		}
		if al.Teams.FromSubject == nil && len(al.Teams.Names) == 0 {
			add("%s.allow.teams: from_subject or names is required", at)
		}
		if t := al.Teams.FromSubject; t != nil {
			if err := ValidateTeamFrom(t.Claim, t.Regex, t.Prefix); err != nil {
				add("%s.allow.teams.from_subject: %v", at, err)
			}
		}
		for _, n := range al.Teams.Names {
			if !teamGlobRe.MatchString(n) || n == "*" {
				add("%s.allow.teams.names: %q must be a lowercase team name or glob (not \"*\" alone)", at, n)
			}
		}
		for _, r := range al.Roles {
			if !nameRe.MatchString(r) {
				add("%s.allow.roles: %q must be a lowercase identifier", at, r)
			}
		}
		for _, g := range al.Groups {
			if !nameRe.MatchString(g) {
				add("%s.allow.groups: %q must be a lowercase identifier", at, g)
			}
		}
		if al.MaxObjects < 1 || al.MaxObjects > 1000 {
			add("%s.allow.max_objects: must be between 1 and 1000", at)
		}
	}
	return errs
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// teamPrefixRe is what may precede a derived team name: the start of a
// lowercase identifier.
var teamPrefixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// ValidateTeamFrom checks a team derivation: a claim name, an anchored RE2
// expression with exactly one capture group and an optional prefix.
func ValidateTeamFrom(claim, expr, prefix string) error {
	if strings.TrimSpace(claim) == "" {
		return errors.New("claim is required")
	}
	if !strings.HasPrefix(expr, "^") || !strings.HasSuffix(expr, "$") {
		return errors.New("regex must be anchored with ^ and $")
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("regex: %v", err)
	}
	if re.NumSubexp() != 1 {
		return fmt.Errorf("regex must have exactly one capture group, found %d (use (?:...) for the others)", re.NumSubexp())
	}
	if prefix != "" && !teamPrefixRe.MatchString(prefix) {
		return fmt.Errorf("prefix %q must be up to 32 characters [a-z0-9._-], starting with a letter or digit", prefix)
	}
	return nil
}

// validateEntra enforces fixed-tenant Entra ID issuers and audiences.
func validateEntra(is Issuer) error {
	u, err := url.Parse(is.Issuer)
	if err != nil {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "login.microsoftonline.com":
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) != 2 || parts[1] != "v2.0" || !guidRe.MatchString(strings.ToLower(parts[0])) {
			return fmt.Errorf("Entra issuer must be https://login.microsoftonline.com/<tenant-id>/v2.0 (tenant GUID; common, organizations and consumers are refused), got %q", is.Issuer)
		}
	case "sts.windows.net":
		if _, ok := entraV1Tenant(is.Issuer); !ok {
			return fmt.Errorf("Entra v1 issuer must be https://sts.windows.net/<tenant-id>/, got %q", is.Issuer)
		}
	default:
		return nil
	}
	for _, a := range is.Audiences {
		if !guidRe.MatchString(strings.ToLower(a)) && !strings.HasPrefix(a, "api://") {
			return fmt.Errorf("Entra audience %q must be the application id (GUID) or an api:// URI", a)
		}
	}
	return nil
}

// EntraV2Tenant returns the tenant of an Entra ID v2 issuer
// (https://login.microsoftonline.com/<tenant-id>/v2.0).
func EntraV2Tenant(issuer string) (string, bool) {
	u, err := url.Parse(issuer)
	if err != nil || strings.ToLower(u.Hostname()) != "login.microsoftonline.com" || u.Scheme != "https" {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[1] != "v2.0" || !guidRe.MatchString(strings.ToLower(parts[0])) {
		return "", false
	}
	return strings.ToLower(parts[0]), true
}

// EntraTenant returns the tenant of an Entra ID issuer, v1 or v2.
func EntraTenant(issuer string) (string, bool) {
	if tid, ok := EntraV2Tenant(issuer); ok {
		return tid, true
	}
	return entraV1Tenant(issuer)
}

func entraV1Tenant(issuer string) (string, bool) {
	u, err := url.Parse(issuer)
	if err != nil || strings.ToLower(u.Hostname()) != "sts.windows.net" || u.Scheme != "https" {
		return "", false
	}
	tid := strings.ToLower(strings.Trim(u.Path, "/"))
	if !guidRe.MatchString(tid) || !strings.HasSuffix(u.Path, "/") {
		return "", false
	}
	return tid, true
}

// SingleReplicaStore reports whether the store only supports one gate
// replica (in-process locks and state).
func (c *Config) SingleReplicaStore() bool {
	return c.Store.Type == "memory" || c.Store.Type == "sqlite"
}

// RoleNames returns sorted role names.
func (c *Config) RoleNames() []string {
	out := make([]string, 0, len(c.Roles))
	for n := range c.Roles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ValidFQDN reports whether s is a lowercase domain name with at least two labels.
func ValidFQDN(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !fqdnLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func normalizeListen(a string) string {
	if strings.HasPrefix(a, ":") {
		return "0.0.0.0" + a
	}
	return a
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

var (
	envNameRe   = regexp.MustCompile(`[^A-Z0-9]+`)
	hostedZone  = regexp.MustCompile(`^(/hostedzone/)?[A-Z0-9]{1,32}$`)
	roleARNRe   = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// envName is the environment variable fragment of a provider id.
func envName(id string) string {
	return strings.Trim(envNameRe.ReplaceAllString(strings.ToUpper(id), "_"), "_")
}

// ProvidersFor returns the ids of the providers whose zone filter selects
// zone.
func (c *Config) ProvidersFor(zone string) []string {
	var out []string
	for _, p := range c.Providers {
		if p.Matches(zone) {
			out = append(out, p.ID)
		}
	}
	return out
}

func (c *Config) validateProviders(add func(string, ...any)) {
	if len(c.Providers) == 0 {
		add("providers: at least one provider is required")
	}
	ids := map[string]bool{}
	pinned := map[string]string{}
	for i, p := range c.Providers {
		at := fmt.Sprintf("providers[%d]", i)
		if !nameRe.MatchString(p.ID) {
			add("%s.id: %q must be a lowercase identifier", at, p.ID)
		}
		if ids[p.ID] {
			add("%s.id: %q duplicated", at, p.ID)
		}
		ids[p.ID] = true
		for _, l := range []struct {
			name  string
			globs []string
		}{{"include", p.Zones.Include}, {"exclude", p.Zones.Exclude}} {
			for _, g := range l.globs {
				if g == "" || strings.ContainsAny(g, " ?/") {
					add("%s.zones.%s: %q: zone glob with * wildcards expected", at, l.name, g)
				}
			}
		}
		if p.Zones.Refresh.D() < 5*time.Minute {
			add("%s.zones.refresh: must be >= 5m (provider rate limits)", at)
		}
		switch p.Kind {
		case KindEuroDNS:
			if p.Route53 != nil {
				add("%s.route53: not allowed for kind eurodns", at)
			}
			if p.EuroDNS == nil {
				add("%s.eurodns: required for kind eurodns", at)
				continue
			}
			validateEuroDNS(at+".eurodns", p.ID, p.EuroDNS, add)
		case KindRoute53:
			if p.EuroDNS != nil {
				add("%s.eurodns: not allowed for kind route53", at)
			}
			if p.Route53 == nil {
				add("%s.route53: required for kind route53", at)
				continue
			}
			validateRoute53(at+".route53", p, add)
			for z := range p.Route53.HostedZones {
				if other, dup := pinned[z]; dup {
					add("%s.route53.hosted_zones: %q is also pinned by provider %s", at, z, other)
				}
				pinned[z] = p.ID
			}
		default:
			add("%s.kind: %q (expected eurodns or route53)", at, p.Kind)
		}
	}
}

func validateEuroDNS(at, id string, e *EuroDNSConfig, add func(string, ...any)) {
	if u, err := url.Parse(e.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
		add("%s.base_url: invalid URL %q", at, e.BaseURL)
	} else if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		add("%s.base_url: https required", at)
	}
	env := "EURODNS_" + envName(id)
	if e.AppID == "" {
		add("%s: app id missing (%s.app_id, %s_APP_ID or EURODNS_APP_ID, or their _FILE variants)", at, at, env)
	}
	if e.APIKey == "" {
		add("%s: api key missing (%s_API_KEY or EURODNS_API_KEY, or their _FILE variants)", at, env)
	}
	if e.Rate.Every.D() < 0 || e.Rate.Burst < 1 {
		add("%s.rate: every must be >= 0 and burst >= 1", at)
	}
	if *e.MaxRetries < 0 {
		add("%s.max_retries: must be >= 0", at)
	}
}

func validateRoute53(at string, p Provider, add func(string, ...any)) {
	r := p.Route53
	if r.Region != "" && !awsRegionRe.MatchString(r.Region) {
		add("%s.region: %q is not an AWS region", at, r.Region)
	}
	if r.AssumeRoleARN != "" && !roleARNRe.MatchString(r.AssumeRoleARN) {
		add("%s.assume_role_arn: %q is not an IAM role ARN", at, r.AssumeRoleARN)
	}
	if r.ExternalID != "" && r.AssumeRoleARN == "" {
		add("%s.external_id: requires assume_role_arn", at)
	}
	for z, id := range r.HostedZones {
		if !ValidFQDN(z) {
			add("%s.hosted_zones: %q is not a valid domain name", at, z)
		}
		if !hostedZone.MatchString(id) {
			add("%s.hosted_zones[%s]: %q is not a hosted zone id", at, z, id)
		}
		if !p.Matches(z) {
			add("%s.hosted_zones: %q is excluded by the zones filter of the provider", at, z)
		}
	}
}
