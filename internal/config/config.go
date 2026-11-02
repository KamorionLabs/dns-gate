// Package config loads and validates the eurodns-gate configuration.
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
)

// Config is the root configuration document.
type Config struct {
	Listen            Listen           `yaml:"listen"`
	Upstream          Upstream         `yaml:"upstream"`
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
}

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

	ClientSecret string `yaml:"-"` // EURODNS_GATE_UI_CLIENT_SECRET(_FILE), optional (public client)
	SessionKey   []byte `yaml:"-"` // EURODNS_GATE_SESSION_KEY(_FILE), 32 bytes, hex or base64
}

// Listen configures the HTTP server.
type Listen struct {
	Address        string   `yaml:"address"`
	TrustedProxies []string `yaml:"trusted_proxies"` // CIDRs allowed to set X-Forwarded-For
}

// Upstream configures the EuroDNS API. The API key is never read from the
// file: it comes from EURODNS_API_KEY or EURODNS_API_KEY_FILE.
type Upstream struct {
	BaseURL    string `yaml:"base_url"`
	AppID      string `yaml:"app_id"`
	Rate       Rate   `yaml:"rate"`
	MaxRetries *int   `yaml:"max_retries"`

	APIKey string `yaml:"-"`
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
// EURODNS_GATE_POSTGRES_DSN or EURODNS_GATE_POSTGRES_DSN_FILE only.
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
// RRsets they create).
type Binding struct {
	Role     string    `yaml:"role"`
	Team     string    `yaml:"team"`
	Groups   []string  `yaml:"groups"`
	Subjects []Subject `yaml:"subjects"`
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

// Known actions.
var knownActions = map[string]bool{
	"dns.read":         true,
	"dns.record.write": true,
	"dns.record.adopt": true,
	"dns.zone.admin":   true,
	"ui.read":          true,
	"policy.read":      true,
	"policy.propose":   true,
	"policy.approve":   true,
	"domain.read":      true,
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
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyEnv(getenv func(string) string) error {
	read := func(name string) (string, error) {
		if v := getenv(name); v != "" {
			return v, nil
		}
		if f := getenv(name + "_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return "", fmt.Errorf("config: %s_FILE: %w", name, err)
			}
			return strings.TrimSpace(string(b)), nil
		}
		return "", nil
	}
	v, err := read("EURODNS_APP_ID")
	if err != nil {
		return err
	}
	if v != "" {
		c.Upstream.AppID = v
	}
	if c.Upstream.APIKey, err = read("EURODNS_API_KEY"); err != nil {
		return err
	}
	if c.Store.Postgres.DSN, err = read("EURODNS_GATE_POSTGRES_DSN"); err != nil {
		return err
	}
	if c.UI.ClientSecret, err = read("EURODNS_GATE_UI_CLIENT_SECRET"); err != nil {
		return err
	}
	k, err := read("EURODNS_GATE_SESSION_KEY")
	if err != nil {
		return err
	}
	if k != "" {
		if c.UI.SessionKey, err = decodeKey(k); err != nil {
			return fmt.Errorf("config: EURODNS_GATE_SESSION_KEY: %w", err)
		}
	}
	return nil
}

func (c *Config) defaults() {
	if c.Listen.Address == "" {
		c.Listen.Address = ":8080"
	}
	if c.Upstream.BaseURL == "" {
		c.Upstream.BaseURL = "https://rest-api.eurodns.com"
	}
	if c.Upstream.Rate.Every == 0 {
		c.Upstream.Rate.Every = Duration(1100 * time.Millisecond)
	}
	if c.Upstream.Rate.Burst == 0 {
		c.Upstream.Rate.Burst = 5
	}
	if c.Upstream.MaxRetries == nil {
		n := 3
		c.Upstream.MaxRetries = &n
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
	for i := range c.Zones {
		c.Zones[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Zones[i])), ".")
	}
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
	if u, err := url.Parse(c.Upstream.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
		add("upstream.base_url: invalid URL %q", c.Upstream.BaseURL)
	} else if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		add("upstream.base_url: https required")
	}
	if c.Upstream.AppID == "" {
		add("upstream: app id missing (upstream.app_id, EURODNS_APP_ID or EURODNS_APP_ID_FILE)")
	}
	if c.Upstream.APIKey == "" {
		add("upstream: api key missing (EURODNS_API_KEY or EURODNS_API_KEY_FILE)")
	}
	if c.Upstream.Rate.Every.D() < 0 || c.Upstream.Rate.Burst < 1 {
		add("upstream.rate: every must be >= 0 and burst >= 1")
	}
	if *c.Upstream.MaxRetries < 0 {
		add("upstream.max_retries: must be >= 0")
	}

	if len(c.Zones) == 0 {
		add("zones: at least one managed zone is required")
	}
	seenZone := map[string]bool{}
	for _, z := range c.Zones {
		if !ValidFQDN(z) {
			add("zones: %q is not a valid domain name", z)
		}
		if seenZone[z] {
			add("zones: %q listed twice", z)
		}
		seenZone[z] = true
	}

	switch c.Store.Type {
	case "memory":
	case "sqlite":
		if c.Store.SQLite.Path == "" {
			add("store.sqlite.path: required")
		}
	case "postgres":
		if c.Store.Postgres.DSN == "" {
			add("store.postgres: DSN missing (EURODNS_GATE_POSTGRES_DSN or EURODNS_GATE_POSTGRES_DSN_FILE)")
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
	for i, is := range c.Issuers {
		at := fmt.Sprintf("issuers[%d]", i)
		if !nameRe.MatchString(is.Name) {
			add("%s.name: %q must be a lowercase identifier", at, is.Name)
		}
		if issuers[is.Name] {
			add("%s.name: %q duplicated", at, is.Name)
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

	if c.UI.Enabled {
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
			add("ui: session key missing or not 32 bytes (EURODNS_GATE_SESSION_KEY or EURODNS_GATE_SESSION_KEY_FILE)")
		}
		if c.UI.SessionTTL.D() < time.Minute || c.UI.SessionTTL.D() > 24*time.Hour {
			add("ui.session_ttl: must be between 1m and 24h")
		}
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
