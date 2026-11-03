package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/glob"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

// Layers of the policy.
const (
	LayerBase    = "base"
	LayerManaged = "managed"
)

type compiledRole struct {
	name      string
	layer     string
	role      uiapi.Role
	ephemeral time.Duration
}

type compiledGroup struct {
	name    string
	layer   string
	members []uiapi.SubjectMatcher
}

type compiledBinding struct {
	index   int // index within its layer
	layer   string
	binding uiapi.Binding
	teamRe  *regexp.Regexp // binding.TeamFrom.Regex, nil without team_from
}

// Discovery is the list of zones found in the EuroDNS account
// (zones_discovery, see internal/discovery).
type Discovery interface {
	// Discovered reports whether zone is in the account, after the
	// include and exclude filters.
	Discovered(zone string) bool
	// DiscoveredZones returns them, sorted.
	DiscoveredZones() []string
}

type compiledKey struct {
	layer string
	key   uiapi.VirtualKey
}

// Snapshot is an immutable compiled policy (base + managed). Evaluation only
// reads a snapshot: no store call on the hot path.
type Snapshot struct {
	RevisionID string // active managed revision, "" for base only
	Base       uiapi.PolicyDocument
	Managed    *uiapi.PolicyDocument

	zones      map[string]bool // managed: base zones and managed document zones
	discovery  Discovery       // live account list, nil without zones_discovery
	roles      map[string]*compiledRole
	groups     map[string]*compiledGroup
	groupNames []string
	bindings   []compiledBinding
	keys       []compiledKey
	protected  []config.Protected
	bounds     config.Bounds
	maxChanges int
	issuers    map[string]config.Issuer
}

// BaseDocument converts the file policy to the document form.
func BaseDocument(c *config.Config) uiapi.PolicyDocument {
	d := uiapi.PolicyDocument{
		Groups:      map[string]uiapi.Group{},
		Roles:       map[string]uiapi.Role{},
		Bindings:    []uiapi.Binding{},
		VirtualKeys: []uiapi.VirtualKey{},
	}
	for name, g := range c.Groups {
		d.Groups[name] = uiapi.Group{Description: g.Description, Members: matchers(g.Members)}
	}
	for name, r := range c.Roles {
		ur := uiapi.Role{RebaseOnSave: r.RebaseOnSave, MaxChangesPerRequest: r.MaxChangesPerRequest}
		if r.EphemeralTTL > 0 {
			ur.EphemeralTTL = r.EphemeralTTL.D().String()
		}
		for _, rule := range r.Rules {
			nr := uiapi.Rule{Zones: rule.Zones, Actions: rule.Actions}
			if rule.Records != nil {
				nr.Records = &uiapi.RecordScope{Hosts: rule.Records.Hosts, Types: rule.Records.Types}
			}
			ur.Rules = append(ur.Rules, nr)
		}
		d.Roles[name] = ur
	}
	for _, b := range c.Bindings {
		ub := uiapi.Binding{Role: b.Role, Team: b.Team, Groups: b.Groups, Subjects: matchers(b.Subjects)}
		if b.TeamFrom != nil {
			ub.TeamFrom = &uiapi.TeamFrom{Claim: b.TeamFrom.Claim, Regex: b.TeamFrom.Regex, Prefix: b.TeamFrom.Prefix}
		}
		d.Bindings = append(d.Bindings, ub)
	}
	for _, k := range c.VirtualKeys {
		d.VirtualKeys = append(d.VirtualKeys, uiapi.VirtualKey{
			ID: k.ID, AppID: k.AppID, KeySHA256: k.KeySHA256, Roles: k.Roles, Teams: k.Teams,
			ExpiresAt: k.ExpiresAt, AllowedCIDRs: k.AllowedCIDRs,
		})
	}
	return d
}

func matchers(ss []config.Subject) []uiapi.SubjectMatcher {
	out := make([]uiapi.SubjectMatcher, 0, len(ss))
	for _, s := range ss {
		m := uiapi.SubjectMatcher{Issuer: s.Issuer, Claims: map[string][]string{}}
		for k, v := range s.Claims {
			m.Claims[k] = []string(v)
		}
		out = append(out, m)
	}
	return out
}

// compile builds a snapshot. The managed document must be validated first.
func compile(c *config.Config, base uiapi.PolicyDocument, managed *uiapi.PolicyDocument, revisionID string, disc Discovery) *Snapshot {
	s := &Snapshot{
		RevisionID: revisionID,
		Base:       base,
		Managed:    managed,
		zones:      map[string]bool{},
		discovery:  disc,
		roles:      map[string]*compiledRole{},
		groups:     map[string]*compiledGroup{},
		protected:  c.Protected,
		bounds:     c.Policy.Bounds,
		maxChanges: c.Limits.MaxChangesPerRequest,
		issuers:    map[string]config.Issuer{},
	}
	for _, z := range c.Zones {
		s.zones[z] = true
	}
	if managed != nil {
		for _, z := range managed.Zones {
			if z = normZone(z); z != "" {
				s.zones[z] = true
			}
		}
	}
	for _, is := range c.Issuers {
		s.issuers[is.Name] = is
	}
	add := func(doc *uiapi.PolicyDocument, layer string) {
		for name, r := range doc.Roles {
			cr := &compiledRole{name: name, layer: layer, role: r}
			if r.EphemeralTTL != "" {
				cr.ephemeral, _ = time.ParseDuration(r.EphemeralTTL)
			}
			s.roles[name] = cr
		}
		for name, g := range doc.Groups {
			s.groups[name] = &compiledGroup{name: name, layer: layer, members: g.Members}
		}
		for i, b := range doc.Bindings {
			cb := compiledBinding{index: i, layer: layer, binding: b}
			if b.TeamFrom != nil {
				// Validated documents always compile; an invalid expression
				// (unchecked compile of an old revision) binds nobody.
				cb.teamRe, _ = regexp.Compile(b.TeamFrom.Regex)
			}
			s.bindings = append(s.bindings, cb)
		}
		for _, k := range doc.VirtualKeys {
			s.keys = append(s.keys, compiledKey{layer: layer, key: k})
		}
	}
	add(&base, LayerBase)
	if managed != nil {
		add(managed, LayerManaged)
	}
	for name := range s.groups {
		s.groupNames = append(s.groupNames, name)
	}
	sort.Strings(s.groupNames)
	return s
}

// Zones returns the managed zones, sorted.
func (s *Snapshot) Zones() []string {
	out := make([]string, 0, len(s.zones))
	for z := range s.zones {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

// IsManaged reports whether the zone is managed (base or managed layer).
func (s *Snapshot) IsManaged(zone string) bool { return s.zones[normZone(zone)] }

// IsUnmanaged reports whether the zone exists in the account (discovery) but
// is not managed: it is readable, never writable nor adoptable.
func (s *Snapshot) IsUnmanaged(zone string) bool {
	zone = normZone(zone)
	return !s.zones[zone] && s.discovery != nil && s.discovery.Discovered(zone)
}

// UnmanagedZones returns the discovered zones that are not managed, sorted.
func (s *Snapshot) UnmanagedZones() []string {
	if s.discovery == nil {
		return nil
	}
	var out []string
	for _, z := range s.discovery.DiscoveredZones() {
		if !s.zones[z] {
			out = append(out, z)
		}
	}
	return out
}

// Resolution is the outcome of binding a subject.
type Resolution struct {
	Roles    []string // sorted
	Teams    []string // binding order
	Groups   []string // sorted
	Bindings []string // "role@team" (team may be empty)
}

// Resolve computes the groups, roles and teams of an OIDC subject.
func (s *Snapshot) Resolve(issuer string, claims map[string]any) Resolution {
	var r Resolution
	inGroup := map[string]bool{}
	for _, name := range s.groupNames {
		for _, m := range s.groups[name].members {
			if MatcherMatches(m, issuer, claims) {
				inGroup[name] = true
				r.Groups = append(r.Groups, name)
				break
			}
		}
	}
	roles, teams := map[string]bool{}, map[string]bool{}
	for _, b := range s.bindings {
		if !s.bindingApplies(b.binding, issuer, claims, inGroup) {
			continue
		}
		team := b.binding.Team
		if b.binding.TeamFrom != nil {
			var ok bool
			if team, ok = deriveTeam(b, claims); !ok {
				// Fail closed: without its own team the binding would act
				// for the team of another binding of the subject.
				continue
			}
		}
		if !roles[b.binding.Role] {
			roles[b.binding.Role] = true
			r.Roles = append(r.Roles, b.binding.Role)
		}
		if team != "" && !teams[team] {
			teams[team] = true
			r.Teams = append(r.Teams, team)
		}
		r.Bindings = append(r.Bindings, b.binding.Role+"@"+team)
	}
	sort.Strings(r.Roles)
	return r
}

// deriveTeam computes the team of a team_from binding: prefix plus the
// lowercased capture of the regex on a string claim, and it must be a valid
// team name.
func deriveTeam(b compiledBinding, claims map[string]any) (string, bool) {
	if b.teamRe == nil {
		return "", false
	}
	v, ok := claims[b.binding.TeamFrom.Claim].(string)
	if !ok {
		return "", false
	}
	m := b.teamRe.FindStringSubmatch(v)
	if len(m) != 2 || m[1] == "" {
		return "", false
	}
	team := b.binding.TeamFrom.Prefix + strings.ToLower(m[1])
	if !nameRe.MatchString(team) {
		return "", false
	}
	return team, true
}

// TeamFromString renders a team derivation, e.g. "ci-" + sub ~ ^repo:acme/(.+)$.
func TeamFromString(t *uiapi.TeamFrom) string {
	if t == nil {
		return ""
	}
	out := t.Claim + " ~ " + t.Regex
	if t.Prefix != "" {
		out = fmt.Sprintf("%q + %s", t.Prefix, out)
	}
	return out
}

func (s *Snapshot) bindingApplies(b uiapi.Binding, issuer string, claims map[string]any, inGroup map[string]bool) bool {
	for _, g := range b.Groups {
		if inGroup[g] {
			return true
		}
	}
	for _, m := range b.Subjects {
		if MatcherMatches(m, issuer, claims) {
			return true
		}
	}
	return false
}

// VirtualKeys returns the keys of both layers.
func (s *Snapshot) VirtualKeys() []uiapi.VirtualKey {
	out := make([]uiapi.VirtualKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k.key)
	}
	return out
}

// MatcherMatches reports whether claims of issuer match every claim glob.
func MatcherMatches(m uiapi.SubjectMatcher, issuer string, claims map[string]any) bool {
	if m.Issuer != issuer || len(m.Claims) == 0 {
		return false
	}
	for name, patterns := range m.Claims {
		if !ClaimMatches(claims[name], patterns) {
			return false
		}
	}
	return true
}

// ClaimMatches: a string claim must match one of the patterns; an array
// claim matches when it contains a value matching one of them. Booleans and
// numbers are compared as text, other types never match.
func ClaimMatches(v any, patterns []string) bool {
	for _, s := range ClaimStrings(v) {
		if glob.Any(patterns, s) {
			return true
		}
	}
	return false
}

// ClaimStrings returns the string values of a claim.
func ClaimStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case bool, float64:
		return []string{fmt.Sprint(t)}
	default:
		return nil
	}
}

// Decision explains an authorization result.
type Decision struct {
	Allowed bool
	Matched string // e.g. "roles.web.rules[0]"
	Denied  string
	Layer   string
}

// IsMeta reports whether an action is a policy.* action (base only, not
// zone-scoped).
func IsMeta(action string) bool { return strings.HasPrefix(action, "policy.") }

// Decide evaluates an action for a set of roles. key is nil for zone-level
// checks.
func (s *Snapshot) Decide(roles []string, action, zone string, key *rrset.Key) Decision {
	meta := IsMeta(action)
	zone = normZone(zone)
	if !meta && !s.zones[zone] {
		if !s.IsUnmanaged(zone) {
			return Decision{Denied: "zone not managed: " + zone}
		}
		if action != ActionDNSRead && action != ActionUIRead {
			return Decision{Denied: "zone not managed: " + zone + " (discovered in the account, read-only until a policy revision manages it)"}
		}
	}
	if key != nil && !meta {
		k := normKey(*key)
		key = &k
		if action != ActionDNSRead && action != ActionUIRead {
			if p, ok := s.protectedBy(zone, k); ok {
				return Decision{Denied: fmt.Sprintf("protected: zones=%s hosts=%s types=%s", strings.Join(p.Zones, ","), strings.Join(p.Hosts, ","), strings.Join(p.Types, ","))}
			}
		}
	}
	sorted := append([]string(nil), roles...)
	sort.Strings(sorted)
	for _, name := range sorted {
		cr := s.roles[name]
		if cr == nil || (meta && cr.layer != LayerBase) {
			continue
		}
		for i, r := range cr.role.Rules {
			if !contains(r.Actions, action) {
				continue
			}
			if !meta && !glob.Any(r.Zones, zone) {
				continue
			}
			if cr.layer == LayerManaged && !s.withinBounds(r, action) {
				continue
			}
			if key != nil && !meta && r.Records != nil && !scopeMatches(*r.Records, *key) {
				continue
			}
			return Decision{Allowed: true, Matched: fmt.Sprintf("roles.%s.rules[%d]", name, i), Layer: cr.layer}
		}
	}
	return Decision{Denied: "no rule grants " + action}
}

// Permissions lists the effective rules of roles, sorted by role. Managed
// rules lose the actions Decide ignores (policy.*, outside the bounds).
func (s *Snapshot) Permissions(roles []string) []uiapi.Permission {
	out := []uiapi.Permission{}
	sorted := append([]string(nil), roles...)
	sort.Strings(sorted)
	for _, name := range sorted {
		cr := s.roles[name]
		if cr == nil {
			continue
		}
		for _, r := range cr.role.Rules {
			actions := []string{}
			for _, a := range r.Actions {
				if cr.layer != LayerManaged || s.withinBounds(r, a) {
					actions = append(actions, a)
				}
			}
			if len(actions) == 0 {
				continue
			}
			p := uiapi.Permission{Role: name, Zones: append([]string{}, r.Zones...), Actions: actions, Hosts: []string{}, Types: []string{}}
			if r.Records != nil {
				p.Hosts = append(p.Hosts, r.Records.Hosts...)
				p.Types = append(p.Types, r.Records.Types...)
			}
			out = append(out, p)
		}
	}
	return out
}

// withinBounds re-checks a managed rule against the base bounds (defense
// in depth: documents are validated before activation).
func (s *Snapshot) withinBounds(r uiapi.Rule, action string) bool {
	if IsMeta(action) || !contains(s.bounds.Actions, action) {
		return false
	}
	for _, z := range r.Zones {
		if !ZoneCovered(s.bounds.Zones, z) {
			return false
		}
	}
	return true
}

// ZoneCovered reports whether a zone pattern only matches zones that one of
// the bound globs matches. Only "*" wildcards are supported: matching the
// pattern text with a bound glob is then a sound inclusion test.
func ZoneCovered(bounds []string, pattern string) bool {
	if strings.Contains(pattern, "?") {
		return false
	}
	for _, b := range bounds {
		if !strings.Contains(b, "?") && glob.Match(b, pattern) {
			return true
		}
	}
	return false
}

func (s *Snapshot) protectedBy(zone string, key rrset.Key) (config.Protected, bool) {
	for _, p := range s.protected {
		if glob.Any(p.Zones, zone) && hostMatches(p.Hosts, key.Host) && typeMatches(p.Types, key.Type) {
			return p, true
		}
	}
	return config.Protected{}, false
}

func (s *Snapshot) role(name string) *compiledRole { return s.roles[name] }

func scopeMatches(sc uiapi.RecordScope, key rrset.Key) bool {
	if len(sc.Hosts) > 0 && !hostMatches(sc.Hosts, key.Host) {
		return false
	}
	if len(sc.Types) > 0 && !typeMatches(sc.Types, key.Type) {
		return false
	}
	return true
}

func rrsetKey(host, typ string) rrset.Key { return rrset.Key{Host: host, Type: typ} }

// Explain simulates the decision for an OIDC subject with concrete claims.
func (s *Snapshot) Explain(issuer string, claims map[string]any, action, zone, host, typ string) uiapi.ExplainResponse {
	resp := uiapi.ExplainResponse{Groups: []string{}, Bindings: []string{}}
	is, ok := s.issuers[issuer]
	if !ok {
		resp.Denied = "unknown issuer " + issuer
		return resp
	}
	for name, pats := range is.BoundClaims {
		if !ClaimMatches(claims[name], pats) {
			resp.Denied = "issuer bound_claims: " + name
			return resp
		}
	}
	res := s.Resolve(issuer, claims)
	if res.Groups != nil {
		resp.Groups = res.Groups
	}
	if res.Bindings != nil {
		resp.Bindings = res.Bindings
	}
	var key *rrset.Key
	if host != "" || typ != "" {
		k := rrsetKey(host, typ)
		key = &k
	}
	d := s.Decide(res.Roles, action, zone, key)
	resp.Allowed, resp.Matched, resp.Denied, resp.Layer = d.Allowed, d.Matched, d.Denied, d.Layer
	if len(res.Roles) == 0 && !d.Allowed {
		resp.Denied = "no binding applies to this subject"
	}
	return resp
}
