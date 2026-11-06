package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// ActionAPIKeyManage lets a subject create, change, rotate and revoke the
// API keys of its teams, for roles whose zones it manages. It is checked on
// the zone patterns of the key role, not on one zone.
const ActionAPIKeyManage = "gate.apikey.manage"

// IsGate reports whether an action is a gate.* action. API keys never hold
// one: a key cannot manage keys.
func IsGate(action string) bool { return strings.HasPrefix(action, "gate.") }

// HasRole reports whether a role exists in either layer.
func (s *Snapshot) HasRole(name string) bool { return s.roles[name] != nil }

// RoleZones returns the zone patterns of the rules of a role, nil if the
// role does not exist.
func (s *Snapshot) RoleZones(name string) []string {
	cr := s.roles[name]
	if cr == nil {
		return nil
	}
	var out []string
	for _, r := range cr.role.Rules {
		out = append(out, r.Zones...)
	}
	return out
}

// RoleFolders returns the folder patterns of the rules of a role.
func (s *Snapshot) RoleFolders(name string) []string {
	cr := s.roles[name]
	if cr == nil {
		return nil
	}
	var out []string
	for _, r := range cr.role.Rules {
		out = append(out, r.Folders...)
	}
	return out
}

// GrantsPattern reports whether one of roles grants action on every zone
// the zone pattern matches.
func (s *Snapshot) GrantsPattern(roles []string, action, pattern string) bool {
	return s.grantsRule(roles, action, zoneSelector(pattern), nil)
}

// GrantsFolderPattern reports whether one of roles grants action on every
// zone whose folder the folder pattern matches.
func (s *Snapshot) GrantsFolderPattern(roles []string, action, pattern string) bool {
	return s.grantsRule(roles, action, selector{pattern: pattern, folder: true}, nil)
}

// selector is a zone pattern of a rule or, with folder, a folder pattern.
type selector struct {
	pattern string
	folder  bool
}

func zoneSelector(pattern string) selector { return selector{pattern: strings.ToLower(pattern)} }

func (sel selector) String() string {
	if sel.folder {
		return fmt.Sprintf("folders %q", sel.pattern)
	}
	return fmt.Sprintf("zones %q", sel.pattern)
}

// selectors lists the zone and folder patterns of a rule.
func selectors(r uiapi.Rule) []selector {
	out := make([]selector, 0, len(r.Zones)+len(r.Folders))
	for _, z := range r.Zones {
		out = append(out, zoneSelector(z))
	}
	for _, f := range r.Folders {
		out = append(out, selector{pattern: f, folder: true})
	}
	return out
}

// ruleCovers reports whether a rule applies to every zone the selector
// does: a zone pattern covered by its zones, a folder pattern covered by
// its folders or a rule on every zone ("*").
func ruleCovers(r uiapi.Rule, sel selector) bool {
	if sel.folder {
		return glob.FolderCovered(r.Folders, sel.pattern) || ZoneCovered(r.Zones, "*")
	}
	return ZoneCovered(r.Zones, sel.pattern)
}

// GrantsAnywhere reports whether one of roles grants action on some zone.
func (s *Snapshot) GrantsAnywhere(roles []string, action string) bool {
	for _, name := range roles {
		cr := s.roles[name]
		if cr == nil {
			continue
		}
		for _, r := range cr.role.Rules {
			if contains(r.Actions, action) && s.ruleEffective(cr, r, action) {
				return true
			}
		}
	}
	return false
}

func (s *Snapshot) grantsRule(roles []string, action string, sel selector, records *uiapi.RecordScope) bool {
	if IsMeta(action) {
		return false
	}
	for _, name := range roles {
		cr := s.roles[name]
		if cr == nil {
			continue
		}
		for _, r := range cr.role.Rules {
			if contains(r.Actions, action) && s.ruleEffective(cr, r, action) && ruleCovers(r, sel) && scopeCovered(r.Records, records) {
				return true
			}
		}
	}
	return false
}

// scopeCovered reports whether the record scope k (nil: every record) is
// within the scope h.
func scopeCovered(h, k *uiapi.RecordScope) bool {
	if h == nil {
		return true
	}
	if len(h.Hosts) > 0 {
		if k == nil || len(k.Hosts) == 0 {
			return false
		}
		for _, p := range k.Hosts {
			if !HostCovered(h.Hosts, p) {
				return false
			}
		}
	}
	if len(h.Types) > 0 {
		if k == nil || len(k.Types) == 0 {
			return false
		}
		for _, t := range k.Types {
			if !typeCovered(h.Types, t) {
				return false
			}
		}
	}
	return true
}

// KeyRoleProblem explains why a holder of roles may not give role to an API
// key, "" when it may. The role must exist and grant neither policy.* nor
// gate.* actions; the holder must hold gate.apikey.manage on every zone and
// folder pattern of the role, and every action of the role on the same zones,
// folders and records: a key never has more rights than the subject that
// issued it.
func (s *Snapshot) KeyRoleProblem(holder []string, role string) string {
	cr := s.roles[role]
	if cr == nil {
		return fmt.Sprintf("unknown role %q", role)
	}
	if ttl := s.EphemeralTTL(holder); ttl > 0 && s.writes(role) {
		if k := s.EphemeralTTL([]string{role}); k <= 0 || k > ttl {
			return fmt.Sprintf("role %s must be ephemeral with an ephemeral_ttl of at most %s, as the caller's write rights", role, ttl)
		}
	}
	if max := s.MaxChanges(holder); max > 0 && s.writes(role) {
		if k := s.MaxChanges([]string{role}); k <= 0 || k > max {
			return fmt.Sprintf("role %s allows more changes per request than the caller (max_changes_per_request %d)", role, max)
		}
	}
	for i, r := range cr.role.Rules {
		sels := selectors(r)
		for _, sel := range sels {
			if !s.grantsRule(holder, ActionAPIKeyManage, sel, nil) {
				return fmt.Sprintf("%s not granted on %s of role %s", ActionAPIKeyManage, sel, role)
			}
		}
		for _, a := range r.Actions {
			if IsMeta(a) || IsGate(a) {
				return fmt.Sprintf("role %s grants %s, which API keys cannot hold", role, a)
			}
			for _, sel := range sels {
				if !s.grantsRule(holder, a, sel, r.Records) {
					return fmt.Sprintf("role %s rules[%d] grants %s on %s beyond the caller's own rights", role, i, a, sel)
				}
			}
		}
	}
	return ""
}

// RoleReserved reports whether a role grants a policy.* or gate.* action,
// which an API key never holds even if its role gained one after issuance.
func (s *Snapshot) RoleReserved(name string) bool {
	cr := s.roles[name]
	if cr == nil {
		return false
	}
	for _, r := range cr.role.Rules {
		for _, a := range r.Actions {
			if IsMeta(a) || IsGate(a) {
				return true
			}
		}
	}
	return false
}

// writes reports whether a role grants dns.record.write.
func (s *Snapshot) writes(role string) bool {
	cr := s.roles[role]
	if cr == nil {
		return false
	}
	for _, r := range cr.role.Rules {
		if contains(r.Actions, ActionRecordWrite) {
			return true
		}
	}
	return false
}

// RoleGrant is what a role declares: its rules, ephemeral TTL (0 for
// permanent) and change limit (0 to inherit the global default, -1 for
// unlimited). An API key records the grant of its role at issuance; values
// resolved through the global limits or the bounds of the managed layer are
// left out, so changing those never invalidates keys.
type RoleGrant struct {
	Rules        []uiapi.Rule  `json:"rules"`
	EphemeralTTL time.Duration `json:"ephemeral_ttl"`
	MaxChanges   int           `json:"max_changes"`
}

// RoleGrant returns the declared grant of a role, false if it does not
// exist.
func (s *Snapshot) RoleGrant(name string) (RoleGrant, bool) {
	cr := s.roles[name]
	if cr == nil {
		return RoleGrant{}, false
	}
	g := RoleGrant{Rules: []uiapi.Rule{}, EphemeralTTL: cr.ephemeral, MaxChanges: cr.role.MaxChangesPerRequest}
	for _, r := range cr.role.Rules {
		g.Rules = append(g.Rules, uiapi.Rule{Zones: r.Zones, Folders: r.Folders, Actions: r.Actions, Records: r.Records})
	}
	return g, true
}

// Within reports whether g declares nothing beyond limit: every action of
// every rule on the same zones, folders and records, an ephemeral TTL no longer (when
// limit is ephemeral and g writes), and a change limit no looser: an
// unlimited limit accepts any, an inherited one only inherited, an explicit
// one an explicit value no higher.
func (g RoleGrant) Within(limit RoleGrant) bool {
	writes := false
	for _, r := range g.Rules {
		for _, a := range r.Actions {
			writes = writes || a == ActionRecordWrite
			for _, sel := range selectors(r) {
				if !rulesCover(limit.Rules, a, sel, r.Records) {
					return false
				}
			}
		}
	}
	if writes && limit.EphemeralTTL > 0 && (g.EphemeralTTL <= 0 || g.EphemeralTTL > limit.EphemeralTTL) {
		return false
	}
	switch {
	case limit.MaxChanges == -1:
		return true
	case limit.MaxChanges == 0:
		return g.MaxChanges == 0
	default:
		return g.MaxChanges > 0 && g.MaxChanges <= limit.MaxChanges
	}
}

func rulesCover(rules []uiapi.Rule, action string, sel selector, records *uiapi.RecordScope) bool {
	for _, r := range rules {
		if contains(r.Actions, action) && ruleCovers(r, sel) && scopeCovered(r.Records, records) {
			return true
		}
	}
	return false
}
