package policy

import (
	"fmt"
	"strings"

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

// GrantsPattern reports whether one of roles grants action on every zone
// the zone pattern matches.
func (s *Snapshot) GrantsPattern(roles []string, action, pattern string) bool {
	return s.grantsRule(roles, action, strings.ToLower(pattern), nil)
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

func (s *Snapshot) grantsRule(roles []string, action, pattern string, records *uiapi.RecordScope) bool {
	if IsMeta(action) {
		return false
	}
	for _, name := range roles {
		cr := s.roles[name]
		if cr == nil {
			continue
		}
		for _, r := range cr.role.Rules {
			if contains(r.Actions, action) && s.ruleEffective(cr, r, action) && ZoneCovered(r.Zones, pattern) && scopeCovered(r.Records, records) {
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
// gate.* actions; the holder must hold gate.apikey.manage on every zone
// pattern of the role, and every action of the role on the same zones and
// records: a key never has more rights than the subject that issued it.
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
	if max := s.MaxChanges(holder); max > 0 {
		if k := s.MaxChanges([]string{role}); k <= 0 || k > max {
			return fmt.Sprintf("role %s allows more changes per request than the caller (max_changes_per_request %d)", role, max)
		}
	}
	for i, r := range cr.role.Rules {
		for _, z := range r.Zones {
			if !s.GrantsPattern(holder, ActionAPIKeyManage, z) {
				return fmt.Sprintf("%s not granted on zones %q of role %s", ActionAPIKeyManage, z, role)
			}
		}
		for _, a := range r.Actions {
			if IsMeta(a) || IsGate(a) {
				return fmt.Sprintf("role %s grants %s, which API keys cannot hold", role, a)
			}
			for _, z := range r.Zones {
				if !s.grantsRule(holder, a, strings.ToLower(z), r.Records) {
					return fmt.Sprintf("role %s rules[%d] grants %s on %q beyond the caller's own rights", role, i, a, z)
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
