package policy

import (
	"sort"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// ActionOwnershipApprove lets a subject adopt RRsets for another team than
// its own and approve the ownership transfers of a zone.
const ActionOwnershipApprove = "dns.ownership.approve"

// teamMember reports whether an OIDC subject is a member of a declared team.
func (s *Snapshot) teamMember(team, issuer string, claims map[string]any, inGroup map[string]bool) bool {
	t := s.teams[team]
	if team == "" || t == nil {
		return false
	}
	for _, g := range t.team.Members.Groups {
		if inGroup[g] {
			return true
		}
	}
	for _, m := range t.team.Members.Subjects {
		if MatcherMatches(m, issuer, claims) {
			return true
		}
	}
	return false
}

// StrictTeams reports whether team references must be declared (the base
// file has a teams block).
func (s *Snapshot) StrictTeams() bool { return s.strict }

// TeamDeclared reports whether a team is declared, in the base file or the
// managed layer.
func (s *Snapshot) TeamDeclared(name string) bool { return s.teams[name] != nil }

// TeamMembers returns the members of a declared team.
func (s *Snapshot) TeamMembers(name string) (uiapi.TeamMembers, bool) {
	t := s.teams[name]
	if t == nil {
		return uiapi.TeamMembers{}, false
	}
	return t.team.Members, true
}

// KnownTeam reports whether name may own RRsets: a valid team name that is
// declared or belongs to a team_from family. Before the teams block exists
// (migration) every valid name is accepted.
func (s *Snapshot) KnownTeam(name string) bool {
	if !nameRe.MatchString(name) {
		return false
	}
	return !s.strict || s.teams[name] != nil || s.familyOf(name) != nil
}

// familyOf returns the derivation (team_from of a binding, from_subject of
// a delegation) whose prefix name carries.
func (s *Snapshot) familyOf(name string) *uiapi.TeamFrom {
	var best *uiapi.TeamFrom
	consider := func(tf *uiapi.TeamFrom) {
		if tf == nil || len(name) <= len(tf.Prefix) || !strings.HasPrefix(name, tf.Prefix) {
			return
		}
		if best == nil || len(tf.Prefix) > len(best.Prefix) {
			best = tf
		}
	}
	for _, b := range s.bindings {
		consider(b.binding.TeamFrom)
	}
	for _, name := range s.delegationNames {
		consider(uiTeamFrom(s.delegations[name].Allow.Teams.FromSubject))
	}
	return best
}

// ClaimTeamAllowed reports whether a team taken from the team_claim of an
// issuer is kept: always before the teams block exists; afterwards only a
// member of a family that is not a declared team, so that a claim never
// makes its holder a member of a declared team.
func (s *Snapshot) ClaimTeamAllowed(name string) bool {
	if !s.strict {
		return true
	}
	return nameRe.MatchString(name) && s.teams[name] == nil && s.familyOf(name) != nil
}

// referencedTeams returns the fixed teams named by bindings and virtual
// keys, with the roles and keys naming them.
func (s *Snapshot) referencedTeams() map[string]*uiapi.TeamInfo {
	out := map[string]*uiapi.TeamInfo{}
	get := func(team string) *uiapi.TeamInfo {
		ti := out[team]
		if ti == nil {
			ti = &uiapi.TeamInfo{Name: team, Roles: []string{}}
			out[team] = ti
		}
		return ti
	}
	for _, b := range s.bindings {
		if b.binding.Team == "" || b.binding.TeamFrom != nil {
			continue
		}
		ti := get(b.binding.Team)
		if !contains(ti.Roles, b.binding.Role) {
			ti.Roles = append(ti.Roles, b.binding.Role)
		}
	}
	for _, k := range s.keys {
		for _, t := range k.key.Teams {
			ti := get(t)
			if !contains(ti.VirtualKeys, k.key.ID) {
				ti.VirtualKeys = append(ti.VirtualKeys, k.key.ID)
			}
			for _, r := range k.key.Roles {
				if !contains(ti.Roles, r) {
					ti.Roles = append(ti.Roles, r)
				}
			}
		}
	}
	for _, ti := range out {
		sort.Strings(ti.Roles)
		sort.Strings(ti.VirtualKeys)
	}
	return out
}

// UndeclaredTeams returns the teams bindings or virtual keys name without
// a declaration, sorted.
func (s *Snapshot) UndeclaredTeams() []string {
	var out []string
	for name := range s.referencedTeams() {
		if s.teams[name] == nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

const (
	warnAutoTeam  = "referenced but not declared: declared automatically until the teams block exists"
	warnStoreTeam = "owns RRsets but no binding, virtual key or declaration names it"
)

// TeamInfos lists the teams: declared teams, teams referenced without a
// declaration, team_from families and team_claim issuers, then the owners
// found in the store (storeOwners) that none of them covers. Members are
// included with withMembers (policy.read).
func (s *Snapshot) TeamInfos(storeOwners []string, withMembers bool) []uiapi.TeamInfo {
	refs := s.referencedTeams()
	var out []uiapi.TeamInfo
	listed := map[string]bool{}
	for _, name := range sortedKeys(s.teams) {
		out = append(out, s.declaredInfo(name, refs[name], withMembers))
		listed[name] = true
	}
	for _, name := range sortedKeys(refs) {
		if !listed[name] {
			ti := *refs[name]
			ti.Kind, ti.Warning = uiapi.TeamKindAuto, warnAutoTeam
			out = append(out, ti)
			listed[name] = true
		}
	}
	families := map[string]bool{}
	for _, b := range s.bindings {
		tf := b.binding.TeamFrom
		if tf == nil {
			continue
		}
		key := TeamFromString(tf)
		if families[key] {
			continue
		}
		families[key] = true
		out = append(out, uiapi.TeamInfo{Name: tf.Prefix + "*", Kind: uiapi.TeamKindFamily, Family: tf, Roles: s.familyRoles(tf)})
	}
	for _, name := range sortedKeys(s.issuers) {
		if is := s.issuers[name]; is.TeamClaim != "" {
			ti := uiapi.TeamInfo{Name: "*", Kind: uiapi.TeamKindClaim, Issuer: name, Roles: []string{},
				Description: "teams of claim " + is.TeamClaim + " of issuer " + name}
			if s.strict {
				ti.Warning = "only members of a team_from family are kept, never a declared team"
			}
			out = append(out, ti)
		}
	}
	owners := append([]string(nil), storeOwners...)
	sort.Strings(owners)
	for _, o := range owners {
		if listed[o] || o == "" {
			continue
		}
		listed[o] = true
		if tf := s.familyOf(o); tf != nil {
			out = append(out, uiapi.TeamInfo{Name: o, Kind: uiapi.TeamKindFamily, Family: tf, Roles: s.familyRoles(tf)})
			continue
		}
		out = append(out, uiapi.TeamInfo{Name: o, Kind: uiapi.TeamKindStore, Roles: []string{}, Warning: warnStoreTeam})
	}
	if out == nil {
		out = []uiapi.TeamInfo{}
	}
	return out
}

// TeamInfo describes one team: declared, referenced, a member of a
// family, or one of storeOwners. False when the name is none of them.
func (s *Snapshot) TeamInfo(name string, storeOwners []string, withMembers bool) (uiapi.TeamInfo, bool) {
	refs := s.referencedTeams()
	if s.teams[name] != nil {
		return s.declaredInfo(name, refs[name], withMembers), true
	}
	if ti, ok := refs[name]; ok {
		out := *ti
		out.Kind, out.Warning = uiapi.TeamKindAuto, warnAutoTeam
		return out, true
	}
	if tf := s.familyOf(name); tf != nil && nameRe.MatchString(name) {
		return uiapi.TeamInfo{Name: name, Kind: uiapi.TeamKindFamily, Family: tf, Roles: s.familyRoles(tf)}, true
	}
	if contains(storeOwners, name) {
		return uiapi.TeamInfo{Name: name, Kind: uiapi.TeamKindStore, Roles: []string{}, Warning: warnStoreTeam}, true
	}
	return uiapi.TeamInfo{}, false
}

func (s *Snapshot) declaredInfo(name string, ref *uiapi.TeamInfo, withMembers bool) uiapi.TeamInfo {
	t := s.teams[name]
	ti := uiapi.TeamInfo{Name: name, Kind: uiapi.TeamKindDeclared, Layer: t.layer, Description: t.team.Description, Roles: []string{}}
	if ref != nil {
		ti.Roles, ti.VirtualKeys = ref.Roles, ref.VirtualKeys
	}
	if withMembers {
		m := t.team.Members
		ti.Members = &m
	}
	return ti
}

func (s *Snapshot) familyRoles(tf *uiapi.TeamFrom) []string {
	out := []string{}
	key := TeamFromString(tf)
	for _, b := range s.bindings {
		if b.binding.TeamFrom != nil && TeamFromString(b.binding.TeamFrom) == key && !contains(out, b.binding.Role) {
			out = append(out, b.binding.Role)
		}
	}
	sort.Strings(out)
	return out
}
