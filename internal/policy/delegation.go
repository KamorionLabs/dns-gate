package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// managedByRe bounds the client label of delegated objects.
var managedByRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,64}$`)

// addDelegated compiles the delegated roles and bindings of a managed
// document. They come after the other managed bindings, sorted by name. An
// unchecked compile (old revision) never lets a delegated role shadow
// another role.
func (s *Snapshot) addDelegated(doc *uiapi.PolicyDocument) {
	if doc.Delegated == nil {
		return
	}
	for _, name := range sortedKeys(doc.Delegated.Roles) {
		if _, taken := s.roles[name]; taken {
			continue
		}
		dr := doc.Delegated.Roles[name]
		cr := &compiledRole{name: name, layer: LayerManaged, role: dr.Role, delegation: dr.Owner.Delegation}
		if dr.EphemeralTTL != "" {
			cr.ephemeral, _ = time.ParseDuration(dr.EphemeralTTL)
		}
		s.roles[name] = cr
	}
	idx := len(doc.Bindings)
	for _, name := range sortedKeys(doc.Delegated.Bindings) {
		db := doc.Delegated.Bindings[name]
		cb := compiledBinding{index: idx, layer: LayerManaged, binding: db.Binding, name: name, delegation: db.Owner.Delegation}
		if db.TeamFrom != nil {
			cb.teamRe, _ = regexp.Compile(db.TeamFrom.Regex)
		}
		s.bindings = append(s.bindings, cb)
		idx++
	}
}

// DelegationsFor returns the delegations whose subjects match an OIDC
// subject, in file order.
func (s *Snapshot) DelegationsFor(issuer string, claims map[string]any) []string {
	var out []string
	for _, name := range s.delegationNames {
		for _, m := range s.delegations[name].Subjects {
			if MatcherMatches(subjectMatcher(m), issuer, claims) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// Delegation returns a delegation of the base file, nil if unknown (or the
// managed policy is disabled).
func (s *Snapshot) Delegation(name string) *config.Delegation { return s.delegations[name] }

// withinDelegation re-checks a delegated rule against its delegation
// (defense in depth: documents are validated before activation). A rule of
// a delegation removed from the file grants nothing.
func (s *Snapshot) withinDelegation(name string, r uiapi.Rule, action string) bool {
	d := s.delegations[name]
	return d != nil && ruleWithinDelegation(d, r, action)
}

func ruleWithinDelegation(d *config.Delegation, r uiapi.Rule, action string) bool {
	if !contains(d.Allow.Actions, action) {
		return false
	}
	for _, z := range r.Zones {
		if !ZoneCovered(d.Allow.Zones, strings.ToLower(z)) {
			return false
		}
	}
	return recordsWithinDelegation(d, r.Records)
}

// recordsWithinDelegation checks the record scope of a rule against
// allow.records: every host and type of the rule must be covered, and a rule
// without hosts (or types) is refused when the delegation restricts them.
func recordsWithinDelegation(d *config.Delegation, sc *uiapi.RecordScope) bool {
	lim := d.Allow.Records
	if lim == nil {
		return true
	}
	if len(lim.Hosts) > 0 {
		if sc == nil || len(sc.Hosts) == 0 {
			return false
		}
		for _, h := range sc.Hosts {
			if !HostCovered(lim.Hosts, h) {
				return false
			}
		}
	}
	if len(lim.Types) > 0 {
		if sc == nil || len(sc.Types) == 0 {
			return false
		}
		for _, t := range sc.Types {
			if !typeCovered(lim.Types, t) {
				return false
			}
		}
	}
	return true
}

func typeCovered(allowed []string, t string) bool {
	for _, a := range allowed {
		if a == "*" || (t != "*" && strings.EqualFold(a, t)) {
			return true
		}
	}
	return false
}

// HostCovered reports whether every host matched by the host pattern p is
// matched by one of the allowed host patterns (same syntax as rules: "@" is
// the apex, "*" one label, "**" one or more labels, a bare "**" every host,
// "*" inside a label any run of characters). It is conservative: it may
// refuse a pattern that is in fact covered, never the reverse.
func HostCovered(allowed []string, p string) bool {
	p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
	if p == "" || strings.Contains(p, "?") {
		return false
	}
	for _, a := range allowed {
		a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
		switch {
		case a == "" || strings.Contains(a, "?"):
			continue
		case a == "**":
			return true
		case p == "**":
			continue
		case a == "@" || p == "@":
			if a == p {
				return true
			}
			continue
		}
		if labelsCovered(strings.Split(a, "."), strings.Split(p, ".")) {
			return true
		}
	}
	return false
}

func labelsCovered(a, p []string) bool {
	if len(a) == 0 {
		return len(p) == 0
	}
	if a[0] == "**" {
		for i := 1; i <= len(p); i++ {
			if labelsCovered(a[1:], p[i:]) {
				return true
			}
		}
		return false
	}
	if len(p) == 0 || p[0] == "**" || !glob.Match(a[0], p[0]) {
		return false
	}
	return labelsCovered(a[1:], p[1:])
}

// matcherCovered reports whether a binding matcher only matches subjects
// that one of the allowed matchers matches: same issuer, and every claim of
// the allowed matcher constrained by the binding matcher with patterns it
// covers.
func matcherCovered(allowed []config.Subject, m uiapi.SubjectMatcher) bool {
	for _, a := range allowed {
		if a.Issuer != m.Issuer || len(a.Claims) == 0 {
			continue
		}
		ok := true
		for name, apats := range a.Claims {
			pats := m.Claims[name]
			if len(pats) == 0 {
				ok = false
				break
			}
			for _, p := range pats {
				if !glob.Covered(apats, p) {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func subjectMatcher(m config.Subject) uiapi.SubjectMatcher {
	out := uiapi.SubjectMatcher{Issuer: m.Issuer, Claims: map[string][]string{}}
	for k, v := range m.Claims {
		out.Claims[k] = []string(v)
	}
	return out
}

// teamFromEqual compares two team derivations.
func teamFromEqual(a, b *uiapi.TeamFrom) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Claim == b.Claim && a.Regex == b.Regex && a.Prefix == b.Prefix
}

// DeriveTeamFromValue applies a team derivation to a literal claim value.
func DeriveTeamFromValue(t *config.TeamFrom, value string) (string, bool) {
	re, err := regexp.Compile(t.Regex)
	if err != nil {
		return "", false
	}
	cb := compiledBinding{teamRe: re, binding: uiapi.Binding{TeamFrom: &uiapi.TeamFrom{Claim: t.Claim, Regex: t.Regex, Prefix: t.Prefix}}}
	return deriveTeam(cb, map[string]any{t.Claim: value})
}

func uiTeamFrom(t *config.TeamFrom) *uiapi.TeamFrom {
	if t == nil {
		return nil
	}
	return &uiapi.TeamFrom{Claim: t.Claim, Regex: t.Regex, Prefix: t.Prefix}
}

// DelegationViews renders policy.delegations for the API.
func DelegationViews(c *config.Config) []uiapi.Delegation {
	out := []uiapi.Delegation{}
	for _, d := range c.Policy.Delegations {
		v := uiapi.Delegation{Name: d.Name, Description: d.Description, Subjects: matchers(d.Subjects), Allow: uiapi.DelegationAllow{
			Zones: append([]string{}, d.Allow.Zones...), Actions: append([]string{}, d.Allow.Actions...),
			BindingSubjects: matchers(d.Allow.BindingSubjects),
			Teams:           uiapi.DelegationTeams{FromSubject: uiTeamFrom(d.Allow.Teams.FromSubject), Names: d.Allow.Teams.Names},
			Roles:           d.Allow.Roles, Groups: d.Allow.Groups, MaxObjects: d.Allow.MaxObjects,
		}}
		if d.Allow.Records != nil {
			v.Allow.Records = &uiapi.RecordScope{Hosts: d.Allow.Records.Hosts, Types: d.Allow.Records.Types}
		}
		out = append(out, v)
	}
	return out
}

// ObjectETag is the strong ETag of a delegated object: a hash of its JSON
// (content and owner).
func ObjectETag(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// validateDelegated checks the delegated section of a managed document: the
// same rules as the other managed objects, plus the limits of the owning
// delegation. roleOK, groupOK and matcher are the checks of ValidateManaged.
func validateDelegated(v *verrs, c *config.Config, base uiapi.PolicyDocument, d uiapi.PolicyDocument, roleOK func(path, name string), groupOK func(path, g string), matcher func(path string, m uiapi.SubjectMatcher)) {
	ds := d.Delegated
	if ds == nil {
		return
	}
	delegations := map[string]*config.Delegation{}
	for i := range c.Policy.Delegations {
		delegations[c.Policy.Delegations[i].Name] = &c.Policy.Delegations[i]
	}
	count := map[string]int{}
	owner := func(at string, o uiapi.DelegatedOwner) *config.Delegation {
		dl := delegations[o.Delegation]
		if dl == nil {
			v.add(at+".owner.delegation", "unknown delegation %q (removed from policy.delegations? take the object over or delete it)", o.Delegation)
			return nil
		}
		if o.CreatedBy == "" || o.UpdatedBy == "" {
			v.add(at+".owner", "created_by and updated_by are required")
		}
		if o.ManagedBy != "" && !managedByRe.MatchString(o.ManagedBy) {
			v.add(at+".owner.managed_by", "must be 1 to 64 characters [A-Za-z0-9._/-]")
		}
		count[o.Delegation]++
		return dl
	}

	for _, name := range sortedKeys(ds.Roles) {
		r := ds.Roles[name]
		at := "delegated.roles." + name
		if !nameRe.MatchString(name) {
			v.add(at, "role name must be a lowercase identifier")
		}
		if _, ok := base.Roles[name]; ok {
			v.add(at, "role %q is defined by the base policy", name)
		}
		if _, ok := d.Roles[name]; ok {
			v.add(at, "role %q is also a managed role", name)
		}
		validateRole(v, c, at, r.Role)
		dl := owner(at, r.Owner)
		if dl == nil {
			continue
		}
		for i, rule := range r.Rules {
			validateRuleInDelegation(v, dl, fmt.Sprintf("%s.rules[%d]", at, i), rule)
		}
	}

	for _, name := range sortedKeys(ds.Bindings) {
		b := ds.Bindings[name]
		at := "delegated.bindings." + name
		if !nameRe.MatchString(name) {
			v.add(at, "binding name must be a lowercase identifier")
		}
		validateBinding(v, at, b.Binding, groupOK, matcher)
		dl := owner(at, b.Owner)
		if dl == nil {
			continue
		}
		validateDelegatedBindingRole(v, c, base, d, dl, at+".role", b.Role, roleOK)
		for j, g := range b.Groups {
			if !contains(dl.Allow.Groups, g) {
				v.add(fmt.Sprintf("%s.groups[%d]", at, j), "group %q is not in the allow.groups of delegation %q", g, dl.Name)
			}
		}
		for j, m := range b.Subjects {
			if !matcherCovered(dl.Allow.BindingSubjects, m) {
				v.add(fmt.Sprintf("%s.subjects[%d]", at, j), "subject %s is not covered by the allow.binding_subjects of delegation %q", MatcherString(m), dl.Name)
			}
		}
		validateDelegatedTeam(v, dl, at, b.Binding)
	}

	for _, name := range sortedKeys(count) {
		if dl := delegations[name]; dl != nil && count[name] > dl.Allow.MaxObjects {
			v.add("delegated", "delegation %q holds %d objects, more than its allow.max_objects (%d)", name, count[name], dl.Allow.MaxObjects)
		}
	}
}

func validateRuleInDelegation(v *verrs, dl *config.Delegation, rat string, rule uiapi.Rule) {
	for j, z := range rule.Zones {
		if !ZoneCovered(dl.Allow.Zones, strings.ToLower(z)) {
			v.add(fmt.Sprintf("%s.zones[%d]", rat, j), "zone %q is outside the allow.zones of delegation %q", z, dl.Name)
		}
	}
	for j, a := range rule.Actions {
		if !contains(dl.Allow.Actions, a) {
			v.add(fmt.Sprintf("%s.actions[%d]", rat, j), "action %q is outside the allow.actions of delegation %q", a, dl.Name)
		}
	}
	lim := dl.Allow.Records
	if lim == nil {
		return
	}
	sc := rule.Records
	if sc == nil {
		sc = &uiapi.RecordScope{}
	}
	if len(lim.Hosts) > 0 {
		if len(sc.Hosts) == 0 {
			v.add(rat+".records.hosts", "delegation %q limits hosts to %s: the rule must name its hosts", dl.Name, strings.Join(lim.Hosts, ", "))
		}
		for j, h := range sc.Hosts {
			if !HostCovered(lim.Hosts, h) {
				v.add(fmt.Sprintf("%s.records.hosts[%d]", rat, j), "host %q is outside the allow.records.hosts of delegation %q (%s)", h, dl.Name, strings.Join(lim.Hosts, ", "))
			}
		}
	}
	if len(lim.Types) > 0 {
		if len(sc.Types) == 0 {
			v.add(rat+".records.types", "delegation %q limits types to %s: the rule must name its types", dl.Name, strings.Join(lim.Types, ", "))
		}
		for j, t := range sc.Types {
			if !typeCovered(lim.Types, t) {
				v.add(fmt.Sprintf("%s.records.types[%d]", rat, j), "type %q is outside the allow.records.types of delegation %q (%s)", t, dl.Name, strings.Join(lim.Types, ", "))
			}
		}
	}
}

// validateDelegatedBindingRole: a delegated binding grants a role of its own
// delegation, or a base or managed role listed in allow.roles whose every
// rule is within the delegation.
func validateDelegatedBindingRole(v *verrs, c *config.Config, base, d uiapi.PolicyDocument, dl *config.Delegation, path, name string, roleOK func(path, name string)) {
	if dr, ok := d.Delegated.Role(name); ok {
		if dr.Owner.Delegation != dl.Name {
			v.add(path, "role %q belongs to delegation %q", name, dr.Owner.Delegation)
		}
		return
	}
	if !contains(dl.Allow.Roles, name) {
		v.add(path, "role %q is neither a role of delegation %q nor in its allow.roles", name, dl.Name)
		return
	}
	roleOK(path, name)
	r, ok := d.Roles[name]
	if !ok {
		r, ok = base.Roles[name]
	}
	if !ok {
		return
	}
	for _, rule := range r.Rules {
		for _, a := range rule.Actions {
			if !ruleWithinDelegation(dl, rule, a) {
				v.add(path, "role %q grants %s beyond the limits of delegation %q", name, a, dl.Name)
				return
			}
		}
	}
}

// validateDelegatedTeam checks the team of a delegated binding against
// allow.teams.
func validateDelegatedTeam(v *verrs, dl *config.Delegation, at string, b uiapi.Binding) {
	fs := dl.Allow.Teams.FromSubject
	switch {
	case b.TeamFrom != nil:
		if fs == nil || !teamFromEqual(b.TeamFrom, uiTeamFrom(fs)) {
			v.add(at+".team_from", "delegation %q only allows team_from %s", dl.Name, teamFromText(fs))
		}
	case b.Team == "":
		v.add(at+".team", "a delegated binding needs a team or team_from")
	case glob.Any(dl.Allow.Teams.Names, b.Team):
	case fs != nil:
		if len(b.Groups) > 0 {
			v.add(at+".team", "team %q is not in allow.teams.names, and a team derived from the subject cannot apply to groups", b.Team)
			return
		}
		for j, m := range b.Subjects {
			vals := m.Claims[fs.Claim]
			if len(vals) != 1 || strings.ContainsAny(vals[0], "*?") {
				v.add(fmt.Sprintf("%s.subjects[%d].claims.%s", at, j, fs.Claim), "a team derived from the subject needs exactly one literal %s value (or use team_from)", fs.Claim)
				continue
			}
			if t, ok := DeriveTeamFromValue(fs, vals[0]); !ok || t != b.Team {
				v.add(at+".team", "team %q is not the team derived from %s %q (%s)", b.Team, fs.Claim, vals[0], derivedOrNone(t, ok))
			}
		}
	default:
		v.add(at+".team", "team %q is not in the allow.teams.names of delegation %q", b.Team, dl.Name)
	}
}

func derivedOrNone(t string, ok bool) string {
	if !ok {
		return "no valid team derived"
	}
	return "derived: " + t
}

func teamFromText(t *config.TeamFrom) string {
	if t == nil {
		return "(none)"
	}
	return TeamFromString(uiTeamFrom(t))
}
