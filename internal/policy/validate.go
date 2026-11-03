package policy

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
)

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	appIDRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)
)

var knownActions = map[string]bool{
	ActionDNSRead: true, ActionRecordWrite: true, ActionRecordAdopt: true,
	ActionZoneAdmin: true, ActionDomainRead: true, ActionUIRead: true,
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

type verrs []uiapi.ValidationError

func (v *verrs) add(path, format string, a ...any) {
	*v = append(*v, uiapi.ValidationError{Path: path, Message: fmt.Sprintf(format, a...)})
}

// ValidateManaged checks a managed document against the base policy and
// the configured bounds. Errors carry paths such as
// "roles.web.rules[0].actions[1]".
func ValidateManaged(c *config.Config, base uiapi.PolicyDocument, d uiapi.PolicyDocument) []uiapi.ValidationError {
	var v verrs
	issuers := map[string]bool{}
	for _, is := range c.Issuers {
		issuers[is.Name] = true
	}
	if !c.Policy.Editable {
		v.add("", "the managed policy is disabled (policy.editable is false)")
		return v
	}

	matcher := func(path string, m uiapi.SubjectMatcher) {
		if !issuers[m.Issuer] {
			v.add(path+".issuer", "unknown issuer %q", m.Issuer)
		}
		if len(m.Claims) == 0 {
			v.add(path+".claims", "at least one claim is required")
		}
		for name, pats := range m.Claims {
			if name == "" || len(pats) == 0 {
				v.add(path+".claims."+name, "claim name and at least one pattern are required")
			}
			for i, p := range pats {
				if p == "" || p == "*" {
					v.add(fmt.Sprintf("%s.claims.%s[%d]", path, name, i), "pattern %q matches anyone", p)
				}
			}
		}
	}

	baseZones := map[string]bool{}
	for _, z := range c.Zones {
		baseZones[z] = true
	}
	seenZone := map[string]bool{}
	for i, z := range d.Zones {
		at := fmt.Sprintf("zones[%d]", i)
		switch {
		case z != normZone(strings.TrimSpace(z)):
			v.add(at, "zone %q must be lowercase, without a trailing dot", z)
		case !config.ValidFQDN(z):
			v.add(at, "%q is not a valid domain name", z)
		case seenZone[z]:
			v.add(at, "zone %q listed twice", z)
		case !baseZones[z] && !ZoneCovered(c.Policy.Bounds.Zones, z):
			v.add(at, "zone %q is outside policy.bounds.zones", z)
		}
		seenZone[z] = true
	}

	for _, name := range sortedKeys(d.Groups) {
		g := d.Groups[name]
		at := "groups." + name
		if !nameRe.MatchString(name) {
			v.add(at, "group name must be a lowercase identifier")
		}
		if _, ok := base.Groups[name]; ok {
			v.add(at, "group %q is defined by the base policy", name)
		}
		if len(g.Members) == 0 {
			v.add(at+".members", "at least one member matcher is required")
		}
		for i, m := range g.Members {
			matcher(fmt.Sprintf("%s.members[%d]", at, i), m)
		}
	}

	for _, name := range sortedKeys(d.Roles) {
		r := d.Roles[name]
		at := "roles." + name
		if !nameRe.MatchString(name) {
			v.add(at, "role name must be a lowercase identifier")
		}
		if _, ok := base.Roles[name]; ok {
			v.add(at, "role %q is defined by the base policy", name)
		}
		validateRole(&v, c, at, r)
	}

	// A managed binding or key may use a managed role, or a base role that
	// grants nothing beyond the bounds (and no policy.* action).
	roleOK := func(path, name string) {
		if _, ok := d.Roles[name]; ok {
			return
		}
		br, ok := base.Roles[name]
		if !ok {
			if dr, delegated := d.Delegated.Role(name); delegated {
				v.add(path, "role %q belongs to delegation %q: only its delegated bindings can use it", name, dr.Owner.Delegation)
				return
			}
			v.add(path, "unknown role %q", name)
			return
		}
		for _, rule := range br.Rules {
			for _, a := range rule.Actions {
				if IsMeta(a) || !contains(c.Policy.Bounds.Actions, a) {
					v.add(path, "base role %q grants %s, outside the managed bounds", name, a)
					return
				}
			}
			for _, z := range rule.Zones {
				if !ZoneCovered(c.Policy.Bounds.Zones, z) {
					v.add(path, "base role %q covers zone %q, outside the managed bounds", name, z)
					return
				}
			}
		}
	}

	groupOK := func(path, g string) {
		_, inBase := base.Groups[g]
		_, inDoc := d.Groups[g]
		if !inBase && !inDoc {
			v.add(path, "unknown group %q", g)
		}
	}
	for i, b := range d.Bindings {
		at := fmt.Sprintf("bindings[%d]", i)
		roleOK(at+".role", b.Role)
		validateBinding(&v, at, b, groupOK, matcher)
	}

	ids, apps := map[string]bool{}, map[string]bool{}
	for _, k := range base.VirtualKeys {
		ids[k.ID], apps[k.AppID] = true, true
	}
	for i, k := range d.VirtualKeys {
		at := fmt.Sprintf("virtual_keys[%d]", i)
		if !nameRe.MatchString(k.ID) {
			v.add(at+".id", "id must be a lowercase identifier")
		} else if ids[k.ID] {
			v.add(at+".id", "id %q already used", k.ID)
		}
		ids[k.ID] = true
		if !appIDRe.MatchString(k.AppID) {
			v.add(at+".app_id", "app_id must be 3 to 64 characters [A-Za-z0-9._-]")
		} else if apps[k.AppID] {
			v.add(at+".app_id", "app_id %q already used", k.AppID)
		}
		apps[k.AppID] = true
		if !sha256Re.MatchString(k.KeySHA256) {
			v.add(at+".key_sha256", "lowercase hex sha256 required")
		}
		if len(k.Roles) == 0 {
			v.add(at+".roles", "at least one role is required")
		}
		for j, r := range k.Roles {
			roleOK(fmt.Sprintf("%s.roles[%d]", at, j), r)
		}
		for j, t := range k.Teams {
			if !nameRe.MatchString(t) {
				v.add(fmt.Sprintf("%s.teams[%d]", at, j), "team must be a lowercase identifier")
			}
		}
		if k.ExpiresAt == nil {
			v.add(at+".expires_at", "managed virtual keys must expire")
		}
		for j, p := range k.AllowedCIDRs {
			if _, err := netip.ParsePrefix(p); err != nil {
				v.add(fmt.Sprintf("%s.allowed_cidrs[%d]", at, j), "invalid CIDR %q", p)
			}
		}
	}
	validateDelegated(&v, c, base, d, roleOK, groupOK, matcher)
	return v
}

// validateRole checks the rules and options of a managed role.
func validateRole(v *verrs, c *config.Config, at string, r uiapi.Role) {
	if len(r.Rules) == 0 {
		v.add(at+".rules", "at least one rule is required")
	}
	for i, rule := range r.Rules {
		rat := fmt.Sprintf("%s.rules[%d]", at, i)
		if len(rule.Zones) == 0 {
			v.add(rat+".zones", "at least one zone is required")
		}
		for j, z := range rule.Zones {
			if !ZoneCovered(c.Policy.Bounds.Zones, strings.ToLower(z)) {
				v.add(fmt.Sprintf("%s.zones[%d]", rat, j), "zone %q is outside policy.bounds.zones", z)
			}
		}
		if len(rule.Actions) == 0 {
			v.add(rat+".actions", "at least one action is required")
		}
		for j, a := range rule.Actions {
			p := fmt.Sprintf("%s.actions[%d]", rat, j)
			switch {
			case IsMeta(a):
				v.add(p, "%s can only be granted by the base policy", a)
			case !knownActions[a]:
				v.add(p, "unknown action %q", a)
			case !contains(c.Policy.Bounds.Actions, a):
				v.add(p, "action %q is outside policy.bounds.actions", a)
			}
		}
		if rule.Records != nil && len(rule.Records.Hosts) == 0 && len(rule.Records.Types) == 0 {
			v.add(rat+".records", "hosts or types required when records is set")
		}
	}
	if r.EphemeralTTL != "" {
		if d, err := time.ParseDuration(r.EphemeralTTL); err != nil || d < 0 {
			v.add(at+".ephemeral_ttl", "invalid duration %q", r.EphemeralTTL)
		}
	}
	if r.MaxChangesPerRequest < 0 || r.MaxChangesPerRequest > 1000 {
		v.add(at+".max_changes_per_request", "must be between 0 (default) and 1000; unlimited is reserved to the base policy")
	}
}

// validateBinding checks the team, groups and subjects of a managed binding
// (the role is checked by the caller).
func validateBinding(v *verrs, at string, b uiapi.Binding, groupOK func(path, g string), matcher func(path string, m uiapi.SubjectMatcher)) {
	if b.Team != "" && !nameRe.MatchString(b.Team) {
		v.add(at+".team", "team must be a lowercase identifier")
	}
	if b.TeamFrom != nil {
		if b.Team != "" {
			v.add(at+".team", "team and team_from are exclusive")
		}
		if err := config.ValidateTeamFrom(b.TeamFrom.Claim, b.TeamFrom.Regex, b.TeamFrom.Prefix); err != nil {
			v.add(at+".team_from", "%v", err)
		}
	}
	if len(b.Groups) == 0 && len(b.Subjects) == 0 {
		v.add(at, "groups or subjects required")
	}
	for j, g := range b.Groups {
		groupOK(fmt.Sprintf("%s.groups[%d]", at, j), g)
	}
	for j, m := range b.Subjects {
		matcher(fmt.Sprintf("%s.subjects[%d]", at, j), m)
	}
}

// ValidateZonesDiscovered checks that every zone a managed document adds
// (not already managed by cur, the active snapshot) exists in the EuroDNS
// account. Zones already managed are not checked again, so that a zone
// removed from the account does not block unrelated policy changes.
func ValidateZonesDiscovered(d uiapi.PolicyDocument, cur *Snapshot, disc Discovery, loaded bool) []uiapi.ValidationError {
	var v verrs
	for i, z := range d.Zones {
		z = normZone(z)
		if cur != nil && cur.IsManaged(z) {
			continue
		}
		at := fmt.Sprintf("zones[%d]", i)
		switch {
		case disc == nil:
			v.add(at, "zone %q is not managed yet: adding zones requires zones_discovery.enabled", z)
		case !loaded:
			v.add(at, "the zone list of the EuroDNS account is not loaded yet: retry later")
		case !disc.Discovered(z):
			v.add(at, "zone %q was not found in the EuroDNS account (or is filtered out by zones_discovery include/exclude)", z)
		}
	}
	return v
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
