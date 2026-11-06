package policy

import (
	"fmt"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// OwnedCounter returns the number of RRsets a team owns in a zone; an empty
// team counts the RRsets of every team, an empty type every type, the type
// dns.TypeURLForward only the URL forwards.
type OwnedCounter func(team, zone, typ string) int

type grantKey struct {
	who, role, zone, action string
}

// grants lists what every binding and virtual key grants, per managed zone.
func (s *Snapshot) grants() map[grantKey]bool {
	out := map[grantKey]bool{}
	addRole := func(who, roleName string) {
		cr := s.roles[roleName]
		if cr == nil {
			return
		}
		for _, r := range cr.role.Rules {
			for _, a := range r.Actions {
				if IsMeta(a) {
					out[grantKey{who, roleName, "*", a}] = true
					continue
				}
				if !s.ruleEffective(cr, r, a) {
					continue
				}
				for z := range s.zones {
					if ok, _ := s.ruleApplies(cr, r, z, s.folderOnce(z)); ok {
						out[grantKey{who, roleName, z, a}] = true
					}
				}
			}
		}
	}
	for _, b := range s.bindings {
		addRole(bindingWho(b.binding), b.binding.Role)
	}
	for _, k := range s.keys {
		for _, r := range k.key.Roles {
			addRole("virtual key "+k.key.ID, r)
		}
	}
	return out
}

func bindingWho(b uiapi.Binding) string {
	var parts []string
	for _, g := range b.Groups {
		parts = append(parts, "group "+g)
	}
	for _, m := range b.Subjects {
		parts = append(parts, MatcherString(m))
	}
	who := strings.Join(parts, ", ")
	switch {
	case b.TeamFrom != nil:
		who = "team from " + TeamFromString(b.TeamFrom) + " (" + who + ")"
	case b.Team != "" && who == "":
		who = "team " + b.Team + " (members)"
	case b.Team != "":
		who = "team " + b.Team + " (" + who + ")"
	}
	return who
}

// MatcherString renders a matcher as "issuer{claim=a|b,...}".
func MatcherString(m uiapi.SubjectMatcher) string {
	names := sortedKeys(m.Claims)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, n+"="+strings.Join(m.Claims[n], "|"))
	}
	return m.Issuer + "{" + strings.Join(parts, ",") + "}"
}

// teamWrites returns team -> zones where the team can write records or URL
// forwards.
func (s *Snapshot) teamWrites() map[string]map[string]bool {
	return s.teamWritesOf(ActionRecordWrite, ActionForwardWrite)
}

// teamWritesOf returns team -> zones where the team holds one of actions.
func (s *Snapshot) teamWritesOf(actions ...string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(team, role string) {
		cr := s.roles[role]
		if team == "" || cr == nil {
			return
		}
		for _, r := range cr.role.Rules {
			if !slices.ContainsFunc(actions, func(a string) bool { return contains(r.Actions, a) && s.ruleEffective(cr, r, a) }) {
				continue
			}
			for z := range s.zones {
				if ok, _ := s.ruleApplies(cr, r, z, s.folderOnce(z)); ok {
					if out[team] == nil {
						out[team] = map[string]bool{}
					}
					out[team][z] = true
				}
			}
		}
	}
	for _, b := range s.bindings {
		// Teams derived from claims are only known per subject.
		add(b.binding.Team, b.binding.Role)
	}
	for _, k := range s.keys {
		for _, t := range k.key.Teams {
			for _, r := range k.key.Roles {
				add(t, r)
			}
		}
	}
	return out
}

// Impact compares two snapshots: permissions gained and lost per binding,
// group or virtual key, and warnings when a team that owns RRsets loses
// write access to their zone.
func Impact(old, new *Snapshot, owned OwnedCounter) []uiapi.ImpactItem {
	og, ng := old.grants(), new.grants()
	type agg struct {
		kind, who, role string
		zones, actions  map[string]bool
	}
	groups := map[string]*agg{}
	collect := func(set, other map[grantKey]bool, kind string) {
		for k := range set {
			if other[k] {
				continue
			}
			id := kind + "\x00" + k.who + "\x00" + k.role
			a := groups[id]
			if a == nil {
				a = &agg{kind: kind, who: k.who, role: k.role, zones: map[string]bool{}, actions: map[string]bool{}}
				groups[id] = a
			}
			a.zones[k.zone] = true
			a.actions[k.action] = true
		}
	}
	collect(ng, og, "gain")
	collect(og, ng, "loss")

	var items []uiapi.ImpactItem
	for _, a := range groups {
		zones, actions := keys(a.zones), keys(a.actions)
		verb := "gains"
		if a.kind == "loss" {
			verb = "loses"
		}
		items = append(items, uiapi.ImpactItem{
			Kind: a.kind, Who: a.who, Role: a.role, Zones: zones, Actions: actions,
			Message: fmt.Sprintf("%s %s %s on %s (role %s)", a.who, verb, strings.Join(actions, ", "), strings.Join(zones, ", "), a.role),
		})
	}

	// Group membership changes.
	for _, name := range unionKeys(old.groups, new.groups) {
		og, ng := old.groups[name], new.groups[name]
		switch {
		case og == nil:
			items = append(items, uiapi.ImpactItem{Kind: "gain", Who: "group " + name, Message: fmt.Sprintf("group %s is created with %d member matcher(s)", name, len(ng.members))})
		case ng == nil:
			items = append(items, uiapi.ImpactItem{Kind: "loss", Who: "group " + name, Message: fmt.Sprintf("group %s is removed", name)})
		case membersText(og.members) != membersText(ng.members):
			items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "group " + name, Message: fmt.Sprintf("members of group %s change: %s -> %s", name, membersText(og.members), membersText(ng.members))})
		}
	}

	// Team declarations and their members.
	for _, name := range unionKeys(old.teams, new.teams) {
		ot, nt := old.teams[name], new.teams[name]
		switch {
		case ot == nil:
			items = append(items, uiapi.ImpactItem{Kind: "gain", Who: "team " + name, Message: fmt.Sprintf("team %s is declared with %s", name, teamMembersText(nt.team.Members))})
		case nt == nil:
			items = append(items, uiapi.ImpactItem{Kind: "loss", Who: "team " + name, Message: fmt.Sprintf("team %s is no longer declared: bindings naming it without groups or subjects bind nobody", name)})
		case teamMembersText(ot.team.Members) != teamMembersText(nt.team.Members):
			items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "team " + name, Message: fmt.Sprintf("members of team %s change: %s -> %s", name, teamMembersText(ot.team.Members), teamMembersText(nt.team.Members))})
		}
	}
	oldUndeclared := map[string]bool{}
	for _, t := range old.UndeclaredTeams() {
		oldUndeclared[t] = true
	}
	for _, t := range new.UndeclaredTeams() {
		if !oldUndeclared[t] {
			items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "team " + t,
				Message: fmt.Sprintf("team %s is not declared under teams: it is declared automatically during the migration to the teams block", t)})
		}
	}

	// Zones brought under management or released.
	for _, zone := range unionKeys(old.zones, new.zones) {
		switch {
		case !old.zones[zone]:
			items = append(items, uiapi.ImpactItem{Kind: "gain", Who: "zone " + zone, Zones: []string{zone},
				Message: fmt.Sprintf("zone %s becomes managed: writes and adoption are possible there within the roles", zone)})
		case !new.zones[zone]:
			items = append(items, uiapi.ImpactItem{Kind: "loss", Who: "zone " + zone, Zones: []string{zone},
				Message: fmt.Sprintf("zone %s is no longer managed: it becomes read-only through the gate", zone)})
			n := 0
			if owned != nil {
				n = owned("", zone, "")
			}
			if n > 0 {
				items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "zone " + zone, Zones: []string{zone}, Actions: []string{ActionRecordWrite},
					Message: fmt.Sprintf("zone %s stops being managed while the gate owns %d RRset(s) there: no team can change them until the zone is managed again", zone, n)})
			}
		}
	}

	items = append(items, folderItems(old, new)...)

	// Teams losing write where they own RRsets, or dns.forward.write where
	// they own URL forwards.
	ow, nw := old.teamWrites(), new.teamWrites()
	for _, team := range keysOf(ow) {
		for _, zone := range keys(ow[team]) {
			if nw[team][zone] {
				continue
			}
			n := 0
			if owned != nil {
				n = owned(team, zone, "")
			}
			if n == 0 {
				continue
			}
			items = append(items, uiapi.ImpactItem{
				Kind: "warning", Who: "team " + team, Zones: []string{zone}, Actions: []string{ActionRecordWrite},
				Message: fmt.Sprintf("team %s loses write on %s where it owns %d RRset(s): they become unmanageable through the gate", team, zone, n),
			})
		}
	}
	of, nf := old.teamWritesOf(ActionForwardWrite), new.teamWritesOf(ActionForwardWrite)
	for _, team := range keysOf(of) {
		for _, zone := range keys(of[team]) {
			if nf[team][zone] || !nw[team][zone] {
				continue
			}
			n := 0
			if owned != nil {
				n = owned(team, zone, dns.TypeURLForward)
			}
			if n == 0 {
				continue
			}
			items = append(items, uiapi.ImpactItem{
				Kind: "warning", Who: "team " + team, Zones: []string{zone}, Actions: []string{ActionForwardWrite},
				Message: fmt.Sprintf("team %s loses %s on %s where it owns %d URL forward(s): they become unmanageable through the gate", team, ActionForwardWrite, zone, n),
			})
		}
	}

	oldIneffective := map[string]bool{}
	for _, w := range old.IneffectiveProfileGrants(LayerManaged) {
		oldIneffective[w] = true
	}
	for _, w := range new.IneffectiveProfileGrants(LayerManaged) {
		if !oldIneffective[w] {
			role, _, _ := strings.Cut(w, ".rules[")
			items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "role " + role, Role: role, Actions: []string{ActionZoneProfile},
				Message: fmt.Sprintf("%s grants %s without effect: zone profiles are account-wide, the action only counts on zones [\"*\"] without records", w, ActionZoneProfile)})
		}
	}

	oldUnscoped := map[string]bool{}
	for _, w := range old.ForwardWithoutHosts("") {
		oldUnscoped[w] = true
	}
	for _, w := range new.ForwardWithoutHosts("") {
		if !oldUnscoped[w] {
			role, _, _ := strings.Cut(w, ".rules[")
			items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "role " + role, Role: role, Actions: []string{ActionForwardWrite},
				Message: fmt.Sprintf("%s grants %s on every host: records.types does not apply to URL forwards, scope them with records.hosts", w, ActionForwardWrite)})
		}
	}

	order := map[string]int{"warning": 0, "loss": 1, "gain": 2}
	sort.Slice(items, func(i, j int) bool {
		if order[items[i].Kind] != order[items[j].Kind] {
			return order[items[i].Kind] < order[items[j].Kind]
		}
		return items[i].Message < items[j].Message
	})
	if items == nil {
		items = []uiapi.ImpactItem{}
	}
	return items
}

// folderItems warns about the folder rules new has and old has not: the
// zones they reach follow the EuroDNS folder layout, not the policy; and
// about every folder rule while zone discovery has not listed the accounts
// (they match no zone until it has).
func folderItems(old, new *Snapshot) []uiapi.ImpactItem {
	var items []uiapi.ImpactItem
	found := false
	for _, name := range sortedKeys(new.roles) {
		cr := new.roles[name]
		for i, r := range cr.role.Rules {
			if len(r.Folders) == 0 {
				continue
			}
			found = true
			if or := old.roles[name]; or != nil && i < len(or.role.Rules) && reflect.DeepEqual(or.role.Rules[i], r) {
				continue
			}
			var zones []string
			for _, z := range keys(new.zones) {
				if ok, via := new.ruleApplies(cr, r, z, new.folderOnce(z)); ok && via != "" {
					zones = append(zones, z)
				}
			}
			items = append(items, uiapi.ImpactItem{
				Kind: "warning", Who: "role " + name, Role: name, Zones: zones, Actions: r.Actions,
				Message: fmt.Sprintf("role %s rules[%d] is a dynamic folder rule (%s, %d zone%s currently): its zones follow the EuroDNS folders, moving a domain changes them without a policy revision",
					name, i, strings.Join(r.Folders, ", "), len(zones), map[bool]string{true: "s"}[len(zones) != 1]),
			})
		}
	}
	if found && !new.discoveryLoaded() {
		items = append(items, uiapi.ImpactItem{Kind: "warning", Who: "zone discovery",
			Message: "the provider accounts are not listed yet (zone discovery not loaded): folder rules match no zone until they are"})
	}
	return items
}

func teamMembersText(m uiapi.TeamMembers) string {
	parts := []string{}
	for _, g := range m.Groups {
		parts = append(parts, "group "+g)
	}
	if t := membersText(m.Subjects); t != "" {
		parts = append(parts, t)
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "no members"
	}
	return strings.Join(parts, "; ")
}

func membersText(ms []uiapi.SubjectMatcher) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, MatcherString(m))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysOf[T any](m map[string]T) []string { return sortedKeys(m) }

func unionKeys[T any](a, b map[string]T) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	return keys(set)
}

// WhoCan lists the bindings and virtual keys allowed to perform an action
// on an RRset (or a zone when key is nil).
func (s *Snapshot) WhoCan(action, zone, host, typ string) uiapi.WhoCanResponse {
	zone = normZone(zone)
	resp := uiapi.WhoCanResponse{Folder: s.Folder(zone), Entries: []uiapi.WhoCanEntry{}}
	var key *struct{ host, typ string }
	if host != "" || typ != "" {
		key = &struct{ host, typ string }{host, typ}
	}
	decide := func(role string) Decision {
		if key == nil {
			return s.Decide([]string{role}, action, zone, nil)
		}
		k := normKey(rrsetKey(key.host, key.typ))
		return s.Decide([]string{role}, action, zone, &k)
	}
	if key != nil && !IsMeta(action) {
		_, resp.Protected = s.protectedBy(zone, normKey(rrsetKey(key.host, key.typ)))
	}
	for _, b := range s.bindings {
		d := decide(b.binding.Role)
		if !d.Allowed {
			continue
		}
		e := uiapi.WhoCanEntry{
			Role: b.binding.Role, Team: b.binding.Team, TeamFrom: b.binding.TeamFrom, Layer: b.layer,
			Groups: b.binding.Groups, Subjects: b.binding.Subjects, ByFolder: d.Folder != "",
		}
		if len(b.binding.Groups) == 0 && len(b.binding.Subjects) == 0 {
			if m, ok := s.TeamMembers(b.binding.Team); ok {
				e.TeamMembers = &m
			}
		}
		resp.Entries = append(resp.Entries, e)
	}
	for _, k := range s.keys {
		for _, r := range k.key.Roles {
			if d := decide(r); d.Allowed {
				team := ""
				if len(k.key.Teams) > 0 {
					team = k.key.Teams[0]
				}
				resp.Entries = append(resp.Entries, uiapi.WhoCanEntry{Role: r, Team: team, Layer: k.layer, Keys: []string{k.key.ID}, ByFolder: d.Folder != ""})
				break
			}
		}
	}
	return resp
}
