package policy

import (
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func TestScopeActionsAreKnown(t *testing.T) {
	known := func(a string) bool {
		return knownActions[a] || a == uiapi.ActionPolicyRead || a == uiapi.ActionPolicyPropose || a == uiapi.ActionPolicyApprove
	}
	for _, sc := range scope.All {
		for _, a := range scope.Actions([]string{sc}) {
			if !known(a) {
				t.Errorf("scope %s grants unknown action %s", sc, a)
			}
		}
	}
	for _, a := range scope.NeverDelegable {
		if !known(a) {
			t.Errorf("never delegable action %s is unknown", a)
		}
	}
}

func TestEngineScopes(t *testing.T) {
	e := FromConfig(&config.Config{
		Zones: []string{"example.com", "example.org"},
		Roles: map[string]config.Role{"all": {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{
			ActionUIRead, ActionDNSRead, ActionRecordWrite, ActionRecordAdopt, ActionZoneAdmin, ActionOwnershipApprove, "policy.read", "policy.approve", ActionAPIKeyManage,
		}}}}},
	})
	user := &identity.Subject{Issuer: "idp", ID: "u", Roles: []string{"all"}, Teams: []string{"web"}}
	if !e.Allow(user, ActionZoneAdmin, "example.com") || !e.AllowMeta(user, "policy.approve") {
		t.Fatal("direct subject keeps its rights")
	}
	c := *user
	c.Client, c.Scopes = &identity.Client{ID: "copilot", Zones: []string{"example.com"}}, []string{scope.DNSRead, scope.DNSPlan, scope.PolicyRead}
	k := dns.Key{Host: "www", Type: "A"}
	checks := []struct {
		s      *identity.Subject
		action string
		zone   string
		want   bool
	}{
		{&c, ActionDNSRead, "example.com", true},
		{&c, ActionDNSRead, "example.org", false},
		{&c, ActionRecordWrite, "example.com", false},
		{c.WithIntent(identity.IntentPlan), ActionRecordWrite, "example.com", true},
		{c.WithIntent(identity.IntentPlan), ActionRecordWrite, "example.org", false},
		{c.WithIntent(identity.IntentTransfer), ActionRecordWrite, "example.com", false},
		{&c, ActionZoneAdmin, "example.com", false},
		{&c, ActionAPIKeyManage, "example.com", false},
		{&c, ActionOwnershipApprove, "example.com", false},
	}
	for _, ch := range checks {
		if got := e.Allow(ch.s, ch.action, ch.zone); got != ch.want {
			t.Errorf("Allow %s %s intent %q: %v", ch.action, ch.zone, ch.s.Intent, got)
		}
		if got := e.AllowRRset(ch.s, ch.action, ch.zone, k); got != ch.want {
			t.Errorf("AllowRRset %s %s intent %q: %v", ch.action, ch.zone, ch.s.Intent, got)
		}
		if got, _ := e.AllowRRsetFolder(ch.s, ch.action, ch.zone, k); got != ch.want {
			t.Errorf("AllowRRsetFolder %s %s: %v", ch.action, ch.zone, got)
		}
	}
	if !e.AllowMeta(&c, "policy.read") || e.AllowMeta(&c, "policy.approve") {
		t.Fatal("policy.* actions follow the scopes")
	}
	if _, ok := e.OwnerTeam(&c, "example.com"); ok {
		t.Fatal("no owner team without a write scope")
	}
	if team, ok := e.OwnerTeam(c.WithIntent(identity.IntentPlan), "example.com"); !ok || team != "web" {
		t.Fatal("owner team of a plan")
	}
	ps := e.Permissions(&c)
	if len(ps) != 1 || len(ps[0].Zones) != 1 || ps[0].Zones[0] != "example.com" {
		t.Fatalf("permissions: %+v", ps)
	}
	for _, a := range ps[0].Actions {
		if a != ActionUIRead && a != ActionDNSRead && a != "policy.read" {
			t.Fatalf("permission action %s beyond the scopes", a)
		}
	}
}
