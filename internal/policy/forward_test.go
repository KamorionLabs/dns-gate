package policy

import (
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
)

func TestForwardWriteScope(t *testing.T) {
	e := FromConfig(&config.Config{
		Zones: []string{"example.com"},
		Roles: map[string]config.Role{
			"redirects": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionForwardWrite, ActionRecordAdopt},
				Records: &config.RecordScope{Hosts: []string{"go", "*.go"}, Types: []string{"CNAME"}}}}},
			"web": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionRecordWrite}}}},
		},
		Protected: []config.Protected{{Zones: []string{"*"}, Hosts: []string{"@"}}},
	})
	r, w := subj("redirects"), subj("web")
	if !e.AllowRRset(r, ActionForwardWrite, "example.com", dns.ForwardKey("go")) || !e.AllowRRset(r, ActionForwardWrite, "example.com", dns.ForwardKey("a.go")) {
		t.Fatal("dns.forward.write is scoped by hosts only")
	}
	if e.AllowRRset(r, ActionForwardWrite, "example.com", dns.ForwardKey("www")) || e.AllowRRset(r, ActionForwardWrite, "example.com", dns.ForwardKey("@")) {
		t.Fatal("host scope or protected list ignored")
	}
	if e.AllowRRset(r, ActionRecordAdopt, "example.com", dns.ForwardKey("go")) {
		t.Fatal("records.types still scopes dns.record.adopt on forwards")
	}
	if e.AllowRRset(w, ActionForwardWrite, "example.com", dns.ForwardKey("go")) || e.AllowRRset(r, ActionRecordWrite, "example.com", dns.Key{Host: "go", Type: "CNAME"}) {
		t.Fatal("record and forward writes are separate actions")
	}
	if team, ok := e.OwnerTeam(r, "example.com"); !ok || team != "web" {
		t.Fatal("a forward writer owns what it creates")
	}
	if WriteAction(dns.ForwardKey("go")) != ActionForwardWrite || WriteAction(dns.Key{Host: "go", Type: "A"}) != ActionRecordWrite {
		t.Fatal("WriteAction")
	}
}

func TestProtectedEntryCoversForwards(t *testing.T) {
	e := FromConfig(&config.Config{
		Zones: []string{"example.com"},
		Roles: map[string]config.Role{"redirects": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionForwardWrite}}}}},
		Protected: []config.Protected{{Zones: []string{"*"}, Hosts: []string{"www"}, Types: []string{"CNAME"}},
			{Zones: []string{"*"}, Hosts: []string{"mail"}, Types: []string{"MX"}}},
	})
	r := subj("redirects")
	if e.AllowRRset(r, ActionForwardWrite, "example.com", dns.ForwardKey("www")) || !e.IsProtected("example.com", dns.ForwardKey("www")) {
		t.Fatal("a protected CNAME must protect the forward of its host")
	}
	if !e.AllowRRset(r, ActionForwardWrite, "example.com", dns.ForwardKey("mail")) {
		t.Fatal("a protected MX does not concern forwards")
	}
	if _, ok := e.Holder().Current().ProtectedRecord("www", dns.TypeURLForward); !ok {
		t.Fatal("zone profile check must see the forward as protected")
	}
}

func TestForwardWritersCountInImpact(t *testing.T) {
	e := FromConfig(&config.Config{
		Zones: []string{"example.com"},
		Roles: map[string]config.Role{
			"redirects": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionForwardWrite}, Records: &config.RecordScope{Types: []string{"CNAME"}}}}},
		},
		Bindings: []config.Binding{{Role: "redirects", Team: "marketing", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"x"}}}}}},
	})
	sn := e.Holder().Current()
	if !sn.teamWrites()["marketing"]["example.com"] {
		t.Fatal("a team writing only forwards writes in the zone")
	}
	if got := sn.ForwardWithoutHosts(""); len(got) != 1 || got[0] != "redirects.rules[0]" {
		t.Fatalf("forward grant without hosts not flagged: %v", got)
	}
}

func TestImpactWarnsOnLostForwardWrite(t *testing.T) {
	snap := func(actions ...string) *Snapshot {
		return FromConfig(&config.Config{
			Zones:    []string{"example.com"},
			Roles:    map[string]config.Role{"web": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: actions}}}},
			Bindings: []config.Binding{{Role: "web", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"x"}}}}}},
		}).Holder().Current()
	}
	owned := func(team, zone, typ string) int {
		if team == "web" && typ == dns.TypeURLForward {
			return 2
		}
		if team == "web" && typ == "" {
			return 5
		}
		return 0
	}
	var found bool
	for _, it := range Impact(snap(ActionRecordWrite, ActionForwardWrite), snap(ActionRecordWrite), owned) {
		found = found || (it.Kind == "warning" && strings.Contains(it.Message, "loses dns.forward.write on example.com where it owns 2 URL forward(s)"))
	}
	if !found {
		t.Fatal("no warning for a team losing dns.forward.write over its forwards")
	}
}

func TestForwardGrantWithoutHostsWarnsInEveryLayer(t *testing.T) {
	old := FromConfig(&config.Config{Zones: []string{"example.com"}}).Holder().Current()
	wide := FromConfig(&config.Config{Zones: []string{"example.com"}, Roles: map[string]config.Role{
		"wide": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionForwardWrite}, Records: &config.RecordScope{Types: []string{"A"}}}}},
	}}).Holder().Current()
	var found bool
	for _, it := range Impact(old, wide, nil) {
		found = found || strings.Contains(it.Message, "grants dns.forward.write on every host")
	}
	if !found {
		t.Fatal("no warning for a base rule granting forwards on every host")
	}
}
