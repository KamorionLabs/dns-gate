package policy

import (
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
