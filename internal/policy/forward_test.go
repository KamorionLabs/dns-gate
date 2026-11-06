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
