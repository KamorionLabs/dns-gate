package policy

import (
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
)

func testEngine() *Engine {
	return FromConfig(&config.Config{
		Zones:  []string{"example.com", "example.org"},
		Limits: config.Limits{MaxChangesPerRequest: 20},
		Roles: map[string]config.Role{
			"reader": {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionDNSRead, ActionUIRead}}}},
			"web": {Rules: []config.Rule{{
				Zones:   []string{"example.com"},
				Actions: []string{ActionDNSRead, ActionRecordWrite},
				Records: &config.RecordScope{Hosts: []string{"*.staging", "app"}, Types: []string{"CNAME", "TXT"}},
			}}},
			"acme": {
				Rules:                []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionRecordWrite}, Records: &config.RecordScope{Hosts: []string{"_acme-challenge", "_acme-challenge.**"}, Types: []string{"TXT"}}}},
				RebaseOnSave:         true,
				EphemeralTTL:         config.Duration(24 * time.Hour),
				MaxChangesPerRequest: 4,
			},
			"admin": {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionRecordWrite, ActionRecordAdopt}}}, MaxChangesPerRequest: -1},
		},
		Protected: []config.Protected{{Zones: []string{"*"}, Hosts: []string{"@"}, Types: []string{"NS", "MX", "SOA"}}},
	})
}

func subj(roles ...string) *identity.Subject {
	return &identity.Subject{Issuer: "ci", ID: "x", Roles: roles, Teams: []string{"web"}}
}

func TestDenyByDefault(t *testing.T) {
	e := testEngine()
	if e.Allow(nil, ActionDNSRead, "example.com") || e.Allow(subj(), ActionDNSRead, "example.com") {
		t.Fatal("no role must deny")
	}
	if e.Allow(subj("reader"), ActionDNSRead, "other.com") {
		t.Fatal("unmanaged zone must deny")
	}
	if e.Allow(subj("reader"), ActionRecordWrite, "example.com") {
		t.Fatal("reader cannot write")
	}
	if !e.Allow(subj("reader"), ActionDNSRead, "EXAMPLE.org.") {
		t.Fatal("reader can read any managed zone")
	}
}

func TestRecordScope(t *testing.T) {
	e := testEngine()
	s := subj("web")
	ok := []dns.Key{{Host: "www.staging", Type: "CNAME"}, {Host: "APP", Type: "txt"}}
	ko := []dns.Key{{Host: "a.b.staging", Type: "CNAME"}, {Host: "www.staging", Type: "A"}, {Host: "www", Type: "CNAME"}}
	for _, k := range ok {
		if !e.AllowRRset(s, ActionRecordWrite, "example.com", k) {
			t.Errorf("%v should be allowed", k)
		}
	}
	for _, k := range ko {
		if e.AllowRRset(s, ActionRecordWrite, "example.com", k) {
			t.Errorf("%v should be denied", k)
		}
	}
	if e.AllowRRset(s, ActionRecordWrite, "example.org", dns.Key{Host: "app", Type: "CNAME"}) {
		t.Error("web role is limited to example.com")
	}
}

func TestProtectedWins(t *testing.T) {
	e := testEngine()
	mx := dns.Key{Host: "@", Type: "MX"}
	if e.AllowRRset(subj("admin"), ActionRecordWrite, "example.com", mx) || e.AllowRRset(subj("admin"), ActionRecordAdopt, "example.com", dns.Key{Host: "", Type: "ns"}) {
		t.Fatal("protected records are never writable")
	}
	if !e.AllowRRset(subj("reader"), ActionDNSRead, "example.com", mx) {
		t.Fatal("protected records stay readable")
	}
	if !e.IsProtected("example.org", dns.Key{Host: "@", Type: "SOA"}) || e.IsProtected("example.org", dns.Key{Host: "www", Type: "MX"}) {
		t.Fatal("IsProtected mismatch")
	}
}

func TestACMERole(t *testing.T) {
	e := testEngine()
	s := subj("acme")
	if !e.AllowRRset(s, ActionRecordWrite, "example.org", dns.Key{Host: "_acme-challenge.www", Type: "TXT"}) ||
		!e.AllowRRset(s, ActionRecordWrite, "example.org", dns.Key{Host: "_acme-challenge", Type: "TXT"}) {
		t.Fatal("acme challenge allowed")
	}
	if e.AllowRRset(s, ActionRecordWrite, "example.org", dns.Key{Host: "www", Type: "TXT"}) {
		t.Fatal("acme limited to challenges")
	}
	if !e.RebaseOnSave(s) || e.RebaseOnSave(subj("web")) {
		t.Fatal("rebase mismatch")
	}
	if e.EphemeralTTL(s) != 24*time.Hour || e.EphemeralTTL(subj("acme", "web")) != 0 || e.EphemeralTTL(subj("reader")) != 0 {
		t.Fatal("ephemeral mismatch")
	}
	if e.MaxChangesPerRequest(s) != 4 || e.MaxChangesPerRequest(subj("web")) != 20 || e.MaxChangesPerRequest(subj("acme", "admin")) != 0 {
		t.Fatal("max changes mismatch")
	}
}

func TestOwnerTeam(t *testing.T) {
	e := testEngine()
	if team, ok := e.OwnerTeam(subj("web"), "example.com"); !ok || team != "web" {
		t.Fatal("owner team")
	}
	if _, ok := e.OwnerTeam(subj("reader"), "example.com"); ok {
		t.Fatal("reader has no owner team")
	}
	if _, ok := e.OwnerTeam(&identity.Subject{Roles: []string{"web"}}, "example.com"); ok {
		t.Fatal("no team, no ownership")
	}
}
