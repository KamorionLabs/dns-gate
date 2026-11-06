package policy

import (
	"sort"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

type fakeDiscovery map[string]bool

func (f fakeDiscovery) Discovered(z string) bool { return f[z] }
func (f fakeDiscovery) DiscoveredZones() []string {
	var out []string
	for z := range f {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

func discoveryConfig() *config.Config {
	c := layeredConfig()
	c.Roles["reader-all"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionDNSRead, ActionUIRead}}}}
	c.Roles["org-reader"] = config.Role{Rules: []config.Rule{{Zones: []string{"*.example.org"}, Actions: []string{ActionDNSRead, ActionUIRead}}}}
	c.Roles["admin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionDNSRead, ActionRecordWrite, ActionRecordAdopt, ActionZoneAdmin, ActionUIRead}}}}
	return c
}

func TestUnmanagedZonesReadOnly(t *testing.T) {
	c := discoveryConfig()
	h, _ := NewHolder(c)
	h.SetDiscovery(fakeDiscovery{"example.com": true, "new.example.org": true, "other.net": true})
	e := New(h)

	if got := strings.Join(e.UnmanagedZones(), ","); got != "new.example.org,other.net" {
		t.Fatalf("unmanaged zones = %s", got)
	}
	if e.Managed("other.net") || !e.IsUnmanaged("other.net") || e.IsUnmanaged("example.com") || e.IsUnmanaged("absent.net") {
		t.Fatal("managed/unmanaged classification")
	}
	admin := &identity.Subject{Roles: []string{"admin"}}
	for _, a := range []string{ActionDNSRead, ActionUIRead} {
		if !e.Allow(admin, a, "other.net") {
			t.Fatalf("%s should be allowed on a discovered zone", a)
		}
	}
	for _, a := range []string{ActionRecordWrite, ActionRecordAdopt, ActionZoneAdmin} {
		if e.Allow(admin, a, "other.net") {
			t.Fatalf("%s must be denied on an unmanaged zone", a)
		}
	}
	if e.AllowRRset(admin, ActionRecordWrite, "other.net", dns.Key{Host: "www", Type: "A"}) {
		t.Fatal("RRset write on an unmanaged zone")
	}
	if _, ok := e.OwnerTeam(&identity.Subject{Roles: []string{"admin"}, Teams: []string{"dns"}}, "other.net"); ok {
		t.Fatal("no owner team on an unmanaged zone")
	}
	// Zone globs of the rules still apply.
	org := &identity.Subject{Roles: []string{"org-reader"}}
	if !e.Allow(org, ActionDNSRead, "new.example.org") || e.Allow(org, ActionDNSRead, "other.net") {
		t.Fatal("zone globs must scope reads of unmanaged zones")
	}
	// Absent from the account: nothing.
	if e.Allow(admin, ActionDNSRead, "absent.net") {
		t.Fatal("undiscovered zone readable")
	}
	// Without discovery, the same zone is unknown.
	if New(mustHolder(t, c)).Allow(admin, ActionDNSRead, "other.net") {
		t.Fatal("unmanaged zone readable without discovery")
	}
}

func mustHolder(t *testing.T, c *config.Config) *Holder {
	t.Helper()
	h, err := NewHolder(c)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestManagedZonesFromDocument(t *testing.T) {
	c := discoveryConfig()
	h := mustHolder(t, c)
	h.SetDiscovery(fakeDiscovery{"new.example.org": true, "other.net": true})
	doc := goodDoc()
	doc.Zones = []string{"New.Example.org."}
	Normalize(&doc)
	snap, errs := h.Compile(&doc, "r1")
	if len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	if !snap.IsManaged("new.example.org") || snap.IsUnmanaged("new.example.org") || !snap.IsUnmanaged("other.net") {
		t.Fatal("document zone must become managed")
	}
	admin := []string{"admin"}
	if !snap.Decide(admin, ActionRecordWrite, "new.example.org", nil).Allowed {
		t.Fatal("writes on a zone managed by the document")
	}
	if got := strings.Join(snap.Zones(), ","); got != "example.com,example.org,new.example.org,secret.net" {
		t.Fatalf("zones = %s", got)
	}
}

func TestValidateManagedZones(t *testing.T) {
	c := discoveryConfig()
	base := BaseDocument(c)
	cases := map[string]struct {
		zones []string
		want  string
	}{
		"outside bounds": {[]string{"other.net"}, "outside policy.bounds.zones"},
		"invalid":        {[]string{"not_a_zone"}, "not a valid domain name"},
		"uppercase":      {[]string{"Example.org"}, "lowercase"},
		"duplicate":      {[]string{"a.example.org", "a.example.org"}, "listed twice"},
	}
	for name, tc := range cases {
		doc := goodDoc()
		doc.Zones = tc.zones
		errs := ValidateManaged(c, base, doc)
		if len(errs) == 0 || !strings.Contains(paths(errs), tc.want) || !strings.HasPrefix(errs[0].Path, "zones[") {
			t.Errorf("%s: got %q", name, paths(errs))
		}
	}
	doc := goodDoc()
	doc.Zones = []string{"a.example.org", "secret.net"} // secret.net is a base zone: redundant, allowed
	if errs := ValidateManaged(c, base, doc); len(errs) > 0 {
		t.Fatal(paths(errs))
	}
}

func TestValidateZonesDiscovered(t *testing.T) {
	c := discoveryConfig()
	h := mustHolder(t, c)
	disc := fakeDiscovery{"a.example.org": true}
	doc := uiapi.PolicyDocument{Zones: []string{"a.example.org", "example.com"}}
	if errs := ValidateZonesDiscovered(doc, h.Current(), disc, true); len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	doc.Zones = []string{"b.example.org"}
	if errs := ValidateZonesDiscovered(doc, h.Current(), disc, true); !strings.Contains(paths(errs), "not found in a provider account") {
		t.Fatalf("got %q", paths(errs))
	}
	if errs := ValidateZonesDiscovered(doc, h.Current(), disc, false); !strings.Contains(paths(errs), "not loaded yet") {
		t.Fatalf("got %q", paths(errs))
	}
	if errs := ValidateZonesDiscovered(doc, h.Current(), nil, false); !strings.Contains(paths(errs), "requires the zone listing of the providers") {
		t.Fatalf("got %q", paths(errs))
	}
	// A zone already managed by the active revision is not checked again.
	active := uiapi.PolicyDocument{Zones: []string{"b.example.org"}}
	Normalize(&active)
	snap, errs := h.Compile(&active, "r1")
	if len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	if errs := ValidateZonesDiscovered(doc, snap, disc, true); len(errs) > 0 {
		t.Fatal(paths(errs))
	}
}

func TestImpactZones(t *testing.T) {
	c := discoveryConfig()
	c.Bindings = append(c.Bindings, config.Binding{Role: "reader-all", Groups: []string{"policy-admins"}})
	h := mustHolder(t, c)
	withZone := goodDoc()
	withZone.Zones = []string{"a.example.org"}
	Normalize(&withZone)
	without := goodDoc()
	Normalize(&without)
	gain := Impact(h.CompileUnchecked(&without, "r1"), h.CompileUnchecked(&withZone, "r2"), nil)
	text := impactText(gain)
	if !strings.Contains(text, "gain: zone a.example.org becomes managed") ||
		!strings.Contains(text, "gains dns.read, ui.read on a.example.org") {
		t.Fatalf("impact of adding a zone:\n%s", text)
	}
	owned := func(team, zone, _ string) int {
		if team == "" && zone == "a.example.org" {
			return 3
		}
		return 0
	}
	loss := impactText(Impact(h.CompileUnchecked(&withZone, "r2"), h.CompileUnchecked(&without, "r3"), owned))
	if !strings.Contains(loss, "loss: zone a.example.org is no longer managed") ||
		!strings.Contains(loss, "warning: zone a.example.org stops being managed while the gate owns 3 RRset(s)") {
		t.Fatalf("impact of removing a zone:\n%s", loss)
	}
	if !strings.HasPrefix(loss, "warning:") {
		t.Fatalf("warnings come first:\n%s", loss)
	}
	if strings.Contains(impactText(Impact(h.CompileUnchecked(&withZone, "r2"), h.CompileUnchecked(&without, "r3"), nil)), "warning: zone") {
		t.Fatal("no warning when nothing is owned")
	}
}

func impactText(items []uiapi.ImpactItem) string {
	var out []string
	for _, it := range items {
		out = append(out, it.Kind+": "+it.Message)
	}
	return strings.Join(out, "\n")
}

func adoBinding() config.Binding {
	return config.Binding{
		Role:     "admin",
		TeamFrom: &config.TeamFrom{Claim: "sub", Regex: `^sc://[^/]+/[^/]+/dns-gate-(.+)$`, Prefix: "ado-"},
		Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"sub": {"sc://org/project/dns-gate-*"}}}},
	}
}

func TestTeamFromClaim(t *testing.T) {
	c := discoveryConfig()
	c.Bindings = append(c.Bindings, adoBinding(), config.Binding{Role: "reader-all", Team: "readers", Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"sub": {"sc://*"}}}}})
	snap := mustHolder(t, c).Current()

	cases := map[string]struct {
		sub   string
		roles string
		teams string
	}{
		"derived team":           {"sc://org/project/dns-gate-Web", "admin,reader-all", "ado-web,readers"},
		"other pipeline":         {"sc://org/project/dns-gate-shop", "admin,reader-all", "ado-shop,readers"},
		"invalid team":           {"sc://org/project/dns-gate-a b", "reader-all", "readers"},
		"capture with slash":     {"sc://org/project/dns-gate-x/y", "reader-all", "readers"},
		"bound glob, no capture": {"sc://org/other/dns-gate-web", "reader-all", "readers"},
	}
	for name, tc := range cases {
		r := snap.Resolve("entra", map[string]any{"sub": tc.sub})
		if got := strings.Join(r.Roles, ","); got != tc.roles {
			t.Errorf("%s: roles %s, want %s", name, got, tc.roles)
		}
		if got := strings.Join(r.Teams, ","); got != tc.teams {
			t.Errorf("%s: teams %s, want %s", name, got, tc.teams)
		}
	}
	// The derived team comes first: it owns what the pipeline creates.
	e := New(mustHolder(t, c))
	r := snap.Resolve("entra", map[string]any{"sub": "sc://org/project/dns-gate-web"})
	team, ok := e.OwnerTeam(&identity.Subject{Roles: r.Roles, Teams: r.Teams}, "example.com")
	if !ok || team != "ado-web" {
		t.Fatalf("owner team %q %v", team, ok)
	}
	// A non-string claim never binds.
	if r := snap.Resolve("entra", map[string]any{"sub": []any{"sc://org/project/dns-gate-web"}}); strings.Contains(strings.Join(r.Teams, ","), "ado-") {
		t.Fatalf("array claim derived a team: %v", r.Teams)
	}
	// Explain shows the derived team, who-can the derivation.
	ex := snap.Explain("entra", map[string]any{"sub": "sc://org/project/dns-gate-web"}, ActionRecordWrite, "example.com", "www", "A")
	if !ex.Allowed || !strings.Contains(strings.Join(ex.Bindings, ","), "admin@ado-web") {
		t.Fatalf("explain: %+v", ex)
	}
	found := false
	for _, en := range snap.WhoCan(ActionRecordWrite, "example.com", "www", "A").Entries {
		found = found || (en.TeamFrom != nil && en.TeamFrom.Prefix == "ado-")
	}
	if !found {
		t.Fatal("who-can must show the team derivation")
	}
}

func TestTeamFromValidation(t *testing.T) {
	c := discoveryConfig()
	base := BaseDocument(c)
	bad := map[string]*uiapi.TeamFrom{
		"no claim":       {Regex: `^(.+)$`},
		"unanchored":     {Claim: "sub", Regex: `repo:(.+)`},
		"two groups":     {Claim: "sub", Regex: `^(a)(b)$`},
		"no group":       {Claim: "sub", Regex: `^ab$`},
		"invalid regex":  {Claim: "sub", Regex: `^(a$`},
		"invalid prefix": {Claim: "sub", Regex: `^(.+)$`, Prefix: "CI_"},
	}
	for name, tf := range bad {
		doc := goodDoc()
		doc.Bindings = []uiapi.Binding{{Role: "web-writer", TeamFrom: tf, Groups: []string{"operators"}}}
		if errs := ValidateManaged(c, base, doc); len(errs) == 0 || errs[0].Path != "bindings[0].team_from" {
			t.Errorf("%s: got %q", name, paths(errs))
		}
	}
	doc := goodDoc()
	doc.Bindings = []uiapi.Binding{{Role: "web-writer", Team: "web", TeamFrom: &uiapi.TeamFrom{Claim: "sub", Regex: `^(.+)$`}, Groups: []string{"operators"}}}
	if errs := ValidateManaged(c, base, doc); !strings.Contains(paths(errs), "exclusive") {
		t.Fatalf("got %q", paths(errs))
	}
	doc.Bindings[0].Team = ""
	doc.Bindings[0].TeamFrom.Regex = `^repo:acme/(?:infra-)?([a-z0-9-]+):.*$`
	if errs := ValidateManaged(c, base, doc); len(errs) > 0 {
		t.Fatal(paths(errs))
	}
}

// The Azure DevOps example of CONFIG.md: team = service connection name.
func TestTeamFromAzureDevOpsServiceConnection(t *testing.T) {
	c := discoveryConfig()
	c.Issuers = append(c.Issuers, config.Issuer{Name: "azure-devops", Issuer: "https://vstoken.dev.azure.com/org-id"})
	tf := &config.TeamFrom{Claim: "sub", Regex: `^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$`}
	if err := config.ValidateTeamFrom(tf.Claim, tf.Regex, tf.Prefix); err != nil {
		t.Fatal(err)
	}
	c.Bindings = append(c.Bindings, config.Binding{Role: "admin", TeamFrom: tf,
		Subjects: []config.Subject{{Issuer: "azure-devops", Claims: map[string]config.StringList{"sub": {"sc://org/project/dns-gate-*"}}}}})
	snap := mustHolder(t, c).Current()
	for sub, team := range map[string]string{
		"sc://org/project/dns-gate-certificates-prd": "dns-gate-certificates-prd",
		"sc://org/project/dns-gate-web":              "dns-gate-web",
		"sc://org/project/dns-gate-":                 "",
		"sc://org/project/other":                     "",
	} {
		r := snap.Resolve("azure-devops", map[string]any{"sub": sub})
		if got := strings.Join(r.Teams, ","); got != team {
			t.Errorf("%s: teams %q, want %q", sub, got, team)
		}
	}
}
