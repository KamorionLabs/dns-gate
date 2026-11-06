package policy

import (
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func teamsConfig(strict bool) *config.Config {
	c := layeredConfig()
	c.Roles["web-records"] = config.Role{Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionRecordWrite}}}}
	c.Bindings = append(c.Bindings,
		config.Binding{Role: "web-records", Team: "web"},
		config.Binding{Role: "base-reader", TeamFrom: &config.TeamFrom{Claim: "repo", Regex: "^acme/(.+)$", Prefix: "gh-"}, Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"repo": {"acme/*"}}}}},
	)
	c.Teams = map[string]config.Team{
		"web": {Description: "Web shop", Members: config.TeamMembers{
			Groups:   []string{"policy-admins"},
			Subjects: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"sub": {"pipeline-web-*"}}}},
		}},
		"dns": {Description: "DNS admins"},
	}
	if !strict {
		c.Teams = nil
	}
	return c
}

func TestTeamMembersBinding(t *testing.T) {
	snap := FromConfig(teamsConfig(true)).Holder().Current()
	res := snap.Resolve("entra", map[string]any{"sub": "pipeline-web-prod"})
	if !contains(res.Roles, "web-records") || len(res.Teams) != 1 || res.Teams[0] != "web" {
		t.Fatalf("pipeline member of web: %+v", res)
	}
	res = snap.Resolve("entra", map[string]any{"sub": "someone", "roles": []any{"Gate.PolicyAdmin"}})
	if !contains(res.Roles, "web-records") || !contains(res.Roles, "policy-admin") || res.Teams[0] != "dns" || !contains(res.Teams, "web") {
		t.Fatalf("group member: %+v", res)
	}
	if res := snap.Resolve("entra", map[string]any{"sub": "other"}); len(res.Roles) != 0 {
		t.Fatalf("non member bound: %+v", res)
	}
	if !snap.StrictTeams() || !snap.KnownTeam("web") || snap.KnownTeam("wbe") || !snap.KnownTeam("gh-site") || snap.KnownTeam("gh-") {
		t.Fatal("known teams in strict mode")
	}
	wc := snap.WhoCan(ActionRecordWrite, "example.com", "www", "A")
	found := false
	for _, e := range wc.Entries {
		if e.Role == "web-records" && e.TeamMembers != nil && len(e.TeamMembers.Groups) == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("who-can shows the team members: %+v", wc.Entries)
	}
}

func TestTeamInfos(t *testing.T) {
	snap := FromConfig(teamsConfig(true)).Holder().Current()
	infos := snap.TeamInfos([]string{"web", "gh-site", "legacy"}, false)
	kinds := map[string]string{}
	for _, ti := range infos {
		kinds[ti.Name] = ti.Kind
		if ti.Members != nil {
			t.Fatalf("members without policy.read: %+v", ti)
		}
	}
	want := map[string]string{"web": uiapi.TeamKindDeclared, "dns": uiapi.TeamKindDeclared, "gh-*": uiapi.TeamKindFamily, "gh-site": uiapi.TeamKindFamily, "legacy": uiapi.TeamKindStore}
	for n, k := range want {
		if kinds[n] != k {
			t.Errorf("team %s: kind %q, want %q (%v)", n, kinds[n], k, kinds)
		}
	}
	ti, ok := snap.TeamInfo("web", nil, true)
	if !ok || ti.Members == nil || ti.Description != "Web shop" || len(ti.Roles) != 1 || ti.Roles[0] != "web-records" || ti.Layer != LayerBase {
		t.Fatalf("web: %+v", ti)
	}
	if _, ok := snap.TeamInfo("nobody", nil, false); ok {
		t.Fatal("unknown team found")
	}

	mig := FromConfig(teamsConfig(false)).Holder().Current()
	if mig.StrictTeams() || !mig.KnownTeam("anything") {
		t.Fatal("migration mode accepts any team")
	}
	got := map[string]uiapi.TeamInfo{}
	for _, ti := range mig.TeamInfos(nil, false) {
		got[ti.Name] = ti
	}
	if got["dns"].Kind != uiapi.TeamKindAuto || got["dns"].Warning == "" || got["web"].Kind != uiapi.TeamKindAuto {
		t.Fatalf("auto-declared teams: %+v", got)
	}
}

func TestValidateManagedTeams(t *testing.T) {
	c := teamsConfig(true)
	base := BaseDocument(c)
	doc := goodDoc()
	doc.Teams = map[string]uiapi.Team{"ops": {Members: uiapi.TeamMembers{Groups: []string{"operators"}}}}
	doc.Bindings[0].Team = "ops"
	doc.Bindings = append(doc.Bindings, uiapi.Binding{Role: "web-writer", Team: "ops"})
	if errs := ValidateManaged(c, base, doc); len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	cases := map[string]struct {
		mut  func(*uiapi.PolicyDocument)
		path string
	}{
		"undeclared binding team": {func(d *uiapi.PolicyDocument) { d.Bindings[0].Team = "opz" }, "bindings[0].team"},
		"base team name":          {func(d *uiapi.PolicyDocument) { d.Teams["web"] = d.Teams["ops"] }, "teams.web"},
		"unknown member group": {func(d *uiapi.PolicyDocument) {
			d.Teams["ops"] = uiapi.Team{Members: uiapi.TeamMembers{Groups: []string{"ghost"}}}
		}, "teams.ops.members.groups[0]"},
		"anyone member": {func(d *uiapi.PolicyDocument) {
			d.Teams["ops"] = uiapi.Team{Members: uiapi.TeamMembers{Subjects: []uiapi.SubjectMatcher{{Issuer: "entra", Claims: map[string][]string{"sub": {"*"}}}}}}
		}, "teams.ops.members.subjects[0].claims.sub[0]"},
		"team without members": {func(d *uiapi.PolicyDocument) { d.Bindings[2].Team = "dns" }, "bindings[2]"},
		"undeclared key team": {func(d *uiapi.PolicyDocument) {
			d.VirtualKeys = []uiapi.VirtualKey{{ID: "k", AppID: "app-k", KeySHA256: strings.Repeat("0", 64), Roles: []string{"web-writer"}, Teams: []string{"nope"}}}
		}, "virtual_keys[0].teams[0]"},
	}
	for name, tc := range cases {
		d := doc
		d.Teams = map[string]uiapi.Team{"ops": doc.Teams["ops"]}
		d.Bindings = append([]uiapi.Binding(nil), doc.Bindings...)
		tc.mut(&d)
		errs := ValidateManaged(c, base, d)
		if !strings.Contains(paths(errs), tc.path+":") {
			t.Errorf("%s: want an error at %s, got:\n%s", name, tc.path, paths(errs))
		}
	}
	mig := teamsConfig(false)
	d := goodDoc()
	d.Bindings[0].Team = "anything"
	if errs := ValidateManaged(mig, BaseDocument(mig), d); len(errs) > 0 {
		t.Fatalf("migration mode refuses an undeclared team: %s", paths(errs))
	}
	old := FromConfig(mig).Holder().Current()
	nd := d
	nsnap := FromConfig(mig).Holder().CompileUnchecked(&nd, "r1")
	items := Impact(old, nsnap, nil)
	found := false
	for _, it := range items {
		found = found || (it.Kind == "warning" && strings.Contains(it.Message, "team anything is not declared"))
	}
	if !found {
		t.Fatalf("impact warns about the undeclared team: %+v", items)
	}
}
