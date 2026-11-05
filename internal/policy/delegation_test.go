package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

func TestHostCovered(t *testing.T) {
	cases := []struct {
		allowed []string
		p       string
		want    bool
	}{
		{[]string{"**"}, "@", true},
		{[]string{"**"}, "**", true},
		{[]string{"**.apps"}, "x.apps", true},
		{[]string{"**.apps"}, "a.b.apps", true},
		{[]string{"**.apps"}, "*.apps", true},
		{[]string{"**.apps"}, "**.apps", true},
		{[]string{"**.apps"}, "apps", false},
		{[]string{"*.apps"}, "x.apps", true},
		{[]string{"*.apps"}, "*.apps", true},
		{[]string{"*.apps"}, "**.apps", false},
		{[]string{"*.apps"}, "a.b.apps", false},
		{[]string{"_*.apps"}, "_acme.apps", true},
		{[]string{"_acme*"}, "_*", false},
		{[]string{"@"}, "@", true},
		{[]string{"*"}, "@", false},
		{[]string{"x.apps"}, "**", false},
		{[]string{"a?c"}, "abc", false},
		{[]string{"WWW"}, "www.", true},
	}
	for _, c := range cases {
		if got := HostCovered(c.allowed, c.p); got != c.want {
			t.Errorf("HostCovered(%v, %q) = %v", c.allowed, c.p, got)
		}
	}
}

func TestMatcherCovered(t *testing.T) {
	allowed := []config.Subject{{Issuer: "ado", Claims: map[string]config.StringList{"sub": {"sc://org/proj/gate-*"}}}}
	m := func(iss string, claims map[string][]string) uiapi.SubjectMatcher {
		return uiapi.SubjectMatcher{Issuer: iss, Claims: claims}
	}
	cases := []struct {
		m    uiapi.SubjectMatcher
		want bool
	}{
		{m("ado", map[string][]string{"sub": {"sc://org/proj/gate-x"}}), true},
		{m("ado", map[string][]string{"sub": {"sc://org/proj/gate-x", "sc://org/proj/gate-y"}}), true},
		{m("ado", map[string][]string{"sub": {"sc://org/proj/gate-x", "sc://org/proj/other"}}), false},
		{m("ado", map[string][]string{"sub": {"sc://org/proj/gate-x"}, "aud": {"x"}}), true},
		{m("ado", map[string][]string{"aud": {"x"}}), false},
		{m("other", map[string][]string{"sub": {"sc://org/proj/gate-x"}}), false},
		{m("ado", map[string][]string{"sub": {"sc://org/*"}}), false},
	}
	for i, c := range cases {
		if got := matcherCovered(allowed, c.m); got != c.want {
			t.Errorf("case %d: matcherCovered = %v", i, got)
		}
	}
}

func delegationConfig() *config.Config {
	c := layeredConfig()
	c.Issuers = append(c.Issuers, config.Issuer{Name: "idp", Issuer: "https://idp.example.net"})
	c.Policy.Delegations = []config.Delegation{{
		Name:     "ci",
		Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"ci"}}}},
		Allow: config.DelegationAllow{
			Zones: []string{"example.com"}, Actions: []string{ActionRecordWrite},
			BindingSubjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"p-*"}}}},
			Teams:           config.DelegationTeams{Names: []string{"team-*"}},
			MaxObjects:      10,
		},
	}}
	return c
}

func delegatedDoc(rule uiapi.Rule, b uiapi.Binding, delegation string) uiapi.PolicyDocument {
	o := uiapi.DelegatedOwner{Delegation: delegation, CreatedBy: "idp:ci", UpdatedBy: "idp:ci", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	d := uiapi.PolicyDocument{Delegated: &uiapi.DelegatedObjects{
		Roles:    map[string]uiapi.DelegatedRole{"r": {Role: uiapi.Role{Rules: []uiapi.Rule{rule}}, Owner: o}},
		Bindings: map[string]uiapi.DelegatedBinding{"b": {Binding: b, Owner: o}},
	}}
	Normalize(&d)
	return d
}

func TestValidateDelegatedAndSnapshotRecheck(t *testing.T) {
	c := delegationConfig()
	base := BaseDocument(c)
	rule := uiapi.Rule{Zones: []string{"example.com"}, Actions: []string{ActionRecordWrite}}
	b := uiapi.Binding{Role: "r", Team: "team-a", Subjects: []uiapi.SubjectMatcher{{Issuer: "idp", Claims: map[string][]string{"sub": {"p-a"}}}}}
	doc := delegatedDoc(rule, b, "ci")
	if errs := ValidateManaged(c, base, doc); len(errs) > 0 {
		t.Fatalf("valid delegated document: %+v", errs)
	}
	snap := compile(c, base, &doc, "r1", nil)
	res := snap.Resolve("idp", map[string]any{"sub": "p-a"})
	if len(res.Roles) != 1 || res.Teams[0] != "team-a" {
		t.Fatalf("resolve: %+v", res)
	}
	if !snap.Decide(res.Roles, ActionRecordWrite, "example.com", &rrset.Key{Host: "www", Type: "A"}).Allowed {
		t.Fatal("delegated rule not effective")
	}
	if got := snap.Resolve("idp", map[string]any{"sub": "ci"}).Delegations; len(got) != 1 || got[0] != "ci" {
		t.Fatalf("delegations of the delegated subject: %v", got)
	}

	// Unknown delegation (removed from the file): invalid, and the unchecked
	// compile of the old revision grants nothing.
	gone := delegatedDoc(rule, b, "removed")
	errs := ValidateManaged(c, base, gone)
	if len(errs) == 0 || !strings.Contains(errs[0].Message, "unknown delegation") {
		t.Fatalf("unknown delegation: %+v", errs)
	}
	snap = compile(c, base, &gone, "r2", nil)
	if snap.Decide([]string{"r"}, ActionRecordWrite, "example.com", &rrset.Key{Host: "www", Type: "A"}).Allowed {
		t.Fatal("a rule of a removed delegation still grants")
	}

	// A delegated role cannot shadow a managed one.
	doc.Roles = map[string]uiapi.Role{"r": {Rules: []uiapi.Rule{rule}}}
	if errs := ValidateManaged(c, base, doc); len(errs) == 0 {
		t.Fatal("delegated role shadowing a managed role accepted")
	}
}

func TestConfigDelegationsValidation(t *testing.T) {
	good := `
upstream: {app_id: a}
zones: [example.com]
issuers:
  - {name: ci, issuer: "https://ci.example.net", audiences: [gate]}
policy:
  editable: true
  bounds: {zones: [example.com], actions: [dns.read, dns.record.write]}
  delegations:
    - name: workloads
      subjects: [{issuer: ci, claims: {sub: [sc://o/p/workloads]}}]
      allow:
        zones: [example.com]
        actions: [dns.record.write]
        binding_subjects: [{issuer: ci, claims: {sub: ["sc://o/p/gate-*"]}}]
        teams:
          from_subject: {claim: sub, regex: "^sc://[^/]+/[^/]+/(gate-[a-z0-9-]+)$"}
`
	env := func(k string) string {
		if k == "EURODNS_API_KEY" {
			return "k"
		}
		return ""
	}
	cfg, err := config.Parse([]byte(good), env)
	if err != nil {
		t.Fatalf("valid delegation: %v", err)
	}
	if cfg.Policy.Delegations[0].Allow.MaxObjects != config.DefaultDelegationMaxObjects {
		t.Fatalf("max_objects default: %d", cfg.Policy.Delegations[0].Allow.MaxObjects)
	}
	bad := map[string]string{
		"zone outside bounds":   strings.Replace(good, "zones: [example.com]\n        actions", "zones: [example.org]\n        actions", 1),
		"action outside bounds": strings.Replace(good, "actions: [dns.record.write]", "actions: [dns.record.adopt]", 1),
		"policy action":         strings.Replace(good, "actions: [dns.record.write]", "actions: [policy.approve]", 1),
		"no teams":              strings.Replace(good, "teams:\n          from_subject", "teams_unused:\n          from_subject", 1),
		"anyone":                strings.Replace(good, `"sc://o/p/gate-*"`, `"*"`, 1),
		"not editable":          strings.Replace(good, "editable: true", "editable: false", 1),
	}
	for name, y := range bad {
		if _, err := config.Parse([]byte(y), env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
