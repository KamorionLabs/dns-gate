package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func layeredConfig() *config.Config {
	t := true
	return &config.Config{
		Zones:   []string{"example.com", "example.org", "secret.net"},
		Limits:  config.Limits{MaxChangesPerRequest: 20},
		Issuers: []config.Issuer{{Name: "entra", Issuer: "https://login.example.com"}},
		Groups: map[string]config.Group{
			"policy-admins": {Members: []config.Subject{{Issuer: "entra", Claims: map[string]config.StringList{"roles": {"Gate.PolicyAdmin"}}}}},
		},
		Roles: map[string]config.Role{
			"policy-admin": {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose", "policy.approve"}}}},
			"base-reader":  {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionUIRead}}}},
			"root":         {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionRecordWrite}}}},
		},
		Bindings: []config.Binding{
			{Role: "policy-admin", Team: "dns", Groups: []string{"policy-admins"}},
		},
		Protected: []config.Protected{{Zones: []string{"*"}, Hosts: []string{"@"}, Types: []string{"NS"}}},
		Policy: config.Policy{
			Editable: true, RequireApproval: &t, EditMaxAge: config.Duration(15 * time.Minute),
			Bounds: config.Bounds{Zones: []string{"example.com", "*.example.org", "example.org"}, Actions: []string{ActionDNSRead, ActionRecordWrite, ActionUIRead}},
		},
	}
}

func goodDoc() uiapi.PolicyDocument {
	return uiapi.PolicyDocument{
		Groups: map[string]uiapi.Group{
			"operators": {Members: []uiapi.SubjectMatcher{{Issuer: "entra", Claims: map[string][]string{"roles": {"Gate.Operator"}}}}},
		},
		Roles: map[string]uiapi.Role{
			"web-writer": {Rules: []uiapi.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionRecordWrite}, Records: &uiapi.RecordScope{Hosts: []string{"*.staging"}, Types: []string{"CNAME"}}}}},
		},
		Bindings: []uiapi.Binding{
			{Role: "web-writer", Team: "web", Groups: []string{"operators"}},
			{Role: "base-reader", Groups: []string{"operators", "policy-admins"}},
		},
	}
}

func paths(errs []uiapi.ValidationError) string {
	var out []string
	for _, e := range errs {
		out = append(out, e.Path+": "+e.Message)
	}
	return strings.Join(out, "\n")
}

func TestValidateManagedOK(t *testing.T) {
	c := layeredConfig()
	if errs := ValidateManaged(c, BaseDocument(c), goodDoc()); len(errs) > 0 {
		t.Fatal(paths(errs))
	}
}

func TestValidateManagedErrors(t *testing.T) {
	c := layeredConfig()
	base := BaseDocument(c)
	cases := map[string]struct {
		mut  func(*uiapi.PolicyDocument)
		path string
	}{
		"base role name":    {func(d *uiapi.PolicyDocument) { d.Roles["root"] = d.Roles["web-writer"] }, "roles.root"},
		"base group name":   {func(d *uiapi.PolicyDocument) { d.Groups["policy-admins"] = d.Groups["operators"] }, "groups.policy-admins"},
		"meta action":       {func(d *uiapi.PolicyDocument) { setActions(d, ActionDNSRead, "policy.approve") }, "roles.web-writer.rules[0].actions[1]"},
		"action out bounds": {func(d *uiapi.PolicyDocument) { setActions(d, ActionRecordAdopt) }, "roles.web-writer.rules[0].actions[0]"},
		"zone out bounds":   {func(d *uiapi.PolicyDocument) { setZones(d, "*") }, "roles.web-writer.rules[0].zones[0]"},
		"zone other":        {func(d *uiapi.PolicyDocument) { setZones(d, "secret.net") }, "roles.web-writer.rules[0].zones[0]"},
		"question mark":     {func(d *uiapi.PolicyDocument) { setZones(d, "?.example.org") }, "roles.web-writer.rules[0].zones[0]"},
		"base role escalate": {func(d *uiapi.PolicyDocument) {
			d.Bindings = append(d.Bindings, uiapi.Binding{Role: "policy-admin", Groups: []string{"operators"}})
		}, "bindings[2].role"},
		"base role wide": {func(d *uiapi.PolicyDocument) {
			d.Bindings = append(d.Bindings, uiapi.Binding{Role: "root", Groups: []string{"operators"}})
		}, "bindings[2].role"},
		"unknown group":  {func(d *uiapi.PolicyDocument) { d.Bindings[0].Groups = []string{"ghost"} }, "bindings[0].groups[0]"},
		"match anyone":   {func(d *uiapi.PolicyDocument) { d.Groups["operators"].Members[0].Claims["roles"] = []string{"*"} }, "groups.operators.members[0].claims.roles[0]"},
		"unknown issuer": {func(d *uiapi.PolicyDocument) { d.Groups["operators"].Members[0].Issuer = "evil" }, "groups.operators.members[0].issuer"},
		"unlimited": {func(d *uiapi.PolicyDocument) {
			r := d.Roles["web-writer"]
			r.MaxChangesPerRequest = -1
			d.Roles["web-writer"] = r
		}, "roles.web-writer.max_changes_per_request"},
		"key no expiry": {func(d *uiapi.PolicyDocument) {
			d.VirtualKeys = []uiapi.VirtualKey{{ID: "k1", AppID: "vk-k1", KeySHA256: strings.Repeat("a", 64), Roles: []string{"web-writer"}}}
		}, "virtual_keys[0].expires_at"},
	}
	for name, c2 := range cases {
		d := goodDoc()
		c2.mut(&d)
		errs := ValidateManaged(c, base, d)
		found := false
		for _, e := range errs {
			found = found || e.Path == c2.path
		}
		if !found {
			t.Errorf("%s: expected an error at %s, got:\n%s", name, c2.path, paths(errs))
		}
	}
	c.Policy.Editable = false
	if errs := ValidateManaged(c, base, goodDoc()); len(errs) == 0 {
		t.Error("non-editable policy accepted a managed document")
	}
}

func setActions(d *uiapi.PolicyDocument, a ...string) {
	r := d.Roles["web-writer"]
	r.Rules[0].Actions = a
	d.Roles["web-writer"] = r
}

func setZones(d *uiapi.PolicyDocument, z ...string) {
	r := d.Roles["web-writer"]
	r.Rules[0].Zones = z
	d.Roles["web-writer"] = r
}

func TestZoneCovered(t *testing.T) {
	b := []string{"example.com", "*.example.org"}
	for p, want := range map[string]bool{
		"example.com": true, "a.example.org": true, "*.example.org": true, "*.b.example.org": true,
		"*": false, "*.com": false, "example.org": false, "?.example.org": false, "*example.org": false,
	} {
		if got := ZoneCovered(b, p); got != want {
			t.Errorf("ZoneCovered(%q) = %v", p, got)
		}
	}
}

func TestMergedEvaluation(t *testing.T) {
	c := layeredConfig()
	h, _ := NewHolder(c)
	doc := goodDoc()
	snap, errs := h.Compile(&doc, "rev1")
	if len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	claims := map[string]any{"sub": "u1", "roles": []any{"Gate.Operator"}}
	res := snap.Resolve("entra", claims)
	if strings.Join(res.Groups, ",") != "operators" || strings.Join(res.Roles, ",") != "base-reader,web-writer" || res.Teams[0] != "web" {
		t.Fatalf("resolution %+v", res)
	}
	d := snap.Decide(res.Roles, ActionRecordWrite, "example.com", &dns.Key{Host: "www.staging", Type: "CNAME"})
	if !d.Allowed || d.Layer != LayerManaged || d.Matched != "roles.web-writer.rules[0]" {
		t.Fatalf("decision %+v", d)
	}
	if snap.Decide(res.Roles, ActionRecordWrite, "example.com", &dns.Key{Host: "www", Type: "CNAME"}).Allowed {
		t.Fatal("outside record scope")
	}
	if snap.Decide(res.Roles, "policy.approve", "", nil).Allowed {
		t.Fatal("managed layer granted policy.*")
	}
	admin := snap.Resolve("entra", map[string]any{"sub": "a", "roles": []any{"Gate.PolicyAdmin", "Other"}})
	if !snap.Decide(admin.Roles, "policy.approve", "", nil).Allowed {
		t.Fatal("base policy admin")
	}

	// Defense in depth: an unvalidated managed rule outside the bounds is ignored.
	evil := goodDoc()
	evil.Roles["web-writer"] = uiapi.Role{Rules: []uiapi.Rule{{Zones: []string{"*"}, Actions: []string{ActionRecordWrite, "policy.approve"}}}}
	es := h.CompileUnchecked(&evil, "evil")
	if es.Decide([]string{"web-writer"}, ActionRecordWrite, "secret.net", nil).Allowed || es.Decide([]string{"web-writer"}, "policy.approve", "", nil).Allowed {
		t.Fatal("unchecked managed rule escaped the bounds")
	}
}

func TestExplainAndWhoCan(t *testing.T) {
	c := layeredConfig()
	h, _ := NewHolder(c)
	doc := goodDoc()
	snap, _ := h.Compile(&doc, "rev1")
	ex := snap.Explain("entra", map[string]any{"sub": "u", "roles": []any{"Gate.Operator"}}, ActionRecordWrite, "example.com", "app.staging", "CNAME")
	if !ex.Allowed || ex.Layer != LayerManaged || len(ex.Bindings) != 2 || ex.Groups[0] != "operators" {
		t.Fatalf("explain %+v", ex)
	}
	ex = snap.Explain("entra", map[string]any{"sub": "u", "roles": []any{"Gate.Operator"}}, ActionRecordWrite, "example.com", "@", "NS")
	if ex.Allowed || !strings.HasPrefix(ex.Denied, "protected") {
		t.Fatalf("explain protected %+v", ex)
	}
	ex = snap.Explain("entra", map[string]any{"sub": "u"}, ActionDNSRead, "example.com", "", "")
	if ex.Allowed || ex.Denied != "no binding applies to this subject" {
		t.Fatalf("explain unbound %+v", ex)
	}
	wc := snap.WhoCan(ActionRecordWrite, "example.com", "x.staging", "CNAME")
	if len(wc.Entries) != 1 || wc.Entries[0].Role != "web-writer" || wc.Entries[0].Layer != LayerManaged || wc.Entries[0].Groups[0] != "operators" {
		t.Fatalf("who-can %+v", wc)
	}
	if wc := snap.WhoCan(ActionRecordWrite, "example.com", "@", "NS"); !wc.Protected || len(wc.Entries) != 0 {
		t.Fatalf("who-can protected %+v", wc)
	}
}

func TestImpactAndDiff(t *testing.T) {
	c := layeredConfig()
	h, _ := NewHolder(c)
	old := goodDoc()
	oldSnap, _ := h.Compile(&old, "rev1")
	next := goodDoc()
	next.Bindings = next.Bindings[1:] // web loses web-writer
	newSnap, errs := h.Compile(&next, "rev2")
	if len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	items := Impact(oldSnap, newSnap, func(team, zone, _ string) int {
		if team == "web" && zone == "example.com" {
			return 12
		}
		return 0
	})
	if len(items) < 2 || items[0].Kind != "warning" || !strings.Contains(items[0].Message, "team web loses write on example.com where it owns 12") {
		t.Fatalf("impact %+v", items)
	}
	hasLoss := false
	for _, it := range items {
		hasLoss = hasLoss || (it.Kind == "loss" && it.Role == "web-writer")
	}
	if !hasLoss {
		t.Fatalf("missing loss item: %+v", items)
	}

	a, _ := DocumentYAML(old)
	b, _ := DocumentYAML(next)
	diff := UnifiedDiff(a, b, "revision rev1", "revision rev2")
	if !strings.HasPrefix(diff, "--- revision rev1\n+++ revision rev2\n@@ ") || !strings.Contains(diff, "\n-") {
		t.Fatalf("diff:\n%s", diff)
	}
	if UnifiedDiff(a, a, "x", "y") != "" {
		t.Fatal("identical documents must give an empty diff")
	}
}

type fakeActive struct {
	rev *store.PolicyRevision
	err error
}

func (f *fakeActive) ActiveRevision(context.Context) (*store.PolicyRevision, error) {
	return f.rev, f.err
}

func TestHolderRefresh(t *testing.T) {
	c := layeredConfig()
	h, _ := NewHolder(c)
	doc := goodDoc()
	raw, _ := json.Marshal(doc)
	src := &fakeActive{rev: &store.PolicyRevision{ID: "rev-0001", Document: raw}}
	if err := h.Refresh(context.Background(), src); err != nil || h.Current().RevisionID != "rev-0001" {
		t.Fatalf("refresh: %v %q", err, h.Current().RevisionID)
	}
	// A revision that no longer validates keeps the previous snapshot.
	bad := goodDoc()
	setZones(&bad, "secret.net")
	raw, _ = json.Marshal(bad)
	src.rev = &store.PolicyRevision{ID: "rev-0002", Document: raw}
	if err := h.Refresh(context.Background(), src); err == nil || h.Current().RevisionID != "rev-0001" {
		t.Fatalf("invalid revision applied: %v", err)
	}
	src.rev, src.err = nil, store.ErrNotFound
	if err := h.Refresh(context.Background(), src); err != nil || h.Current().RevisionID != "" {
		t.Fatal("no active revision must fall back to base")
	}
}

func TestPermissions(t *testing.T) {
	c := layeredConfig()
	h, _ := NewHolder(c)
	doc := goodDoc()
	doc.Roles["wide"] = uiapi.Role{Rules: []uiapi.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionRecordAdopt}}}}
	snap := h.CompileUnchecked(&doc, "r1")

	got := snap.Permissions([]string{"web-writer", "policy-admin", "unknown", "wide"})
	b, _ := json.Marshal(got)
	want := `[{"role":"policy-admin","zones":["*"],"actions":["policy.read","policy.propose","policy.approve"],"hosts":[],"types":[]},` +
		`{"role":"web-writer","zones":["example.com"],"actions":["dns.read","dns.record.write"],"hosts":["*.staging"],"types":["CNAME"]},` +
		`{"role":"wide","zones":["example.com"],"actions":["dns.read"],"hosts":[],"types":[]}]`
	if string(b) != want {
		t.Fatalf("permissions:\n got %s\nwant %s", b, want)
	}
	if p := snap.Permissions(nil); p == nil || len(p) != 0 {
		t.Fatalf("no role: %#v", p)
	}
}
