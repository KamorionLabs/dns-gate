package policy

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// folderDiscovery is a discovery with folders: zone -> folder ("" for a
// zone of a provider without folders).
type folderDiscovery struct {
	mu      sync.Mutex
	folders map[string]string
}

func (f *folderDiscovery) Discovered(z string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.folders[z]
	return ok
}

func (f *folderDiscovery) DiscoveredZones() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for z := range f.folders {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

func (f *folderDiscovery) Folder(z string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.folders[z]
}

func (f *folderDiscovery) move(z, folder string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.folders[z] = folder
}

func folderConfig() *config.Config {
	c := layeredConfig()
	c.Zones = append(c.Zones, "example.es", "example.fr", "example.net")
	c.Roles["es-writer"] = config.Role{Rules: []config.Rule{{Folders: []string{"/ES", "/ES/**"}, Actions: []string{ActionDNSRead, ActionRecordWrite, ActionUIRead}}}}
	c.Roles["es-madrid"] = config.Role{Rules: []config.Rule{{Folders: []string{"/ES/Madrid"}, Actions: []string{ActionDNSRead}}}}
	c.Roles["root-reader"] = config.Role{Rules: []config.Rule{{Folders: []string{"/"}, Actions: []string{ActionDNSRead}}}}
	c.Roles["mixed"] = config.Role{Rules: []config.Rule{{Zones: []string{"example.com"}, Folders: []string{"/FR"}, Actions: []string{ActionDNSRead}}}}
	c.Bindings = append(c.Bindings, config.Binding{Role: "es-writer", Team: "es", Groups: []string{"policy-admins"}})
	c.Policy.Bounds.Folders = []string{"/ES/**", "/FR"}
	c.Policy.Bounds.Zones = append(c.Policy.Bounds.Zones, "example.es", "example.fr")
	return c
}

func folderHolder(t *testing.T) (*Holder, *folderDiscovery) {
	t.Helper()
	h := mustHolder(t, folderConfig())
	d := &folderDiscovery{folders: map[string]string{
		"example.com": "/", "example.es": "/ES", "example.fr": "/FR", "example.net": "",
		"madrid.example.org": "/ES/Madrid",
	}}
	h.SetDiscovery(d)
	return h, d
}

func TestFolderRulesDecide(t *testing.T) {
	h, d := folderHolder(t)
	e := New(h)
	es := &identity.Subject{Roles: []string{"es-writer"}}
	if !e.AllowRRset(es, ActionRecordWrite, "example.es", dns.Key{Host: "www", Type: "A"}) {
		t.Fatal("/ES rule must grant on a zone of folder /ES")
	}
	if e.Allow(es, ActionRecordWrite, "example.fr") || e.Allow(es, ActionDNSRead, "example.com") {
		t.Fatal("folder rule granted outside its folders")
	}
	if e.Allow(es, ActionDNSRead, "example.net") {
		t.Fatal("a zone without folder matched a folder rule")
	}
	// A folder selector never makes a zone managed: the discovered zone
	// below /ES is readable, not writable.
	if !e.Allow(es, ActionDNSRead, "madrid.example.org") || e.Allow(es, ActionRecordWrite, "madrid.example.org") {
		t.Fatal("unmanaged zone in a selected folder must be read-only")
	}
	snap := h.Current()
	dec := snap.Decide([]string{"es-writer"}, ActionRecordWrite, "example.es", nil)
	if !dec.Allowed || dec.Folder != "/ES" || dec.Matched != "roles.es-writer.rules[0]" {
		t.Fatalf("decision = %+v", dec)
	}
	if dec := snap.Decide([]string{"mixed"}, ActionDNSRead, "example.com", nil); !dec.Allowed || dec.Folder != "" {
		t.Fatalf("a zone listed in zones is not matched by folder: %+v", dec)
	}
	if !snap.Decide([]string{"mixed"}, ActionDNSRead, "example.fr", nil).Allowed {
		t.Fatal("zones or folders: the folder side must grant")
	}
	if !snap.Decide([]string{"root-reader"}, ActionDNSRead, "example.com", nil).Allowed ||
		snap.Decide([]string{"root-reader"}, ActionDNSRead, "example.es", nil).Allowed {
		t.Fatal("/ selects the zones in no folder only")
	}
	if snap.Decide([]string{"es-madrid"}, ActionDNSRead, "example.es", nil).Allowed {
		t.Fatal("/ES/Madrid must not select /ES")
	}

	// Moving a domain to another folder changes the rights at once.
	d.move("example.es", "/FR")
	if e.Allow(es, ActionRecordWrite, "example.es") {
		t.Fatal("rights must follow the folder known at decision time")
	}
	d.move("example.fr", "/ES/Barcelona")
	if !e.Allow(es, ActionRecordWrite, "example.fr") {
		t.Fatal("zone moved below /ES must be granted")
	}
}

func TestFolderExplainWhoCanPermissions(t *testing.T) {
	h, _ := folderHolder(t)
	snap := h.Current()
	claims := map[string]any{"roles": "Gate.PolicyAdmin"}
	exp := snap.Explain("entra", claims, ActionRecordWrite, "example.es", "www", "A")
	if !exp.Allowed || exp.Folder != "/ES" || exp.Matched != "roles.es-writer.rules[0]" {
		t.Fatalf("explain = %+v", exp)
	}
	if exp := snap.Explain("entra", claims, ActionRecordWrite, "example.fr", "www", "A"); exp.Allowed || exp.Folder != "" {
		t.Fatalf("explain outside the folder = %+v", exp)
	}
	wc := snap.WhoCan(ActionRecordWrite, "example.es", "www", "A")
	found := false
	for _, e := range wc.Entries {
		if e.Role == "es-writer" {
			found = e.ByFolder && e.Team == "es"
		}
	}
	if wc.Folder != "/ES" || !found {
		t.Fatalf("who can = %+v", wc)
	}
	if wc := snap.WhoCan(ActionRecordWrite, "example.com", "www", "A"); wc.Folder != "/" {
		t.Fatalf("who can on a root zone = %+v", wc)
	}
	perms := snap.Permissions([]string{"es-writer"})
	if len(perms) != 1 || strings.Join(perms[0].Folders, ",") != "/ES,/ES/**" || len(perms[0].Zones) != 0 {
		t.Fatalf("permissions = %+v", perms)
	}
	if got := BaseDocument(folderConfig()).Roles["es-writer"].Rules[0].Folders; strings.Join(got, ",") != "/ES,/ES/**" {
		t.Fatalf("base document folders = %v", got)
	}
}

func TestFolderImpact(t *testing.T) {
	h, _ := folderHolder(t)
	old := h.Current()
	doc := uiapi.PolicyDocument{
		Roles:    map[string]uiapi.Role{"fr-writer": {Rules: []uiapi.Rule{{Folders: []string{"/FR"}, Actions: []string{ActionRecordWrite}}}}},
		Bindings: []uiapi.Binding{{Role: "fr-writer", Team: "fr", Groups: []string{"policy-admins"}}},
	}
	Normalize(&doc)
	snap, errs := h.Compile(&doc, "r1")
	if len(errs) > 0 {
		t.Fatalf("valid folder document: %+v", errs)
	}
	gain := false
	for _, it := range Impact(old, snap, nil) {
		gain = gain || (it.Kind == "gain" && it.Role == "fr-writer" && strings.Join(it.Zones, ",") == "example.fr")
	}
	if !gain {
		t.Fatalf("impact: %+v", Impact(old, snap, nil))
	}
	dynamic := ""
	for _, it := range Impact(old, snap, nil) {
		if it.Kind == "warning" && it.Role == "fr-writer" {
			dynamic = it.Message
		}
		if strings.Contains(it.Message, "not listed") {
			t.Fatalf("discovery is loaded: %+v", it)
		}
	}
	if !strings.Contains(dynamic, "dynamic folder rule") || !strings.Contains(dynamic, "1 zone currently") {
		t.Fatalf("dynamic folder rule entry: %q", dynamic)
	}
	for _, it := range Impact(snap, snap, nil) {
		if it.Role == "fr-writer" {
			t.Fatalf("unchanged folder rule reported again: %+v", it)
		}
	}

	h.SetDiscovery(notLoaded{h.Discovery().(*folderDiscovery)})
	snap, _ = h.Compile(&doc, "r2")
	warned := false
	for _, it := range Impact(h.Current(), snap, nil) {
		warned = warned || (it.Kind == "warning" && strings.Contains(it.Message, "not listed"))
	}
	if !warned {
		t.Fatalf("no warning while discovery is not loaded: %+v", Impact(h.Current(), snap, nil))
	}
}

type notLoaded struct{ *folderDiscovery }

func (notLoaded) Loaded() bool { return false }

func TestFolderManagedBounds(t *testing.T) {
	c := folderConfig()
	base := BaseDocument(c)
	doc := func(folders ...string) uiapi.PolicyDocument {
		d := uiapi.PolicyDocument{Roles: map[string]uiapi.Role{"r": {Rules: []uiapi.Rule{{Folders: folders, Actions: []string{ActionRecordWrite}}}}}}
		Normalize(&d)
		return d
	}
	if errs := ValidateManaged(c, base, doc("/ES/Madrid", "/FR")); len(errs) > 0 {
		t.Fatalf("folders within bounds: %+v", errs)
	}
	for f, want := range map[string]string{
		"/ES": "outside policy.bounds.folders", "/FR/**": "outside policy.bounds.folders", "ES": "must start with /",
	} {
		errs := ValidateManaged(c, base, doc(f))
		if len(errs) != 1 || errs[0].Path != "roles.r.rules[0].folders[0]" || !strings.Contains(errs[0].Message, want) {
			t.Errorf("%s: %+v", f, errs)
		}
	}
	empty := uiapi.PolicyDocument{Roles: map[string]uiapi.Role{"r": {Rules: []uiapi.Rule{{Actions: []string{ActionRecordWrite}}}}}}
	Normalize(&empty)
	if errs := ValidateManaged(c, base, empty); len(errs) == 0 || !strings.Contains(paths(errs), "zone or folder") {
		t.Fatalf("rule without zones nor folders: %+v", errs)
	}
	// A managed binding of a base role with folders outside the bounds.
	b := uiapi.PolicyDocument{Bindings: []uiapi.Binding{{Role: "root-reader", Team: "x", Groups: []string{"policy-admins"}}}}
	c.Policy.Bounds.Actions = append(c.Policy.Bounds.Actions, ActionDNSRead)
	if errs := ValidateManaged(c, base, b); len(errs) == 0 || !strings.Contains(paths(errs), `covers folder "/"`) {
		t.Fatalf("base role with folders outside the bounds: %+v", errs)
	}
	// Runtime re-check of an unchecked document.
	bad := doc("/IT")
	h, _ := folderHolder(t)
	snap := h.CompileUnchecked(&bad, "old")
	if snap.Decide([]string{"r"}, ActionRecordWrite, "example.es", nil).Allowed {
		t.Fatal("managed folder rule outside the bounds must grant nothing")
	}
}

func TestFolderDelegation(t *testing.T) {
	c := delegationConfig()
	c.Policy.Bounds.Folders = []string{"/ES/**"}
	c.Policy.Delegations[0].Allow.Folders = []string{"/ES/Madrid", "/ES/Madrid/**"}
	base := BaseDocument(c)
	b := uiapi.Binding{Role: "r", Team: "team-a", Subjects: []uiapi.SubjectMatcher{{Issuer: "idp", Claims: map[string][]string{"sub": {"p-a"}}}}}
	ok := delegatedDoc(uiapi.Rule{Folders: []string{"/ES/Madrid/**"}, Actions: []string{ActionRecordWrite}}, b, "ci")
	if errs := ValidateManaged(c, base, ok); len(errs) > 0 {
		t.Fatalf("delegated folder rule within allow.folders: %+v", errs)
	}
	out := delegatedDoc(uiapi.Rule{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}, b, "ci")
	errs := ValidateManaged(c, base, out)
	if !strings.Contains(paths(errs), "delegated.roles.r.rules[0].folders[0]: folder \"/ES/**\" is outside the allow.folders") {
		t.Fatalf("delegated folder rule outside allow.folders: %+v", errs)
	}
	snap := compile(c, base, &out, "r", &folderDiscovery{folders: map[string]string{"example.com": "/ES/Valencia"}})
	if snap.Decide([]string{"r"}, ActionRecordWrite, "example.com", nil).Allowed {
		t.Fatal("delegated rule beyond its delegation must grant nothing")
	}
	snap = compile(c, base, &ok, "r", &folderDiscovery{folders: map[string]string{"example.com": "/ES/Madrid/Centro"}})
	if !snap.Decide([]string{"r"}, ActionRecordWrite, "example.com", nil).Allowed {
		t.Fatal("delegated folder rule not effective")
	}
	if v := DelegationViews(c); strings.Join(v[0].Allow.Folders, ",") != "/ES/Madrid,/ES/Madrid/**" {
		t.Fatalf("delegation view: %+v", v[0].Allow)
	}
}

func TestFolderKeyRoleProblem(t *testing.T) {
	c := &config.Config{
		Zones: []string{"example.com"},
		Roles: map[string]config.Role{
			"keys-es":     {Rules: []config.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionAPIKeyManage, ActionDNSRead, ActionRecordWrite}}}},
			"keys-all":    {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionAPIKeyManage, ActionDNSRead, ActionRecordWrite}}}},
			"keys-com":    {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionAPIKeyManage, ActionDNSRead, ActionRecordWrite}}}},
			"madrid":      {Rules: []config.Rule{{Folders: []string{"/ES/Madrid"}, Actions: []string{ActionRecordWrite}}}},
			"es-exact":    {Rules: []config.Rule{{Folders: []string{"/ES"}, Actions: []string{ActionRecordWrite}}}},
			"madrid-read": {Rules: []config.Rule{{Folders: []string{"/ES/Madrid"}, Actions: []string{ActionRecordAdopt}}}},
		},
	}
	s := FromConfig(c).Holder().Current()
	for _, tc := range []struct {
		holder, role, want string
	}{
		{"keys-es", "madrid", ""},
		{"keys-all", "madrid", ""},
		{"keys-es", "es-exact", `not granted on folders "/ES"`},
		{"keys-com", "madrid", `not granted on folders "/ES/Madrid"`},
		{"keys-es", "madrid-read", "beyond the caller's own rights"},
	} {
		got := s.KeyRoleProblem([]string{tc.holder}, tc.role)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s gives %s: %q, want %q", tc.holder, tc.role, got, tc.want)
		}
	}
	if got := strings.Join(s.RoleFolders("keys-es"), ","); got != "/ES/**" || !s.GrantsFolderPattern([]string{"keys-es"}, ActionRecordWrite, "/ES/Madrid") {
		t.Fatalf("role folders %q", got)
	}
	issued, _ := s.RoleGrant("madrid")
	if len(issued.Rules) != 1 || strings.Join(issued.Rules[0].Folders, ",") != "/ES/Madrid" {
		t.Fatalf("role grant = %+v", issued)
	}
	widened := RoleGrant{Rules: []uiapi.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}}}
	if widened.Within(issued) || !issued.Within(widened) {
		t.Fatal("RoleGrant.Within must compare folders")
	}
}

func TestFolderRulesStayWithinBoundsZones(t *testing.T) {
	c := folderConfig()
	c.Policy.Bounds.Zones = []string{"example.com"}
	c.Policy.Bounds.Folders = []string{"/ES/**"}
	h := mustHolder(t, c)
	d := &folderDiscovery{folders: map[string]string{"example.com": "/ES/a", "secret.net": "/ES/x"}}
	h.SetDiscovery(d)
	doc := uiapi.PolicyDocument{
		Roles:    map[string]uiapi.Role{"es-managed": {Rules: []uiapi.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}}}},
		Bindings: []uiapi.Binding{{Role: "es-managed", Team: "es", Groups: []string{"policy-admins"}}},
	}
	Normalize(&doc)
	snap, errs := h.Compile(&doc, "r1")
	if len(errs) > 0 {
		t.Fatalf("document: %+v", errs)
	}
	if snap.Decide([]string{"es-managed"}, ActionRecordWrite, "secret.net", nil).Allowed {
		t.Fatal("a managed folder rule reached a zone outside policy.bounds.zones")
	}
	if !snap.Decide([]string{"es-managed"}, ActionRecordWrite, "example.com", nil).Allowed {
		t.Fatal("a managed folder rule must apply to a zone within policy.bounds.zones")
	}
	for _, it := range Impact(h.Current(), snap, nil) {
		if it.Role == "es-managed" && strings.Contains(strings.Join(it.Zones, ","), "secret.net") {
			t.Fatalf("impact grants a zone outside the bounds: %+v", it)
		}
	}

	dc := delegationConfig()
	dc.Policy.Bounds.Folders = []string{"/ES/**"}
	dc.Policy.Delegations[0].Allow.Folders = []string{"/ES/**"}
	base := BaseDocument(dc)
	b := uiapi.Binding{Role: "r", Team: "team-a", Subjects: []uiapi.SubjectMatcher{{Issuer: "idp", Claims: map[string][]string{"sub": {"p-a"}}}}}
	dd := delegatedDoc(uiapi.Rule{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}, b, "ci")
	ds := compile(dc, base, &dd, "r", &folderDiscovery{folders: map[string]string{"example.com": "/ES/a", "example.org": "/ES/b"}})
	if ds.Decide([]string{"r"}, ActionRecordWrite, "example.org", nil).Allowed {
		t.Fatal("a delegated folder rule reached a zone outside allow.zones")
	}
	if !ds.Decide([]string{"r"}, ActionRecordWrite, "example.com", nil).Allowed {
		t.Fatal("a delegated folder rule must apply within allow.zones")
	}
}

func TestFolderKeyIssuanceRespectsBoundsZones(t *testing.T) {
	c := folderConfig()
	c.Zones = append(c.Zones, "secret.net")
	c.Policy.Bounds.Zones = []string{"example.com"}
	c.Policy.Bounds.Folders = []string{"/ES/**"}
	c.Policy.Bounds.Actions = []string{ActionRecordWrite, ActionAPIKeyManage}
	c.Roles["es-key"] = config.Role{Rules: []config.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}}}
	h := mustHolder(t, c)
	h.SetDiscovery(&folderDiscovery{folders: map[string]string{"example.com": "/ES/a", "secret.net": "/ES/x"}})
	doc := uiapi.PolicyDocument{Roles: map[string]uiapi.Role{"issuer": {Rules: []uiapi.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionAPIKeyManage, ActionRecordWrite}}}}}}
	Normalize(&doc)
	snap, errs := h.Compile(&doc, "r1")
	if len(errs) > 0 {
		t.Fatalf("document: %+v", errs)
	}
	if snap.Decide([]string{"issuer"}, ActionRecordWrite, "secret.net", nil).Allowed || !snap.Decide([]string{"es-key"}, ActionRecordWrite, "secret.net", nil).Allowed {
		t.Fatal("scenario: the issuer cannot write secret.net, the base key role can")
	}
	if p := snap.KeyRoleProblem([]string{"issuer"}, "es-key"); p == "" {
		t.Fatal("an issuer narrowed by policy.bounds.zones gave a key a wider folder role")
	}
	if snap.GrantsFolderPattern([]string{"issuer"}, ActionAPIKeyManage, "/ES/**") {
		t.Fatal("GrantsFolderPattern ignores the bounds narrowing")
	}

	c.Policy.Bounds.Zones = []string{"*"}
	snap, _ = mustHolder(t, c).Compile(&doc, "r2")
	if p := snap.KeyRoleProblem([]string{"issuer"}, "es-key"); p != "" {
		t.Fatalf("bounds on every zone: %s", p)
	}

	dc := delegationConfig()
	dc.Policy.Bounds.Zones = []string{"*"}
	dc.Policy.Bounds.Folders = []string{"/ES/**"}
	dc.Policy.Bounds.Actions = append(dc.Policy.Bounds.Actions, ActionAPIKeyManage)
	dc.Policy.Delegations[0].Allow.Zones = []string{"example.com"}
	dc.Policy.Delegations[0].Allow.Folders = []string{"/ES/**"}
	dc.Policy.Delegations[0].Allow.Actions = []string{ActionRecordWrite, ActionAPIKeyManage}
	dc.Roles["es-key"] = config.Role{Rules: []config.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}}}
	b := uiapi.Binding{Role: "r", Team: "team-a", Subjects: []uiapi.SubjectMatcher{{Issuer: "idp", Claims: map[string][]string{"sub": {"p-a"}}}}}
	dd := delegatedDoc(uiapi.Rule{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite, ActionAPIKeyManage}}, b, "ci")
	ds := compile(dc, BaseDocument(dc), &dd, "r", &folderDiscovery{folders: map[string]string{"example.org": "/ES/b"}})
	if p := ds.KeyRoleProblem([]string{"r"}, "es-key"); p == "" {
		t.Fatal("a delegated issuer narrowed by allow.zones gave a key a wider folder role")
	}
}

func TestFolderPermissionsShowTheBoundsNarrowing(t *testing.T) {
	c := folderConfig()
	c.Policy.Bounds.Zones = []string{"example.com"}
	h := mustHolder(t, c)
	doc := uiapi.PolicyDocument{Roles: map[string]uiapi.Role{"m": {Rules: []uiapi.Rule{{Folders: []string{"/ES/**"}, Actions: []string{ActionRecordWrite}}}}}}
	Normalize(&doc)
	snap, errs := h.Compile(&doc, "r1")
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	perms := snap.Permissions([]string{"m", "es-writer"})
	if len(perms) != 2 || perms[0].Role != "es-writer" || len(perms[0].FolderZones) != 0 ||
		perms[1].Role != "m" || strings.Join(perms[1].FolderZones, ",") != "example.com" {
		t.Fatalf("permissions: %+v", perms)
	}
	c.Policy.Bounds.Zones = []string{"*"}
	snap, _ = mustHolder(t, c).Compile(&doc, "r2")
	if p := snap.Permissions([]string{"m"}); len(p) != 1 || len(p[0].FolderZones) != 0 {
		t.Fatalf("no narrowing with bounds on every zone: %+v", p)
	}
}
