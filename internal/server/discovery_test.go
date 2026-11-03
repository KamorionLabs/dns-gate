package server

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/discovery"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
)

// fakeDiscovery is a ZoneDiscovery; zones in later appear on the next refresh.
type fakeDiscovery struct {
	mu        sync.Mutex
	zones     map[string]bool
	later     []string
	refreshes int
}

func (f *fakeDiscovery) Discovered(z string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.zones[z]
}
func (f *fakeDiscovery) DiscoveredZones() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for z := range f.zones {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}
func (f *fakeDiscovery) Loaded() bool { return true }
func (f *fakeDiscovery) Status() discovery.Status {
	return discovery.Status{Loaded: true, Count: len(f.DiscoveredZones()), LastRefreshAt: time.Unix(1_700_000_000, 0)}
}
func (f *fakeDiscovery) RefreshIfOlder(context.Context, time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	for _, z := range f.later {
		f.zones[z] = true
	}
	f.later = nil
	return nil
}

func discoveryEnv(t *testing.T) (*env, *fakeDiscovery) {
	disc := &fakeDiscovery{zones: map[string]bool{"example.com": true, "new.example.net": true, "other.net": true}}
	t.Helper()
	tr := true
	e := newEnvDisc(t, func(c *config.Config) {
		c.Issuers[0].CategoryClaim = "kind"
		c.Issuers[0].CategoryMap = map[string]string{"user": "human"}
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.ZonesDiscovery = config.ZonesDiscovery{Enabled: true, Include: []string{"*"}, Refresh: config.Duration(time.Hour)}
		c.Roles["reader"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{policy.ActionDNSRead, policy.ActionUIRead}}}}
		c.Roles["padmin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose", "policy.approve", policy.ActionUIRead}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "reader", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"reader"}}}}},
			config.Binding{Role: "padmin", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"alice", "bob"}}}}},
		)
		c.Policy = config.Policy{
			Editable: true, RequireApproval: &tr, EditMaxAge: config.Duration(15 * time.Minute),
			Bounds: config.Bounds{Zones: []string{"example.com", "*.example.net"}, Actions: []string{policy.ActionDNSRead, policy.ActionRecordWrite, policy.ActionUIRead}},
		}
	}, disc)
	e.engine.extra = []uiapi.ZoneSummary{{Zone: "new.example.net", Unmanaged: true}, {Zone: "other.net", Unmanaged: true}}
	return e, disc
}

func TestDiscoveredZonesReadOnly(t *testing.T) {
	e, _ := discoveryEnv(t)
	reader := e.token("reader")

	r := e.do(t, "GET", "/api/v1/zones", reader, "", nil)
	var zs []uiapi.ZoneSummary
	_ = json.NewDecoder(r.Body).Decode(&zs)
	var names []string
	for _, z := range zs {
		if z.Unmanaged {
			names = append(names, z.Zone)
		}
	}
	if r.StatusCode != 200 || strings.Join(names, ",") != "new.example.net,other.net" {
		t.Fatalf("zones: %d %+v", r.StatusCode, zs)
	}
	// The writer role (example.com only) does not see them.
	r = e.do(t, "GET", "/api/v1/zones", e.token("writer"), "", nil)
	zs = nil
	_ = json.NewDecoder(r.Body).Decode(&zs)
	for _, z := range zs {
		if z.Unmanaged {
			t.Fatalf("writer sees %s", z.Zone)
		}
	}
	// RRsets are readable through the UI API...
	if r := e.do(t, "GET", "/api/v1/zones/other.net/rrsets", reader, "", nil); r.StatusCode != 200 {
		t.Fatalf("rrsets: %d", r.StatusCode)
	}
	// ...but the EuroDNS API, adoption and export stay limited to managed zones.
	if r := e.do(t, "GET", "/dns-zones/other.net", reader, "", nil); r.StatusCode != 403 || reason(t, r) != "zone_not_managed" {
		t.Fatalf("EuroDNS API on an unmanaged zone: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/zones/other.net/terraform", reader, "", nil); r.StatusCode != 404 {
		t.Fatalf("terraform export: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/.well-known/eurodns-gate/zones/other.net/adopt", e.token("admin"), `{"rrsets":[{"host":"www","type":"A"}]}`, nil); r.StatusCode != 403 {
		t.Fatalf("adopt extension: %d", r.StatusCode)
	}
}

func TestMCPListsUnmanagedZones(t *testing.T) {
	e, _ := discoveryEnv(t)
	cs := connect(t, e, e.token("reader"))
	var zs listZonesOut
	call(t, cs, "list_zones", map[string]any{}, &zs)
	var unmanaged []string
	for _, z := range zs.Zones {
		if z.Unmanaged {
			unmanaged = append(unmanaged, z.Zone)
		}
	}
	if strings.Join(unmanaged, ",") != "new.example.net,other.net" {
		t.Fatalf("list_zones: %+v", zs.Zones)
	}
	var rr listRRsetsOut
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "other.net"}, &rr); res.IsError || rr.Zone != "other.net" {
		t.Fatalf("list_rrsets: %s", errText(res))
	}
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "absent.net"}, nil); !res.IsError {
		t.Fatal("undiscovered zone readable over MCP")
	}
}

func TestManageZoneThroughPolicy(t *testing.T) {
	e, disc := discoveryEnv(t)
	alice := e.human("alice", time.Minute)
	bob := e.human("bob", time.Minute)

	// Not in the account (even after the on-demand refresh), outside the bounds.
	for zone, want := range map[string]string{"absent.example.net": "not found in the EuroDNS account", "other.net": "outside policy.bounds.zones"} {
		if status, msg := proposeErr(t, e, alice, uiapi.PolicyDocument{Zones: []string{zone}}); status != 400 || !strings.Contains(msg, want) {
			t.Fatalf("%s: %d %s", zone, status, msg)
		}
	}
	if disc.refreshes != 1 {
		t.Fatalf("on-demand refreshes = %d, want 1", disc.refreshes)
	}
	// A zone added to the account just before is found by the on-demand refresh.
	disc.later = []string{"fresh.example.net"}
	if r, _ := propose(t, e, alice, "", uiapi.PolicyDocument{Zones: []string{"fresh.example.net"}}); r.StatusCode != 201 {
		t.Fatalf("fresh zone: %d", r.StatusCode)
	}

	r, d := propose(t, e, alice, "", uiapi.PolicyDocument{Zones: []string{"new.example.net"}})
	if r.StatusCode != 201 {
		t.Fatalf("propose: %d", r.StatusCode)
	}
	found := false
	for _, it := range d.Impact {
		found = found || (it.Kind == "gain" && it.Who == "zone new.example.net")
	}
	if !found {
		t.Fatalf("impact: %+v", d.Impact)
	}
	if r := e.do(t, "GET", "/dns-zones/new.example.net", e.token("admin"), "", nil); r.StatusCode != 403 {
		t.Fatalf("before activation: %d", r.StatusCode)
	}
	base := "/api/v1/policy/revisions/" + d.ID
	if code, _ := post(t, e, bob, base+"/approve"); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if code, _ := post(t, e, bob, base+"/activate"); code != 200 {
		t.Fatalf("activate: %d", code)
	}
	// Managed now: the EuroDNS API route accepts it (RBAC still applies).
	if r := e.do(t, "GET", "/dns-zones/new.example.net", e.token("reader"), "", nil); r.StatusCode != 200 {
		t.Fatalf("after activation: %d", r.StatusCode)
	}
	if !e.holder.Current().IsManaged("new.example.net") || e.holder.Current().IsUnmanaged("new.example.net") {
		t.Fatal("zone not managed after activation")
	}

	rr := e.do(t, "GET", "/api/v1/policy", alice, "", nil)
	var eff uiapi.EffectivePolicy
	_ = json.NewDecoder(rr.Body).Decode(&eff)
	if eff.Base.Discovery == nil || !eff.Base.Discovery.Loaded || eff.Base.Discovery.Count != 4 || eff.Managed == nil || len(eff.Managed.Zones) != 1 {
		t.Fatalf("effective policy: %+v %+v", eff.Base.Discovery, eff.Managed)
	}
}

func TestManagedZonesNeedDiscovery(t *testing.T) {
	e := policyEnv(t, true)
	e.holder.Config().Policy.Bounds.Zones = []string{"example.com", "*.example.com"}
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	if r, _ := propose(t, e, alice, "", uiapi.PolicyDocument{Zones: []string{"example.com"}}); r.StatusCode != 201 {
		t.Fatalf("base zone repeated: %d", r.StatusCode)
	}
	if status, msg := proposeErr(t, e, alice, uiapi.PolicyDocument{Zones: []string{"sub.example.com"}}); status != 400 || !strings.Contains(msg, "requires zones_discovery.enabled") {
		t.Fatalf("without discovery: %d %s", status, msg)
	}
}

// proposeErr proposes on the empty active revision and returns the status
// and the validation messages.
func proposeErr(t *testing.T, e *env, tok string, doc uiapi.PolicyDocument) (int, string) {
	t.Helper()
	b, _ := json.Marshal(uiapi.ProposeRequest{Document: doc})
	r := e.do(t, "POST", "/api/v1/policy/revisions", tok, string(b), nil)
	var eb errorBody
	_ = json.NewDecoder(r.Body).Decode(&eb)
	var msgs []string
	for _, ve := range eb.Errors {
		msgs = append(msgs, ve.Path+": "+ve.Message)
	}
	return r.StatusCode, strings.Join(msgs, "; ")
}
