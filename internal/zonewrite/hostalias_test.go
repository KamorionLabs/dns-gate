package zonewrite

import (
	"context"
	"slices"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// A host that still names the zone once made relative ("example.com" or
// "www.example.com" in example.com) would be authorized as that key and
// written by the provider as the apex or as www: it is refused before any
// check, on the plan, on the apply and on a zone-level write.
func TestHostAliasRefused(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	before, err := e.prov.ReadZone(ctx, zoneName)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []uiapi.RRsetChange{
		{Host: "example.com.example.com", Type: "MX", Values: []string{"10 evil.example.net."}},
		{Host: "example.com.example.com.", Type: "MX", Values: []string{"10 evil.example.net."}},
		{Host: "EXAMPLE.com.example.com", Type: "NS", Values: []string{"ns.evil.example.net."}},
		{Host: "www.example.com.example.com", Type: "A", Values: []string{"203.0.113.9"}},
		{Host: "www.example.com.example.com", Type: "A", Delete: true},
		{Host: `\119ww`, Type: "A", Values: []string{"203.0.113.9"}},
		{Host: "a..b", Type: "A", Values: []string{"203.0.113.9"}},
		{Host: "a b", Type: "A", Values: []string{"203.0.113.9"}},
	} {
		p, err := e.eng.PlanRRsets(ctx, bob, zoneName, []uiapi.RRsetChange{c})
		if err != nil || p.Allowed || p.Reason != string(ReasonInvalid) {
			t.Errorf("plan %q %s: %+v %v, want %s", c.Host, c.Type, p, err, ReasonInvalid)
		}
		if _, err := e.eng.ApplyRRsets(ctx, admin, zoneName, []uiapi.RRsetChange{c}, 0); reasonOf(err) != ReasonInvalid {
			t.Errorf("apply %q %s: %v, want %s", c.Host, c.Type, err, ReasonInvalid)
		}
	}

	// The zone-level path (EuroDNS contract) builds its keys itself.
	e.wantReason(e.add(bob, zoneName, rec("A", "www.example.com.example.com", "203.0.113.9")), ReasonInvalid)
	e.wantReason(e.add(admin, zoneName, rec("MX", "example.com.example.com", "10 evil.example.net.")), ReasonInvalid)

	after, err := e.prov.ReadZone(ctx, zoneName)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []dns.Key{{Host: dns.Apex, Type: "MX"}, {Host: dns.Apex, Type: "NS"}, {Host: "www", Type: "A"}} {
		b, _ := before.Set(k)
		a, _ := after.Set(k)
		if !slices.Equal(a.Values, b.Values) {
			t.Errorf("%s changed: %v, was %v", keyString(k), a.Values, b.Values)
		}
	}
	if len(after.RRsets) != len(before.RRsets) {
		t.Errorf("the zone has %d RRsets, had %d", len(after.RRsets), len(before.RRsets))
	}
	if e.own("example.com", "MX") != nil || e.own("www.example.com", "A") != nil {
		t.Error("an aliased host was claimed")
	}

	// The fully qualified and the relative forms stay accepted.
	for _, h := range []string{"app", "app2.example.com.", "_dmarc", "*.wild", "com"} {
		p, err := e.eng.PlanRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: h, Type: "TXT", Values: []string{"v"}}})
		if err != nil || !p.Allowed {
			t.Errorf("plan %q: %+v %v, want allowed", h, p, err)
		}
	}
}
