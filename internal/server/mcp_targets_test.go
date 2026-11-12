package server

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/propagation"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// targetsEngine serves a zone whose RRsets point to other names.
type targetsEngine struct{ *fakeEngine }

func (t targetsEngine) Inventory(ctx context.Context, s *identity.Subject, zone string) (*uiapi.ZoneInventory, error) {
	return &uiapi.ZoneInventory{Zone: zone, RRsets: []uiapi.RRset{
		{Host: "app", Type: "CNAME", TTL: 600, Values: []string{"d111.cloudfront.net."}, Status: uiapi.StatusForeign},
		{Host: "old", Type: "CNAME", TTL: 600, Values: []string{"dgone.cloudfront.net."}, Status: uiapi.StatusForeign},
		{Host: "legacy", Type: "CNAME", TTL: 600, Values: []string{"lb.nbs-aws.com."}, Status: uiapi.StatusForeign},
		{Host: "rel", Type: "CNAME", TTL: 600, Values: []string{"app"}, Status: uiapi.StatusForeign},
		{Host: "@", Type: "MX", TTL: 600, Values: []string{"0 example-com.mail.protection.outlook.com."}, Status: uiapi.StatusForeign},
		{Host: "www", Type: "A", TTL: 600, Values: []string{"192.0.2.1"}, Status: uiapi.StatusManaged, Owner: "web"},
	}}, nil
}

// fakeTargets is a propagator that also resolves targets.
type fakeTargets struct {
	fakePropagator
	mu    sync.Mutex
	calls [][]string
	subj  []string
	err   error
}

func (f *fakeTargets) ResolveTargets(_ context.Context, subject string, names []string) (map[string]propagation.Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.calls, f.subj = append(f.calls, slices.Clone(names)), append(f.subj, subject)
	out := map[string]propagation.Target{}
	for _, n := range names {
		switch n {
		case "dgone.cloudfront.net.":
			out[n] = propagation.Target{Name: n, Status: propagation.TargetNXDomain, TakeoverRisk: propagation.TakeoverService(n), Resolver: "r0"}
		default:
			out[n] = propagation.Target{Name: n, Status: propagation.TargetLive, Addresses: []string{"192.0.2.10"}, Resolver: "r0"}
		}
	}
	return out, nil
}

func targetsEnv(t *testing.T) (*env, *fakeTargets) {
	t.Helper()
	e := newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.TargetOwners = []config.TargetOwner{
			{Match: "d111.cloudfront.net", Owner: "NH prod"},
			{Match: "*.nbs-aws.com", Owner: "NBS legacy"},
			{Match: "cloudfront.net", Owner: "AWS CloudFront"},
			{Match: "mail.protection.outlook.com", Owner: "Microsoft 365"},
		}
		c.Roles["reader"] = config.Role{Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{policy.ActionDNSRead, policy.ActionUIRead}}}}
		c.Bindings = append(c.Bindings, config.Binding{Role: "reader", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"reader"}}}}})
	})
	e.server.cfg.Engine = targetsEngine{e.engine}
	f := &fakeTargets{}
	e.server.cfg.Propagation = f
	return e, f
}

func byHost(sets []uiapi.RRset) map[string]uiapi.RRset {
	out := map[string]uiapi.RRset{}
	for _, rs := range sets {
		out[rs.Host+"/"+rs.Type] = rs
	}
	return out
}

func TestRRsetTargets(t *testing.T) {
	for _, c := range []struct {
		rs   uiapi.RRset
		want []string
	}{
		{uiapi.RRset{Type: "CNAME", Values: []string{"Target.Example.NET."}}, []string{"target.example.net."}},
		{uiapi.RRset{Type: "CNAME", Values: []string{"app"}}, []string{"app.example.com."}},
		{uiapi.RRset{Type: "APEX", Values: []string{"lb.example.net."}}, []string{"lb.example.net."}},
		{uiapi.RRset{Type: "A", Alias: &dns.Alias{Target: "d1.cloudfront.net"}}, []string{"d1.cloudfront.net."}},
		{uiapi.RRset{Type: "MX", Values: []string{"10 mx1.example.net.", "20 mx2.example.net."}}, []string{"mx1.example.net.", "mx2.example.net."}},
		{uiapi.RRset{Type: "SRV", Values: []string{"10 5 5060 sip.example.net."}}, []string{"sip.example.net."}},
		{uiapi.RRset{Type: "NS", Values: []string{"ns1.example.net."}}, []string{"ns1.example.net."}},
		{uiapi.RRset{Type: "SRV", Values: []string{"0 0 0 ."}}, nil},
		{uiapi.RRset{Type: "A", Values: []string{"192.0.2.1"}}, nil},
		{uiapi.RRset{Type: "TXT", Values: []string{"v=spf1 include:example.net"}}, nil},
	} {
		if got := rrsetTargets("example.com", &c.rs); !slices.Equal(got, c.want) {
			t.Errorf("%s %v: got %v, want %v", c.rs.Type, c.rs.Values, got, c.want)
		}
	}
}

func TestMCPTargets(t *testing.T) {
	e, f := targetsEnv(t)
	cs := connect(t, e, e.token("reader"))
	tools := toolNames(t, cs)
	if !strings.Contains(tools["list_rrsets"].Description, "takeover_risk") || !strings.Contains(tools["get_rrset"].Description, "resolve=true") {
		t.Fatal("resolve not described")
	}

	// target_owner without resolve: no resolution
	var rs listRRsetsOut
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com"}, &rs); res.IsError {
		t.Fatal(errText(res))
	}
	got := byHost(rs.RRsets)
	for k, want := range map[string]string{"app/CNAME": "NH prod", "old/CNAME": "AWS CloudFront", "legacy/CNAME": "NBS legacy", "@/MX": "Microsoft 365", "www/A": "", "rel/CNAME": ""} {
		if got[k].TargetOwner != want || got[k].Targets != nil {
			t.Errorf("%s: owner %q targets %v, want %q and no targets", k, got[k].TargetOwner, got[k].Targets, want)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("targets resolved without resolve")
	}

	// resolve: one call for the whole listing
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "resolve": true}, &rs); res.IsError {
		t.Fatal(errText(res))
	}
	got = byHost(rs.RRsets)
	if len(f.calls) != 1 || len(f.calls[0]) != 5 || !strings.Contains(f.subj[0], "reader") {
		t.Fatalf("resolver calls: %v %v", f.calls, f.subj)
	}
	old := got["old/CNAME"].Targets
	if len(old) != 1 || old[0].Status != propagation.TargetNXDomain || old[0].TakeoverRisk != "AWS CloudFront" {
		t.Fatalf("dangling: %+v", old)
	}
	if rel := got["rel/CNAME"].Targets; len(rel) != 1 || rel[0].Name != "app.example.com." || rel[0].Status != propagation.TargetLive {
		t.Fatalf("relative target: %+v", rel)
	}
	if got["www/A"].Targets != nil {
		t.Fatal("an A record was resolved")
	}

	// filters reduce what is resolved
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "host": "app", "resolve": true}, &rs); res.IsError || len(f.calls[1]) != 1 {
		t.Fatalf("filtered: %s %v", errText(res), f.calls)
	}

	// compact records carry the label and the resolution
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "type": "CNAME", "compact": true, "resolve": true}, &rs); res.IsError {
		t.Fatal(errText(res))
	}
	if len(rs.RRsets) != 0 || len(rs.Records) != 4 {
		t.Fatalf("compact: %d rrsets, %d records", len(rs.RRsets), len(rs.Records))
	}
	recs := map[string]Record{}
	for _, r := range rs.Records {
		recs[r.Host] = r
	}
	if recs["app"].TargetOwner != "NH prod" || len(recs["old"].Targets) != 1 || recs["old"].Targets[0].TakeoverRisk != "AWS CloudFront" {
		t.Fatalf("compact records: %+v", rs.Records)
	}
	// the page is cut before resolving: only its targets are asked
	before := len(f.calls)
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "limit": 2, "resolve": true}, &rs); res.IsError || rs.NextCursor == "" {
		t.Fatalf("page: %s %+v", errText(res), rs)
	}
	if len(f.calls) != before+1 || len(f.calls[before]) != 2 {
		t.Fatalf("page resolution: %v", f.calls[before:])
	}

	// get_rrset
	var one getRRsetOut
	if res := call(t, cs, "get_rrset", map[string]any{"zone": "example.com", "host": "old", "type": "CNAME", "resolve": true}, &one); res.IsError {
		t.Fatal(errText(res))
	}
	if one.RRset == nil || one.RRset.TargetOwner != "AWS CloudFront" || len(one.RRset.Targets) != 1 || one.RRset.Targets[0].TakeoverRisk == "" {
		t.Fatalf("get_rrset: %+v", one.RRset)
	}

	// rate limited
	f.err = propagation.ErrRateLimited
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "resolve": true}, nil); !res.IsError || !strings.Contains(errText(res), "rate_limited") {
		t.Fatalf("rate limit: %v %s", res.IsError, errText(res))
	}
	// without resolve, the listing still works
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com"}, nil); res.IsError {
		t.Fatal(errText(res))
	}

	// propagation disabled
	e.server.cfg.Propagation = nil
	if res := call(t, cs, "get_rrset", map[string]any{"zone": "example.com", "host": "app", "type": "CNAME", "resolve": true}, nil); !res.IsError || !strings.Contains(errText(res), "not available") {
		t.Fatalf("disabled: %v %s", res.IsError, errText(res))
	}
}

func TestAPIInventoryTargets(t *testing.T) {
	e, f := targetsEnv(t)
	tok := e.token("reader")
	r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets?resolve=true", tok, "", nil)
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	var inv uiapi.ZoneInventory
	if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
		t.Fatal(err)
	}
	got := byHost(inv.RRsets)
	if got["app/CNAME"].TargetOwner != "NH prod" || len(got["old/CNAME"].Targets) != 1 || got["old/CNAME"].Targets[0].TakeoverRisk != "AWS CloudFront" {
		t.Fatalf("inventory: %+v", inv.RRsets)
	}
	f.err = propagation.ErrBusy
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets?resolve=true", tok, "", nil); r.StatusCode != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("busy: %d", r.StatusCode)
	}
	e.server.cfg.Propagation = nil
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets?resolve=true", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("disabled: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets", tok, "", nil); r.StatusCode != 200 {
		t.Fatalf("without resolve: %d", r.StatusCode)
	}
}
