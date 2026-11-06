package zonewrite

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

var (
	fwdA = bound(&identity.Subject{Issuer: "idp", ID: "fa", Name: "fa@example.com", Category: identity.CategoryHuman, Roles: []string{"forwarder"}, Teams: []string{"team-a"}})
	fwdB = bound(&identity.Subject{Issuer: "idp", ID: "fb", Name: "fb@example.com", Category: identity.CategoryHuman, Roles: []string{"forwarder"}, Teams: []string{"team-b"}})
)

func fwd(host, mode, url string) uiapi.RRsetChange {
	return uiapi.RRsetChange{Host: host, Type: dns.TypeURLForward, Forward: &dns.Forward{Mode: mode, URL: url}}
}

func (e *env) forwards() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, raw := range e.srv.Zone(zoneName).URLForwards {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			e.t.Fatal(err)
		}
		out[m["host"].(string)] = m
	}
	return out
}

func TestForwardOwnership(t *testing.T) {
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) { c.TombstoneTTL = time.Hour })
	ctx := context.Background()
	goRaw := string(e.srv.Zone(zoneName).URLForwards[0])

	_, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{fwd("www", "301", "https://example.net/")}, 0)
	e.wantReason(err, ReasonForbidden)

	if _, err := e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("WWW.example.com.", "301", " https://example.net/ ")}, 0); err != nil {
		t.Fatal(err)
	}
	if o := e.own("www", dns.TypeURLForward); o == nil || o.Owner != "team-a" || o.State != store.StateActive {
		t.Fatalf("ownership %+v", o)
	}
	f := e.forwards()
	if f["www"]["forwardType"] != "HTTP301" || f["www"]["url"] != "https://example.net/" {
		t.Fatalf("forwards %v", f)
	}
	if got := string(e.srv.Zone(zoneName).URLForwards[0]); got != goRaw {
		t.Fatalf("untouched forward rewritten: %s", got)
	}
	ev := e.audit.find("applyRRsets", "allow")
	if len(ev) != 1 || ev[0].Changes[0].NewForward == nil || ev[0].Changes[0].NewForward.URL != "https://example.net/" {
		t.Fatalf("audit %+v", ev)
	}

	_, err = e.eng.ApplyRRsets(ctx, fwdB, zoneName, []uiapi.RRsetChange{fwd("www", "302", "https://example.org/")}, 0)
	e.wantReason(err, ReasonNotOwner)
	_, err = e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("go", "302", "https://example.org/")}, 0)
	e.wantReason(err, ReasonForeignRRset)
	_, err = e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{{Host: "x", Type: "A", Forward: &dns.Forward{Mode: "301", URL: "https://example.org/"}}}, 0)
	e.wantReason(err, ReasonInvalid)
	_, err = e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("x", "307", "https://example.org/")}, 0)
	e.wantReason(err, ReasonInvalid)
	_, err = e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("x", "301", "ftp://example.org/")}, 0)
	e.wantReason(err, ReasonInvalid)

	inv, err := e.eng.RRset(ctx, fwdA, zoneName, dns.ForwardKey("www"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{{Host: "www", Type: dns.TypeURLForward, ExpectedHash: "stale",
		Forward: &dns.Forward{Mode: "302", URL: "https://example.org/"}}}, 0)
	e.wantReason(err, ReasonPrecondition)
	if _, err := e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{{Host: "www", Type: dns.TypeURLForward, ExpectedHash: inv.Hash,
		Forward: &dns.Forward{Mode: "frame", URL: "https://example.org/", Title: "Example"}}}, 0); err != nil {
		t.Fatal(err)
	}
	if f := e.forwards()["www"]; f["forwardType"] != "FRAME" || f["title"] != "Example" {
		t.Fatalf("frame %v", f)
	}

	if _, err := e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{{Host: "www", Type: dns.TypeURLForward, Delete: true}}, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.forwards()["www"]; ok || e.own("www", dns.TypeURLForward) != nil {
		t.Fatal("forward not deleted")
	}
	_, err = e.eng.ApplyRRsets(ctx, fwdB, zoneName, []uiapi.RRsetChange{fwd("www", "301", "https://example.org/")}, 0)
	e.wantReason(err, ReasonNotOwner)

	if err := e.eng.Adopt(ctx, admin, zoneName, []uiapi.RRsetRef{{Host: "go", Type: "urlfwd"}}, ""); err != nil {
		t.Fatal(err)
	}
	if o := e.own("go", dns.TypeURLForward); o == nil || !o.Adopted || o.Owner != "team-a" {
		t.Fatalf("adopted %+v", o)
	}
	if _, err := e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("go", "302", "https://example.org/")}, 0); err != nil {
		t.Fatal(err)
	}
	if f := e.forwards()["go"]; f["id"] != float64(41) || f["forwardType"] != "HTTP302" || f["updated"] != nil {
		t.Fatalf("updated entry %v", f)
	}
}

func TestForwardPlanAndInventory(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	res, err := e.eng.PlanRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("www", "302", "http://example.net/a")})
	if err != nil || !res.Allowed || len(res.Changes) != 1 || res.Changes[0].NewForward == nil || res.Changes[0].Type != dns.TypeURLForward {
		t.Fatalf("plan %+v %v", res, err)
	}
	if res, err := e.eng.PlanRRsets(ctx, fwdB, zoneName, []uiapi.RRsetChange{fwd("go", "302", "http://example.net/a")}); err != nil || res.Allowed || res.Reason != string(ReasonForeignRRset) {
		t.Fatalf("plan on a foreign forward %+v %v", res, err)
	}
	inv, err := e.eng.Inventory(ctx, alice, zoneName)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range inv.RRsets {
		if r.Type == dns.TypeURLForward {
			found = r.Host == "go" && r.Forward != nil && r.Forward.Mode == "301" && r.Status == uiapi.StatusForeign && r.TTL == 0
		}
	}
	if !found {
		t.Fatalf("forward missing from the inventory %+v", inv.RRsets)
	}
}

type forwardless struct{ *eurodnsprov.Provider }

func (f forwardless) Capabilities() provider.Capabilities {
	c := f.Provider.Capabilities()
	c.Forwards = false
	return c
}

type httpsProvider struct {
	*eurodnsprov.Provider
	status string
}

func (h httpsProvider) HTTPSRedirect(context.Context, string) (provider.HTTPSRedirect, error) {
	return provider.HTTPSRedirect{Status: h.status, Message: "test"}, nil
}

func TestForwardCapabilityAndHTTPS(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, eurodnstest.Options{})
	e.eng, _ = New(Config{Providers: provider.Single(forwardless{e.prov}), Store: e.st, Authz: e.authz, Zones: []string{zoneName}, Holder: "test"})
	_, err := e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{fwd("www", "301", "https://example.net/")}, 0)
	e.wantReason(err, ReasonInvalid)
	if st, err := e.eng.HTTPSRedirect(ctx, alice, zoneName); err != nil || st.Status != provider.HTTPSUnsupported {
		t.Fatalf("https %+v %v", st, err)
	}

	for status, ok := range map[string]bool{provider.HTTPSActive: true, provider.HTTPSPending: true, provider.HTTPSNoForward: true,
		provider.HTTPSInactive: false, provider.HTTPSUnknown: false} {
		e := newEnv(t, eurodnstest.Options{})
		e.eng, _ = New(Config{Providers: provider.Single(httpsProvider{e.prov, status}), Store: e.st, Authz: e.authz, Zones: []string{zoneName}, Holder: "test"})
		c := fwd("www", "301", "https://example.net/")
		c.RequireHTTPS = true
		res, err := e.eng.PlanRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{c})
		if err != nil || res.Allowed != ok {
			t.Fatalf("%s: plan %+v %v", status, res, err)
		}
		_, err = e.eng.ApplyRRsets(ctx, fwdA, zoneName, []uiapi.RRsetChange{c}, 0)
		if ok {
			if err != nil {
				t.Fatalf("%s: %v", status, err)
			}
			continue
		}
		e.wantReason(err, ReasonHTTPS)
		if !strings.Contains(err.Error(), "subscription") {
			t.Fatalf("%s: message %v", status, err)
		}
	}
}
