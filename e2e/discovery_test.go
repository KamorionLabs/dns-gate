//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// discoveredZone exists in the account but is not in the gate's zones.
const discoveredZone = "example.net"

// accountDomains answers POST /domains/search (the fake has no domain
// listing) and forwards everything else to the EuroDNS fake.
type accountDomains struct {
	mu    sync.Mutex
	names []string
}

func (a *accountDomains) add(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.names = append(a.names, name)
}

func (a *accountDomains) server(t *testing.T, fakeURL string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(fakeURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/domains/search" {
			proxy.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-API-KEY") != upstreamKey {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		page, _ := strconv.Atoi(r.Header.Get("pagination-page"))
		size, _ := strconv.Atoi(r.Header.Get("pagination-size"))
		start := min(max(page-1, 0)*size, len(a.names))
		end := min(start+size, len(a.names))
		out := []map[string]string{}
		for _, n := range a.names[start:end] {
			out = append(out, map[string]string{"domainName": n})
		}
		w.Header().Set("pagination-count", strconv.Itoa(len(a.names)))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// scenarioDiscoveryTeamFrom: a zone of the account outside the config is
// visible read-only, brought under management by a reviewed policy revision,
// then written by two pipelines bound by one team_from binding, each owning
// its own records.
func (e *env) scenarioDiscoveryTeamFrom(t *testing.T) {
	ctx := context.Background()
	e.fake.Seed(&eurodns.Zone{Name: discoveredZone, Records: []eurodns.Record{
		{Type: "CNAME", Host: "www", TTL: 3600, RData: "web.example.org."},
	}})
	e.account.add(discoveredZone)
	if err := e.app.Discovery.Refresh(ctx); err != nil {
		t.Fatalf("discovery: %v", err)
	}

	// Unmanaged: listed, readable, not writable.
	var zones []uiapi.ZoneSummary
	e.getJSON(t, "pipeline:alpha", "/api/v1/zones", &zones)
	if len(zones) != 1 || zones[0].Zone != discoveredZone || !zones[0].Unmanaged {
		t.Fatalf("zones of pipeline:alpha: %+v", zones)
	}
	var inv uiapi.ZoneInventory
	e.getJSON(t, "pipeline:alpha", "/api/v1/zones/"+discoveredZone+"/rrsets", &inv)
	if !inv.Unmanaged || len(inv.RRsets) == 0 {
		t.Fatalf("inventory of the unmanaged zone: %+v", inv)
	}
	alpha := recordTFIn(discoveredZone, "alpha", "alpha.apps", "CNAME", "alpha.example.org.")
	dir := e.workspace(t, "pipeline:alpha", alpha)
	if out, err := e.tf(t, dir, "apply", "-auto-approve", "-no-color"); err == nil {
		t.Fatalf("write on an unmanaged zone succeeded:\n%s", out)
	}

	// Manage it: a revision adding the zone, approved by another admin.
	var eff uiapi.EffectivePolicy
	e.getJSON(t, "admin-a", "/api/v1/policy", &eff)
	if eff.Base.Discovery == nil || eff.Base.Discovery.Count != 2 {
		t.Fatalf("discovery status: %+v", eff.Base.Discovery)
	}
	doc := uiapi.PolicyDocument{}
	parent := ""
	if eff.Managed != nil {
		doc = *eff.Managed
	}
	if eff.Active != nil {
		parent = eff.Active.ID
	}
	doc.Zones = append(doc.Zones, discoveredZone)
	var rev uiapi.RevisionDetail
	e.postJSON(t, "admin-a", "/api/v1/policy/revisions", uiapi.ProposeRequest{ParentID: parent, Document: doc, Comment: "manage " + discoveredZone}, http.StatusCreated, &rev)
	gain := false
	for _, it := range rev.Impact {
		gain = gain || (it.Kind == "gain" && it.Who == "zone "+discoveredZone)
	}
	if !gain {
		t.Fatalf("impact: %+v", rev.Impact)
	}
	e.postJSON(t, "admin-b", "/api/v1/policy/revisions/"+rev.ID+"/approve", uiapi.DecisionRequest{Comment: "ok"}, http.StatusOK, nil)
	e.postJSON(t, "admin-b", "/api/v1/policy/revisions/"+rev.ID+"/activate", nil, http.StatusOK, nil)
	time.Sleep(500 * time.Millisecond) // reload interval of the policy holder

	// Each pipeline gets its own team from its subject.
	_, tokenFile := e.token("pipeline:alpha")
	e.writeTF(t, dir, tokenFile, alpha)
	apply(e, t, dir)
	beta := e.workspace(t, "pipeline:beta", recordTFIn(discoveredZone, "beta", "beta.apps", "CNAME", "beta.example.org."))
	apply(e, t, beta)

	owners := map[string]string{}
	inv = uiapi.ZoneInventory{}
	e.getJSON(t, "pipeline:alpha", "/api/v1/zones/"+discoveredZone+"/rrsets", &inv)
	for _, r := range inv.RRsets {
		owners[r.Host] = r.Owner
	}
	if inv.Unmanaged || owners["alpha.apps"] != "p-alpha" || owners["beta.apps"] != "p-beta" || owners["www"] != "" {
		t.Fatalf("owners after management: %v (unmanaged=%v)", owners, inv.Unmanaged)
	}

	// Ownership isolates them: beta cannot delete what alpha created.
	var alphaID int64
	for _, r := range e.fake.Zone(discoveredZone).Records {
		if r.Host == "alpha.apps" && r.ID != nil {
			alphaID = *r.ID
		}
	}
	if _, err := e.bearerClient("pipeline:beta").DeleteRecord(ctx, discoveredZone, alphaID); reason(err) != "not_owner" {
		t.Fatalf("beta deleting alpha's record: want not_owner, got %v", err)
	}
	// And the role still bounds every pipeline: no write outside *.apps.
	if _, err := e.bearerClient("pipeline:beta").AddRecords(ctx, discoveredZone, []eurodns.Record{{Type: "CNAME", Host: "beta", TTL: 3600, RData: "x.example.org."}}); !eurodns.IsForbidden(err) {
		t.Fatalf("write outside the role: %v", err)
	}
	intact := false
	for _, r := range e.fake.Zone(discoveredZone).Records {
		intact = intact || (r.Host == "www" && r.Type == "CNAME" && r.RData == "web.example.org.")
	}
	if !intact {
		t.Fatal("foreign record of the discovered zone changed")
	}
}
