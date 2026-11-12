package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// folderFake adds EuroDNS folders to fakeDiscovery.
type folderFake struct {
	*fakeDiscovery
	folders map[string]string
}

func (f *folderFake) Folder(z string) string { return f.folders[z] }

func folderEnv(t *testing.T) *env {
	t.Helper()
	ff := &folderFake{
		fakeDiscovery: &fakeDiscovery{zones: map[string]bool{"example.com": true, "new.example.net": true, "other.net": true}},
		folders:       map[string]string{"example.com": "/ES", "new.example.net": "/ES/Madrid", "other.net": "/"},
	}
	tr := true
	e := newEnvDisc(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.Providers = []config.Provider{{ID: "eurodns", Kind: config.KindEuroDNS, Zones: config.ProviderZones{Include: []string{"*"}, Refresh: config.Duration(time.Hour)}}}
		c.Roles["reader"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{policy.ActionDNSRead, policy.ActionUIRead}}}}
		c.Roles["es-reader"] = config.Role{Rules: []config.Rule{{Folders: []string{"/ES/**"}, Actions: []string{policy.ActionDNSRead, policy.ActionUIRead}}}}
		c.Roles["padmin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", policy.ActionUIRead}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "reader", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"reader"}}}}},
			config.Binding{Role: "es-reader", Team: "es", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"es"}}}}},
			config.Binding{Role: "padmin", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"alice"}}}}},
		)
		c.Policy = config.Policy{
			Editable: true, RequireApproval: &tr, EditMaxAge: config.Duration(15 * time.Minute),
			Bounds: config.Bounds{Folders: []string{"/ES/**"}, Actions: []string{policy.ActionDNSRead, policy.ActionUIRead}},
		}
	}, ff)
	e.engine.extra = []uiapi.ZoneSummary{{Zone: "new.example.net", Unmanaged: true}, {Zone: "other.net", Unmanaged: true}}
	return e
}

func TestZoneFolders(t *testing.T) {
	e := folderEnv(t)
	var zs []uiapi.ZoneSummary
	r := e.do(t, "GET", "/api/v1/zones", e.token("reader"), "", nil)
	_ = json.NewDecoder(r.Body).Decode(&zs)
	got := map[string]string{}
	for _, z := range zs {
		got[z.Zone] = z.Folder
	}
	if r.StatusCode != 200 || got["example.com"] != "/ES" || got["new.example.net"] != "/ES/Madrid" || got["other.net"] != "/" || got["example.org"] != "" {
		t.Fatalf("zones: %d %v", r.StatusCode, got)
	}

	cs := connect(t, e, e.token("es"))
	var out listZonesOut
	call(t, cs, "list_zones", map[string]any{}, &out)
	if len(out.Zones) != 1 || out.Zones[0].Zone != "new.example.net" || out.Zones[0].Folder != "/ES/Madrid" {
		t.Fatalf("list_zones of a folder reader: %+v", out.Zones)
	}
	cs = connect(t, e, e.token("reader"))
	out = listZonesOut{}
	call(t, cs, "list_zones", map[string]any{"folder": "/"}, &out)
	if len(out.Zones) != 1 || out.Zones[0].Zone != "other.net" {
		t.Fatalf("list_zones folder filter: %+v", out.Zones)
	}
	if res := call(t, cs, "list_zones", map[string]any{"folder": "ES"}, nil); !res.IsError || !strings.Contains(errText(res), "must start with /") {
		t.Fatalf("invalid folder filter: %s", errText(res))
	}
}

func TestExplainAndWhoCanByFolder(t *testing.T) {
	e := folderEnv(t)
	alice := e.human("alice", time.Minute)
	var exp uiapi.ExplainResponse
	r := e.do(t, "POST", "/api/v1/policy/explain", alice, `{"subject":{"issuer":"idp","claims":{"sub":["es"]}},"action":"dns.read","zone":"new.example.net"}`, nil)
	_ = json.NewDecoder(r.Body).Decode(&exp)
	if r.StatusCode != 200 || !exp.Allowed || exp.Folder != "/ES/Madrid" || exp.Matched != "roles.es-reader.rules[0]" {
		t.Fatalf("explain: %d %+v", r.StatusCode, exp)
	}
	var wc uiapi.WhoCanResponse
	r = e.do(t, "GET", "/api/v1/policy/who-can?zone=new.example.net&action=dns.read", alice, "", nil)
	_ = json.NewDecoder(r.Body).Decode(&wc)
	byFolder := false
	for _, en := range wc.Entries {
		if en.Role == "es-reader" {
			byFolder = en.ByFolder
		}
		if en.Role == "reader" && en.ByFolder {
			t.Fatalf("zone rule reported as folder: %+v", en)
		}
	}
	if r.StatusCode != 200 || wc.Folder != "/ES/Madrid" || !byFolder {
		t.Fatalf("who-can: %d %+v", r.StatusCode, wc)
	}
}

// TestListZonesCompact: compact=true drops sync and write times, and for an
// unmanaged zone every count but its total; unknown counts and no_zone come
// through as they are, in the full and the compact answer.
func TestListZonesCompact(t *testing.T) {
	e := folderEnv(t)
	now := time.Now()
	e.engine.extra = []uiapi.ZoneSummary{
		{Zone: "new.example.net", Unmanaged: true, LastSyncedAt: &now, RRsets: uiapi.Count(4), Foreign: uiapi.Count(4),
			Managed: uiapi.Count(0), Tainted: uiapi.Count(0), Pending: uiapi.Count(0)},
		{Zone: "other.net", Unmanaged: true, NoZone: true},
	}
	cs := connect(t, e, e.token("reader"))

	raw := func(args map[string]any) map[string]map[string]any {
		t.Helper()
		var out struct {
			Zones []map[string]any `json:"zones"`
		}
		if res := call(t, cs, "list_zones", args, &out); res.IsError {
			t.Fatalf("list_zones %v: %s", args, errText(res))
		}
		m := map[string]map[string]any{}
		for _, z := range out.Zones {
			m[z["zone"].(string)] = z
		}
		return m
	}

	full := raw(map[string]any{})
	if _, ok := full["other.net"]["rrsets"]; ok || full["other.net"]["no_zone"] != true {
		t.Fatalf("domain without zone: %v", full["other.net"])
	}
	if full["new.example.net"]["foreign"] != float64(4) || full["new.example.net"]["last_synced_at"] == nil {
		t.Fatalf("read unmanaged zone: %v", full["new.example.net"])
	}

	compact := raw(map[string]any{"compact": true})
	for _, k := range []string{"last_synced_at", "last_write_at", "managed", "tainted", "pending", "foreign"} {
		if _, ok := compact["new.example.net"][k]; ok {
			t.Fatalf("compact unmanaged zone has %s: %v", k, compact["new.example.net"])
		}
	}
	if compact["new.example.net"]["rrsets"] != float64(4) || compact["new.example.net"]["folder"] != "/ES/Madrid" || compact["other.net"]["no_zone"] != true {
		t.Fatalf("compact: %v", compact)
	}
	if mz := compact["example.com"]; mz["managed"] != float64(1) || mz["rrsets"] != float64(3) || mz["last_synced_at"] != nil {
		t.Fatalf("compact managed zone: %v", mz)
	}
}
