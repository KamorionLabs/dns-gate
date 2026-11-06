//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/app"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// scenarioFolders: the discovered zone, managed since scenario 12, is moved
// between EuroDNS folders; a role selecting /ES and below writes there only
// while the zone is in it, every move is audited, and the folder is shown in
// the zone list and the explanation of a decision.
func (e *env) scenarioFolders(t *testing.T) {
	ctx := context.Background()
	if !e.app.Policy.Current().IsManaged(discoveredZone) {
		t.Skip("scenario 12 did not manage " + discoveredZone)
	}
	es := e.bearerClient("ci-es")
	rec := func(host string) []eurodns.Record {
		return []eurodns.Record{{Type: "CNAME", Host: host, TTL: 3600, RData: "es.example.org."}}
	}

	// In no folder: the folder rule does not apply.
	if _, err := es.AddRecords(ctx, discoveredZone, rec("a.es")); !eurodns.IsForbidden(err) {
		t.Fatalf("write before the zone is in /ES: %v", err)
	}

	e.account.setFolder(discoveredZone, "/ES/Madrid")
	if err := e.app.Discovery.Refresh(ctx); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	var zones []uiapi.ZoneSummary
	e.getJSON(t, "ci-es", "/api/v1/zones", &zones)
	if len(zones) != 1 || zones[0].Zone != discoveredZone || zones[0].Folder != "/ES/Madrid" {
		t.Fatalf("zones of the /ES writer: %+v", zones)
	}
	zones = nil
	e.getJSON(t, "admin-a", "/api/v1/zones?folder=/", &zones)
	if len(zones) != 1 || zones[0].Zone != zone || zones[0].Folder != "/" {
		t.Fatalf("zones in no folder: %+v", zones)
	}
	if _, err := es.AddRecords(ctx, discoveredZone, rec("a.es")); err != nil {
		t.Fatalf("write in /ES/Madrid: %v", err)
	}
	if _, err := es.AddRecords(ctx, discoveredZone, rec("b.apps")); !eurodns.IsForbidden(err) {
		t.Fatalf("write outside the hosts of the folder rule: %v", err)
	}
	var exp uiapi.ExplainResponse
	e.postJSON(t, "admin-a", "/api/v1/policy/explain", uiapi.ExplainRequest{
		Subject: uiapi.SubjectMatcher{Issuer: "ci", Claims: map[string][]string{"sub": {"ci-es"}}},
		Action:  "dns.record.write", Zone: discoveredZone, Host: "c.es", Type: "CNAME",
	}, http.StatusOK, &exp)
	if !exp.Allowed || exp.Folder != "/ES/Madrid" || exp.Matched != "roles.es-writer.rules[0]" {
		t.Fatalf("explain: %+v", exp)
	}

	e.account.setFolder(discoveredZone, "/FR")
	if err := e.app.Discovery.Refresh(ctx); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if _, err := es.AddRecords(ctx, discoveredZone, rec("d.es")); !eurodns.IsForbidden(err) {
		t.Fatalf("write after the zone left /ES: %v", err)
	}
	found := false
	for _, r := range e.fake.Zone(discoveredZone).Records {
		found = found || (r.Host == "a.es" && r.Type == "CNAME")
	}
	if !found {
		t.Fatal("record written in /ES missing upstream")
	}

	raw, err := os.ReadFile(e.auditBuf.Name())
	if err != nil {
		t.Fatal(err)
	}
	var moves []string
	writeFolder := ""
	for _, line := range strings.Split(string(raw), "\n") {
		var ev struct {
			Action   string         `json:"action"`
			Zone     string         `json:"zone"`
			Decision string         `json:"decision"`
			Extra    map[string]any `json:"extra"`
			Changes  []struct {
				Host string `json:"host"`
			} `json:"changes"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil || ev.Zone != discoveredZone {
			continue
		}
		if ev.Action == app.ActionZoneFolderChanged {
			moves = append(moves, fmt.Sprint(ev.Extra["old"])+" -> "+fmt.Sprint(ev.Extra["new"]))
		}
		if ev.Decision == "allow" && len(ev.Changes) == 1 && ev.Changes[0].Host == "a.es" {
			writeFolder, _ = ev.Extra["folder"].(string)
		}
	}
	if strings.Join(moves, ", ") != "/ -> /ES/Madrid, /ES/Madrid -> /FR" {
		t.Fatalf("folder change events: %v", moves)
	}
	if writeFolder != "/ES/Madrid" {
		t.Fatalf("the write granted through /ES/Madrid is audited with folder %q", writeFolder)
	}
}
