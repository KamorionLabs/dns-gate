//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// send makes a request to the gate as sub and returns the status and body.
func (e *env) send(t *testing.T, sub, method, path, body string) (int, []byte) {
	t.Helper()
	tok, _ := e.token(sub)
	req, _ := http.NewRequest(method, e.gate.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/zone-profiles") {
		req.Header.Set("pagination-page", "1")
		req.Header.Set("pagination-size", "50")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// scenarioZoneProfiles: a domain transfer is prepared by an administrator
// holding dns.zone.profile on "*": a zone profile is checked, created,
// listed and changed through the neutral API and the EuroDNS-compatible API,
// then deleted; a zone writer is refused, and every step is audited with
// the profile content.
func (e *env) scenarioZoneProfiles(t *testing.T) {
	const prof = `{"name":"transfer-new-domain","records":[{"type":"A","host":"@","ttl":3600,"rdata":"192.0.2.80"},{"type":"CNAME","host":"www","ttl":3600,"rdata":"web.example.net."},{"type":"TXT","host":"@","ttl":3600,"rdata":"v=spf1 -all"}],"urlForwards":[],"mailForwards":[]}`
	base := "/api/v1/providers/eurodns/zone-profiles"

	if st, b := e.send(t, "ci-web", http.MethodPost, "/zone-profiles", prof); st != http.StatusForbidden {
		t.Fatalf("zone writer creates a profile: %d %s", st, b)
	}
	if st, _ := e.send(t, "ci-admin", http.MethodGet, base, ""); st != http.StatusForbidden {
		t.Fatalf("zone admin lists profiles: %d", st)
	}

	st, b := e.send(t, "ci-profiles", http.MethodPost, base+"/check", strings.Replace(prof, `"ttl":3600,"rdata":"192.0.2.80"`, `"ttl":5,"rdata":"192.0.2.80"`, 1))
	var checked struct {
		Report struct {
			IsValid bool `json:"isValid"`
		} `json:"report"`
	}
	if st != http.StatusOK || json.Unmarshal(b, &checked) != nil || checked.Report.IsValid {
		t.Fatalf("check of an invalid profile: %d %s", st, b)
	}

	st, b = e.send(t, "ci-profiles", http.MethodPost, "/zone-profiles", prof)
	var created struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if st != http.StatusCreated || json.Unmarshal(b, &created) != nil || created.ID == 0 {
		t.Fatalf("create through the EuroDNS API: %d %s", st, b)
	}
	id := strconv.FormatInt(created.ID, 10)

	var list uiapi.ZoneProfileList
	e.getJSON(t, "ci-profiles", base, &list)
	if list.Provider != "eurodns" || len(list.Profiles) != 1 || list.Profiles[0].Name != "transfer-new-domain" {
		t.Fatalf("neutral list: %+v", list)
	}
	if st, b = e.send(t, "ci-profiles", http.MethodGet, "/zone-profiles", ""); st != http.StatusOK || !bytes.Contains(b, []byte("transfer-new-domain")) {
		t.Fatalf("EuroDNS list: %d %s", st, b)
	}

	upd := strings.Replace(prof, "192.0.2.80", "192.0.2.81", 1)
	if st, b = e.send(t, "ci-profiles", http.MethodPut, base+"/"+id, upd); st != http.StatusOK {
		t.Fatalf("update: %d %s", st, b)
	}
	if p := e.profiles.Profile(created.ID); p == nil || p.Records[0].RData != "192.0.2.81" {
		t.Fatalf("upstream after update: %+v", p)
	}
	if st, b = e.send(t, "ci-profiles", http.MethodGet, "/zone-profiles/"+id, ""); st != http.StatusOK || !bytes.Contains(b, []byte("192.0.2.81")) {
		t.Fatalf("EuroDNS get: %d %s", st, b)
	}
	if st, b = e.send(t, "ci-profiles", http.MethodDelete, "/zone-profiles/"+id, ""); st != http.StatusNoContent || e.profiles.Len() != 0 {
		t.Fatalf("delete: %d %s", st, b)
	}

	raw, err := os.ReadFile(e.auditBuf.Name())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var ev audit.Event
		if json.Unmarshal(line, &ev) != nil || !strings.HasPrefix(ev.Action, "zone_profile.") && !strings.HasSuffix(ev.Action, "ZoneProfile") && !strings.HasSuffix(ev.Action, "ZoneProfiles") {
			continue
		}
		content, _ := json.Marshal(ev.Extra["profile"])
		seen[ev.Action+"/"+ev.Decision] = string(content)
	}
	for _, k := range []string{"createZoneProfile/deny", "zone_profile.list/deny", "zone_profile.check/allow", "createZoneProfile/allow",
		"zone_profile.list/allow", "zone_profile.update/allow", "deleteZoneProfile/allow"} {
		if _, ok := seen[k]; !ok {
			t.Errorf("audit event %s missing", k)
		}
	}
	if !strings.Contains(seen["createZoneProfile/allow"], "web.example.net.") || !strings.Contains(seen["deleteZoneProfile/allow"], "192.0.2.81") {
		t.Errorf("audited content: %v", seen)
	}
	if strings.Contains(string(raw), upstreamKey) {
		t.Error("upstream key in the audit log")
	}
}
