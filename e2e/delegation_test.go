//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// workloadsSubject is the pipeline of the delegation: it manages the gate
// roles and bindings of the pipelines it creates.
const workloadsSubject = "sc://org/proj/workloads-pipelines"

func (e *env) delegated(t *testing.T, sub, method, path, body string, hdr map[string]string) (int, []byte) {
	t.Helper()
	tok, _ := e.token(sub)
	var r io.Reader = http.NoBody
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.gate.URL+"/api/v1/policy/delegated/"+path, r)
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// waitBound waits until the policy holder serves a binding for sub (the
// delegated write refreshes the replica that served it; the e2e runs one).
func (e *env) waitBound(t *testing.T, sub string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tok, _ := e.token(sub)
		req, _ := http.NewRequest(http.MethodGet, e.gate.URL+"/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if (resp.StatusCode == http.StatusOK) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("binding of %s: /me answers %d", sub, resp.StatusCode)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *env) scenarioDelegation(t *testing.T) {
	pipeline := "sc://org/proj/eurodns-gate-x"
	role := `{"rules":[{"zones":["example.com"],"actions":["dns.read","dns.record.write"],"records":{"hosts":["x.wl"],"types":["CNAME"]}}],"managed_by":"e2e"}`
	binding := fmt.Sprintf(`{"role":"eurodns-gate-x","team":"eurodns-gate-x","subjects":[{"issuer":"ci","claims":{"sub":[%q]}}]}`, pipeline)

	// The pipeline has no gate identity before the delegated pipeline creates one.
	if code, _ := e.delegated(t, pipeline, http.MethodGet, "", "", nil); code != http.StatusForbidden {
		t.Fatalf("pipeline before delegation: %d", code)
	}
	if code, b := e.delegated(t, workloadsSubject, http.MethodPut, "roles/eurodns-gate-x", role, map[string]string{"If-None-Match": "*"}); code != http.StatusOK {
		t.Fatalf("delegated role: %d %s", code, b)
	}
	code, b := e.delegated(t, workloadsSubject, http.MethodPut, "bindings/eurodns-gate-x", binding, map[string]string{"If-None-Match": "*"})
	var res uiapi.DelegatedResult
	_ = json.Unmarshal(b, &res)
	if code != http.StatusOK || !res.Changed || res.RevisionID == "" {
		t.Fatalf("delegated binding: %d %s", code, b)
	}

	// Outside the delegation: a host it does not allow, a subject it does not cover.
	wide := strings.Replace(role, `"x.wl"`, `"www"`, 1)
	if code, b := e.delegated(t, workloadsSubject, http.MethodPut, "roles/too-wide", wide, nil); code != http.StatusBadRequest || !bytes.Contains(b, []byte("invalid_policy")) {
		t.Fatalf("role outside the delegation: %d %s", code, b)
	}
	other := strings.Replace(binding, pipeline, "sc://org/proj/other", 1)
	if code, b := e.delegated(t, workloadsSubject, http.MethodPut, "bindings/other", other, nil); code != http.StatusBadRequest {
		t.Fatalf("binding outside the delegation: %d %s", code, b)
	}
	// The bound pipeline itself cannot use the delegation API.
	if code, _ := e.delegated(t, pipeline, http.MethodPut, "roles/self", role, nil); code != http.StatusForbidden {
		t.Fatalf("bound pipeline used the delegation: %d", code)
	}

	// The bound pipeline writes what its role allows, and only that.
	e.waitBound(t, pipeline, true)
	dir := e.workspace(t, pipeline, recordTF("x", "x.wl", "CNAME", "x.example.net."))
	apply(e, t, dir)
	if got := e.values("x.wl", "CNAME"); len(got) != 1 {
		t.Fatalf("x.wl not created: %v", got)
	}
	_, err := e.bearerClient(pipeline).AddRecords(context.Background(), zone, []eurodns.Record{{Type: "CNAME", Host: "y.wl", TTL: 3600, RData: "y.example.net."}})
	if !eurodns.IsForbidden(err) {
		t.Errorf("bound pipeline wrote outside its role: %v", err)
	}
	if st := e.status(t, "x.wl", "CNAME"); st != uiapi.StatusManaged {
		t.Errorf("x.wl status %s", st)
	}

	// Audit.
	var page uiapi.AuditPage
	e.getJSON(t, "admin-a", "/api/v1/audit?limit=200", &page)
	seen := map[string]bool{}
	for _, ev := range page.Entries {
		seen[ev.Action+":"+ev.Decision] = true
	}
	for _, want := range []string{"policy.delegated.put_role:allow", "policy.delegated.put_binding:allow", "policy.delegated.put_role:deny"} {
		if !seen[want] {
			t.Errorf("audit event %s missing", want)
		}
	}

	e.scenarioDelegationTerraform(t)
}

// scenarioDelegationTerraform drives the same flow with the provider
// resources eurodns_gate_role and eurodns_gate_binding, when the provider
// sources have them (the provider is released after the gate).
func (e *env) scenarioDelegationTerraform(t *testing.T) {
	src := os.Getenv("E2E_PROVIDER_SRC")
	if src == "" {
		src = filepath.Join("..", "..", "terraform-provider-eurodns")
	}
	if b, err := os.ReadFile(filepath.Join(src, "internal", "provider", "resource_gate_role.go")); err != nil || !bytes.Contains(b, []byte("_gate_role")) {
		t.Log("provider without eurodns_gate_role: Terraform part of the delegation scenario skipped")
		return
	}
	pipeline := "sc://org/proj/eurodns-gate-z"
	stack := fmt.Sprintf(`
resource "eurodns_gate_role" "z" {
  name        = "eurodns-gate-z"
  description = "DNS names of pipeline z"
  rules = [{
    zones   = [%[1]q]
    actions = ["dns.read", "dns.record.write"]
    hosts   = ["z.wl", "_acme-challenge.z.wl"]
    types   = ["CNAME", "TXT"]
  }]
}

resource "eurodns_gate_binding" "z" {
  name = "eurodns-gate-z"
  role = eurodns_gate_role.z.name
  team = "eurodns-gate-z"
  subjects = [{
    issuer = "ci"
    claims = { sub = [%[2]q] }
  }]
}
`, zone, pipeline)
	dir := e.workspace(t, workloadsSubject, stack)
	apply(e, t, dir)
	if out := e.mustTF(t, dir, "plan", "-detailed-exitcode", "-no-color"); !strings.Contains(out, "No changes") {
		t.Fatalf("plan after apply is not empty:\n%s", out)
	}

	e.waitBound(t, pipeline, true)
	pdir := e.workspace(t, pipeline, recordTF("z", "z.wl", "CNAME", "z.example.net."))
	apply(e, t, pdir)
	if got := e.values("z.wl", "CNAME"); len(got) != 1 {
		t.Fatalf("z.wl not created: %v", got)
	}

	// Drift: a change made outside Terraform shows up in the plan.
	body := `{"rules":[{"zones":["example.com"],"actions":["dns.read"],"records":{"hosts":["z.wl"],"types":["CNAME"]}}]}`
	if code, b := e.delegated(t, workloadsSubject, http.MethodPut, "roles/eurodns-gate-z", body, nil); code != http.StatusOK {
		t.Fatalf("out-of-band change: %d %s", code, b)
	}
	out, err := e.tf(t, dir, "plan", "-detailed-exitcode", "-no-color")
	if err == nil || !strings.Contains(out, "dns.record.write") {
		t.Fatalf("drift not detected:\n%s", out)
	}
	apply(e, t, dir)

	// Import by name.
	idir := e.workspace(t, workloadsSubject, stack)
	e.mustTF(t, idir, "import", "-no-color", "eurodns_gate_role.z", "eurodns-gate-z")
	e.mustTF(t, idir, "import", "-no-color", "eurodns_gate_binding.z", "eurodns-gate-z")
	if out := e.mustTF(t, idir, "plan", "-detailed-exitcode", "-no-color"); !strings.Contains(out, "No changes") {
		t.Fatalf("plan after import is not empty:\n%s", out)
	}

	// Destroy removes the binding and the role: the pipeline loses its identity.
	e.mustTF(t, pdir, "destroy", "-auto-approve", "-no-color")
	e.mustTF(t, dir, "destroy", "-auto-approve", "-no-color")
	e.waitBound(t, pipeline, false)
	if code, _ := e.delegated(t, workloadsSubject, http.MethodGet, "roles/eurodns-gate-z", "", nil); code != http.StatusNotFound {
		t.Fatalf("role after destroy: %d", code)
	}
}
