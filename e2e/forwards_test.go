//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// forwards returns the URL forwards of the fake zone by host.
func (e *env) forwards(t *testing.T) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, raw := range e.fake.Zone(zone).URLForwards {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out[fmt.Sprint(m["host"])] = m
	}
	return out
}

// scenarioURLForwards drives dnsgate_url_forward (dnsgate provider sources
// with the resource, skipped otherwise) through the forward API: create a
// redirect and a frame, an empty second plan, update, require_https refused
// without an HTTPS redirect subscription, a forward created outside the gate
// refused then adopted and imported, destroy. Forwards of other hosts stay
// byte for byte.
func (e *env) scenarioURLForwards(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(here), "..", "..", "terraform-provider-dnsgate")
	if p := os.Getenv("E2E_DNSGATE_PROVIDER_SRC"); p != "" {
		src = p
	}
	if b, err := exec.Command("grep", "-rl", "dnsgate_url_forward", filepath.Join(src, "internal")).Output(); err != nil || len(b) == 0 {
		t.Skipf("dnsgate provider sources at %s have no dnsgate_url_forward", src)
	}
	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "terraform-provider-dnsgate"), ".")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build dnsgate provider: %v\n%s", err, out)
	}
	cli := filepath.Join(t.TempDir(), "cli.tfrc")
	if err := os.WriteFile(cli, []byte(fmt.Sprintf("provider_installation {\n  dev_overrides {\n    \"kamorionlabs/dnsgate\" = %q\n  }\n  direct {}\n}\n", bin)), 0o600); err != nil {
		t.Fatal(err)
	}

	upstream, err := eurodns.New(eurodns.WithBaseURL(e.fake.URL), eurodns.WithAuth(eurodns.APIKeyAuth{AppID: upstreamApp, APIKey: upstreamKey}),
		eurodns.WithRateLimit(5*time.Millisecond, 50))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	z, err := upstream.GetZone(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	keep := `{"id":900,"host":"keep","forwardType":"HTTP302","url":"https://keep.example.net/","x-extra":true}`
	z.URLForwards = append(z.URLForwards, json.RawMessage(keep),
		json.RawMessage(`{"host":"legacy-go","forwardType":"HTTP301","url":"https://old.example.net/"}`))
	if err := upstream.SaveZone(ctx, zone, z); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	_, tokenFile := e.token("ci-web")
	write := func(body string) {
		main := fmt.Sprintf(`
terraform {
  required_providers {
    dnsgate = { source = "kamorionlabs/dnsgate" }
  }
}
provider "dnsgate" {
  endpoint = %q
  auth { token_file = %q }
}
`, e.gate.URL, tokenFile) + body
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(main), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(e.tfBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+cli, "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", filepath.Base(e.tfBin), strings.Join(args, " "), err, out)
		}
		return out
	}
	noChanges := func() {
		t.Helper()
		if out := must("plan", "-detailed-exitcode", "-no-color"); !strings.Contains(out, "No changes") {
			t.Fatalf("plan not empty:\n%s", out)
		}
	}
	resources := func(redirect, extra string) string {
		return fmt.Sprintf(`
resource "dnsgate_url_forward" "go" {
  zone = %[1]q
  name = "fwd-go"
  type = %[2]q
  url  = "https://example.net/landing"
%[3]s}
resource "dnsgate_url_forward" "shop" {
  zone  = %[1]q
  name  = "fwd-shop"
  type  = "frame"
  url   = "https://shop.example.net/"
  title = "Shop"
}
`, zone, redirect, extra)
	}

	write(resources("301", ""))
	must("apply", "-auto-approve", "-no-color")
	f := e.forwards(t)
	if f["fwd-go"]["forwardType"] != "HTTP301" || f["fwd-go"]["url"] != "https://example.net/landing" || f["fwd-shop"]["forwardType"] != "FRAME" || f["fwd-shop"]["title"] != "Shop" {
		t.Fatalf("forwards after create: %v", f)
	}
	var view struct {
		uiapi.RRset
		HTTPS *struct{ Status string } `json:"https"`
	}
	e.getJSON(t, "ci-admin", "/api/v1/zones/"+zone+"/forwards/fwd-go", &view)
	if view.Status != uiapi.StatusManaged || view.Owner != "web" || view.Forward == nil || view.HTTPS == nil || view.HTTPS.Status != "unknown" {
		t.Fatalf("forward view %+v", view)
	}
	noChanges()

	write(resources("302", ""))
	must("apply", "-auto-approve", "-no-color")
	if got := e.forwards(t)["fwd-go"]["forwardType"]; got != "HTTP302" {
		t.Fatalf("updated forward type %v", got)
	}
	noChanges()

	write(resources("302", "  require_https = true\n"))
	if out, err := run("apply", "-auto-approve", "-no-color"); err == nil || !strings.Contains(out, "https_unavailable") && !strings.Contains(out, "HTTPS") {
		t.Fatalf("require_https without a subscription not refused (%v):\n%s", err, out)
	}
	write(resources("302", ""))
	noChanges()

	legacy := `
resource "dnsgate_url_forward" "legacy" {
  zone = "` + zone + `"
  name = "legacy-go"
  type = "301"
  url  = "https://old.example.net/"
}
`
	write(resources("302", "") + legacy)
	if out, err := run("apply", "-auto-approve", "-no-color"); err == nil || !strings.Contains(out, "foreign") && !strings.Contains(out, "adopt") {
		t.Fatalf("creating over a foreign forward not refused (%v):\n%s", err, out)
	}
	base := "/api/v1/zones/" + zone
	sel := uiapi.AdoptSelection{RRsets: []uiapi.RRsetRef{{Host: "legacy-go", Type: "URLFWD"}}}
	var prev uiapi.AdoptPreview
	e.postJSON(t, "ci-admin", base+"/adopt/preview", sel, http.StatusOK, &prev)
	if len(prev.Candidates) != 1 || !prev.Candidates[0].Adoptable || prev.Candidates[0].Forward == nil {
		t.Fatalf("adopt preview %+v", prev)
	}
	e.postJSON(t, "ci-admin", base+"/adopt", uiapi.AdoptApply{RRsets: sel.RRsets, Comment: "take over the legacy redirect", PreviewToken: prev.PreviewToken}, http.StatusOK, nil)
	must("import", "-no-color", "dnsgate_url_forward.legacy", zone+"/legacy-go")
	noChanges()

	if got := e.getText(t, "ci-admin", base+"/terraform?rrsets=legacy-go/URLFWD"); !strings.Contains(got, `resource "dnsgate_url_forward"`) || !strings.Contains(got, `id = "`+zone+`/legacy-go"`) {
		t.Fatalf("terraform export:\n%s", got)
	}

	must("destroy", "-auto-approve", "-no-color")
	f = e.forwards(t)
	for _, h := range []string{"fwd-go", "fwd-shop", "legacy-go"} {
		if _, ok := f[h]; ok {
			t.Fatalf("%s left after destroy: %v", h, f)
		}
	}
	if raw := e.fake.Zone(zone).URLForwards; len(raw) != 1 || string(raw[0]) != keep {
		t.Fatalf("untouched forward changed: %s", raw)
	}
}
