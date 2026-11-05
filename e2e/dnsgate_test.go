//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// scenarioDNSGateProvider drives the dnsgate Terraform provider (sources in
// E2E_DNSGATE_PROVIDER_SRC, default ../../terraform-provider-dnsgate)
// through the neutral RRset API: create, an empty second plan (values read
// back as written, a long TXT value unquoted included), update, destroy.
func (e *env) scenarioDNSGateProvider(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(here), "..", "..", "terraform-provider-dnsgate")
	if p := os.Getenv("E2E_DNSGATE_PROVIDER_SRC"); p != "" {
		src = p
	}
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Skipf("dnsgate provider sources not found at %s", src)
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
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 12)
	dir := t.TempDir()
	_, tokenFile := e.token("ci-web")
	write := func(aTTL int) {
		main := fmt.Sprintf(`
terraform {
  required_providers {
    dnsgate = { source = "kamorionlabs/dnsgate" }
  }
}
provider "dnsgate" {
  endpoint = %[1]q
  auth { token_file = %[2]q }
}
resource "dnsgate_record_set" "txt" {
  zone   = %[3]q
  name   = "dg-txt"
  type   = "TXT"
  ttl    = 600
  values = [%[4]q]
}
resource "dnsgate_record_set" "cname" {
  zone   = %[3]q
  name   = "dg-cname"
  type   = "CNAME"
  ttl    = 3600
  values = ["target.example.net"]
}
resource "dnsgate_record_set" "a" {
  zone   = %[3]q
  name   = "dg-a"
  type   = "A"
  ttl    = %[5]d
  values = ["192.0.2.21", "192.0.2.20"]
}
`, e.gate.URL, tokenFile, zone, dkim, aTTL)
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(main), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(e.tfBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+cli, "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", filepath.Base(e.tfBin), strings.Join(args, " "), err, out)
		}
		return string(out)
	}

	write(600)
	run("apply", "-auto-approve", "-no-color")
	if got := e.values("dg-txt", "TXT"); !slices.Equal(got, []string{dkim}) {
		t.Fatalf("TXT stored as %q", got)
	}
	if got := e.values("dg-cname", "CNAME"); !slices.Equal(got, []string{"target.example.net."}) {
		t.Fatalf("CNAME stored as %q", got)
	}
	if out := run("plan", "-detailed-exitcode", "-no-color"); !strings.Contains(out, "No changes") {
		t.Fatalf("second plan not empty:\n%s", out)
	}
	if st := e.status(t, "dg-txt", "TXT"); st != "managed" {
		t.Fatalf("dg-txt status %q", st)
	}

	write(3600)
	run("apply", "-auto-approve", "-no-color")
	if out := run("plan", "-detailed-exitcode", "-no-color"); !strings.Contains(out, "No changes") {
		t.Fatalf("plan after update not empty:\n%s", out)
	}

	run("destroy", "-auto-approve", "-no-color")
	for _, k := range [][2]string{{"dg-txt", "TXT"}, {"dg-cname", "CNAME"}, {"dg-a", "A"}} {
		if got := e.values(k[0], k[1]); len(got) != 0 {
			t.Fatalf("%s %s left after destroy: %q", k[0], k[1], got)
		}
	}
}
