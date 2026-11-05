package server

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

const specPath = "../../api/dns-gate.openapi.yaml"

func specRoutes(t *testing.T) (map[string]bool, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                    `yaml:"openapi"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Fatalf("openapi %q, want 3.1", doc.OpenAPI)
	}
	out := map[string]bool{}
	ops := map[string]any{}
	for path, item := range doc.Paths {
		for method, op := range item {
			switch method {
			case "get", "put", "post", "delete", "patch":
				out[strings.ToUpper(method)+" "+path] = true
				ops[strings.ToUpper(method)+" "+path] = op
			}
		}
	}
	return out, ops
}

// TestOpenAPICoversRoutes fails when a route of the server is missing from
// api/dns-gate.openapi.yaml, or when the spec documents a route the server
// does not serve.
func TestOpenAPICoversRoutes(t *testing.T) {
	spec, ops := specRoutes(t)
	served := map[string]bool{"GET " + GateInfoPath: true, "GET " + jwksPath: true}
	for _, rt := range apiRoutes {
		served[rt.Method+" "+rt.Pattern] = true
	}
	var missing, extra []string
	for k := range served {
		if !spec[k] {
			missing = append(missing, k)
		}
	}
	for k := range spec {
		if !served[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("routes missing from the spec: %v\nspec routes not served: %v", missing, extra)
	}
	ids := map[string]string{}
	for k, op := range ops {
		m, _ := op.(map[string]any)
		id, _ := m["operationId"].(string)
		if id == "" || ids[id] != "" {
			t.Errorf("%s: missing or duplicate operationId %q", k, id)
		}
		ids[id] = k
	}
}

// TestOpenAPIRefs checks that every $ref of the spec resolves.
func TestOpenAPIRefs(t *testing.T) {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components map[string]map[string]any `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`"#/components/([A-Za-z]+)/([A-Za-z0-9_]+)"`).FindAllStringSubmatch(string(raw), -1) {
		if _, ok := doc.Components[m[1]][m[2]]; !ok {
			t.Errorf("unresolved $ref %s", m[0])
		}
	}
}

// TestRoutesDispatched checks that every route of the table reaches a
// handler instead of the generic unknown endpoint answers.
func TestRoutesDispatched(t *testing.T) {
	approval := true
	e := newEnvWith(t, func(c *config.Config) { c.Policy.RequireApproval = &approval })
	tok := e.token("writer")
	sample := strings.NewReplacer("{zone}", "example.com", "{host}", "www", "{type}", "A", "{id}", "rev-00000001", "{name}", "web")
	for _, rt := range apiRoutes {
		body := ""
		if rt.Method == http.MethodPost || rt.Method == http.MethodPut {
			body = "{}"
		}
		r := e.do(t, rt.Method, sample.Replace(rt.Pattern), tok, body, nil)
		var b errorBody
		_ = json.NewDecoder(r.Body).Decode(&b)
		if r.StatusCode == http.StatusMethodNotAllowed || b.Message == "unknown API endpoint" || b.Message == "unknown policy endpoint" {
			t.Errorf("%s %s not dispatched: %d %+v", rt.Method, rt.Pattern, r.StatusCode, b)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/nope"},
		{"GET", "/api/v1/zones/example.com"},
		{"GET", "/api/v1/zones/example.com/rrsets/www"},
		{"PATCH", "/api/v1/zones/example.com/rrsets/www/A"},
		{"POST", "/api/v1/zones"},
	} {
		r := e.do(t, tc.method, tc.path, tok, "", nil)
		if r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", tc.method, tc.path, r.StatusCode)
		}
	}
}
