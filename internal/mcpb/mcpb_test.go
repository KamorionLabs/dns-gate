package mcpb

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

// manifestFields are the top-level properties of the MCPB 0.3 manifest
// schema, which allows no others.
var manifestFields = map[string]bool{
	"$schema": true, "dxt_version": true, "manifest_version": true, "name": true, "display_name": true,
	"version": true, "description": true, "long_description": true, "author": true, "repository": true,
	"homepage": true, "documentation": true, "support": true, "icon": true, "icons": true, "screenshots": true,
	"localization": true, "server": true, "tools": true, "tools_generated": true, "prompts": true,
	"prompts_generated": true, "keywords": true, "license": true, "privacy_policies": true,
	"compatibility": true, "user_config": true, "_meta": true,
}

func readZip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	return out
}

func TestBuild(t *testing.T) {
	p := Params{
		GateURL: "https://dns.example.com", MCPURL: "https://dns.example.com/mcp", Issuer: "https://idp.example.com/v2.0",
		ClientID: "client-1", Scope: "api://client-1/.default", Version: "v1.2.3",
	}
	b, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, b)
	if len(files) != 3 || !bytes.Equal(files["server/index.js"], relaySource) || files["package.json"] == nil {
		t.Fatalf("archive entries: %v", len(files))
	}

	var raw map[string]any
	if err := json.Unmarshal(files["manifest.json"], &raw); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	for k := range raw {
		if !manifestFields[k] {
			t.Errorf("manifest field %q is not in the MCPB schema", k)
		}
	}
	for _, k := range []string{"manifest_version", "name", "version", "description", "author", "server"} {
		if raw[k] == nil {
			t.Errorf("required manifest field %q missing", k)
		}
	}
	var m Manifest
	_ = json.Unmarshal(files["manifest.json"], &m)
	if m.ManifestVersion != "0.3" || m.Name != "eurodns-gate-dns-example-com" || m.DisplayName != "EuroDNS gate (dns.example.com)" || m.Version != "1.2.3" {
		t.Fatalf("manifest identity: %+v", m)
	}
	s := m.Server
	if s.Type != "node" || s.EntryPoint != "server/index.js" || s.MCPConfig.Command != "node" || len(s.MCPConfig.Args) != 1 || s.MCPConfig.Args[0] != "${__dirname}/server/index.js" {
		t.Fatalf("manifest server: %+v", s)
	}
	want := map[string]string{
		"EURODNS_GATE_MCP_URL": p.MCPURL, "EURODNS_GATE_ISSUER": p.Issuer,
		"EURODNS_GATE_CLIENT_ID": p.ClientID, "EURODNS_GATE_SCOPE": "client-1/.default",
	}
	if len(s.MCPConfig.Env) != len(want) {
		t.Fatalf("env: %v", s.MCPConfig.Env)
	}
	for k, v := range want {
		if s.MCPConfig.Env[k] != v {
			t.Errorf("env %s = %q, want %q", k, s.MCPConfig.Env[k], v)
		}
	}
	if m.Compatibility.Runtimes["node"] != ">=18.0.0" {
		t.Fatalf("compatibility: %+v", m.Compatibility)
	}

	again, _ := Build(p)
	if !bytes.Equal(b, again) {
		t.Fatal("archive is not reproducible")
	}
}

func TestBuildDefaults(t *testing.T) {
	m := NewManifest(Params{GateURL: "https://gate.example.com:8443/", MCPURL: "https://gate.example.com:8443/mcp", Issuer: "https://idp", ClientID: "c", Version: "dev"})
	if m.Version != "0.0.0" || m.Name != "eurodns-gate-gate-example-com-8443" || m.Homepage != "https://gate.example.com:8443/ui/" {
		t.Fatalf("manifest: %+v", m)
	}
	if _, ok := m.Server.MCPConfig.Env["EURODNS_GATE_SCOPE"]; ok {
		t.Fatal("empty scope must not be set")
	}
	if got := Filename("https://gate.example.com:8443"); got != "eurodns-gate-gate.example.com-8443.mcpb" {
		t.Fatalf("filename: %s", got)
	}
	if _, err := Build(Params{GateURL: "https://gate.example.com"}); err == nil {
		t.Fatal("missing issuer and client id accepted")
	}
}

func TestRelayScope(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	for _, c := range []struct{ scope, want string }{
		{"api://" + id + "/.default", id + "/.default"},
		{"api://" + id + "/access_as_user", id + "/access_as_user"},
		{"api://eurodns-gate/.default", "api://eurodns-gate/.default"},
		{"api://" + id + "-other/.default", "api://" + id + "-other/.default"},
		{"api://" + id, "api://" + id},
		{"https://gate.example.com/" + id + "/.default", "https://gate.example.com/" + id + "/.default"},
		{"gate.read", "gate.read"},
		{"", ""},
	} {
		if got := RelayScope(c.scope, id); got != c.want {
			t.Errorf("RelayScope(%q) = %q, want %q", c.scope, got, c.want)
		}
	}
	if got := RelayScope("api://x/.default", ""); got != "api://x/.default" {
		t.Errorf("without client id: %q", got)
	}
}
