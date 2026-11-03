// Package mcpb builds the Claude Desktop extension of a gate: an MCP Bundle
// (.mcpb, https://github.com/modelcontextprotocol/mcpb), a zip archive with a
// manifest.json and relay.js, a dependency-free Node.js stdio server that
// signs the user in with the gate's OIDC issuer and forwards MCP messages to
// the gate's /mcp endpoint. Claude Desktop runs it with its bundled Node.js,
// so users need no terminal and no runtime of their own.
package mcpb

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ManifestVersion is the MCPB manifest specification version produced.
const ManifestVersion = "0.3"

//go:embed relay.js
var relaySource []byte

// Params are the values baked into a bundle.
type Params struct {
	GateURL  string // public base URL of the gate
	MCPURL   string // MCP endpoint
	Issuer   string // OIDC issuer URL users sign in with
	ClientID string // public client registered with the issuer
	Scope    string // extra scope for a gate token (ui.cli_scope), may be empty
	Version  string // gate version, reported as the extension version
}

// Manifest is the subset of the MCPB manifest the gate writes.
type Manifest struct {
	ManifestVersion string        `json:"manifest_version"`
	Name            string        `json:"name"`
	DisplayName     string        `json:"display_name"`
	Version         string        `json:"version"`
	Description     string        `json:"description"`
	LongDescription string        `json:"long_description"`
	Author          Author        `json:"author"`
	Repository      Repository    `json:"repository"`
	Homepage        string        `json:"homepage"`
	Server          Server        `json:"server"`
	ToolsGenerated  bool          `json:"tools_generated"`
	Keywords        []string      `json:"keywords"`
	License         string        `json:"license"`
	Compatibility   Compatibility `json:"compatibility"`
}

// Author of the extension.
type Author struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Repository of the extension source.
type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Server tells the host how to start the relay.
type Server struct {
	Type       string    `json:"type"`
	EntryPoint string    `json:"entry_point"`
	MCPConfig  MCPConfig `json:"mcp_config"`
}

// MCPConfig is the command line of the relay.
type MCPConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// Compatibility lists the platforms and the Node.js runtime required.
type Compatibility struct {
	Platforms []string          `json:"platforms"`
	Runtimes  map[string]string `json:"runtimes"`
}

const (
	sourceURL  = "https://github.com/KamorionLabs/eurodns-gate"
	entryPoint = "server/index.js"
)

var (
	semver     = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	nonAlnum   = regexp.MustCompile(`[^a-z0-9]+`)
	fileUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)
	// modTime keeps the archive reproducible.
	modTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Host returns the host of the gate URL, the identity of a bundle.
func Host(gateURL string) string {
	u, err := url.Parse(gateURL)
	if err != nil || u.Host == "" {
		return "gate"
	}
	return u.Host
}

// slug is a lowercase, dash-separated form of the host.
func slug(host string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(host), "-"), "-")
}

// Filename is the download name of the bundle, e.g. eurodns-gate-dns.example.com.mcpb.
func Filename(gateURL string) string {
	return "eurodns-gate-" + strings.Trim(fileUnsafe.ReplaceAllString(Host(gateURL), "-"), "-.") + ".mcpb"
}

// RelayScope is the scope the relay requests. The relay signs in as the
// client itself, and Entra ID refuses a token an application requests for
// itself through its App ID URI (AADSTS90009): it must name itself by its
// GUID. A scope under api://<client_id>/ is therefore requested as
// <client_id>/...; any other scope is kept as is.
func RelayScope(scope, clientID string) string {
	if clientID == "" {
		return scope
	}
	fields := strings.Fields(scope)
	for i, f := range fields {
		if rest, ok := strings.CutPrefix(f, "api://"+clientID+"/"); ok {
			fields[i] = clientID + "/" + rest
		}
	}
	return strings.Join(fields, " ")
}

// NewManifest returns the manifest of the bundle for p.
func NewManifest(p Params) Manifest {
	host := Host(p.GateURL)
	version := strings.TrimPrefix(p.Version, "v")
	if !semver.MatchString(version) {
		version = "0.0.0"
	}
	env := map[string]string{
		"EURODNS_GATE_MCP_URL":   p.MCPURL,
		"EURODNS_GATE_ISSUER":    p.Issuer,
		"EURODNS_GATE_CLIENT_ID": p.ClientID,
	}
	if scope := RelayScope(p.Scope, p.ClientID); scope != "" {
		env["EURODNS_GATE_SCOPE"] = scope
	}
	return Manifest{
		ManifestVersion: ManifestVersion,
		Name:            "eurodns-gate-" + slug(host),
		DisplayName:     "EuroDNS gate (" + host + ")",
		Version:         version,
		Description:     "EuroDNS zones and records through the gate at " + host + ", with your own permissions.",
		LongDescription: "Connects Claude to the EuroDNS gate at " + host + ". You sign in once in your browser with your usual account; the gate then applies your permissions and records every action in its journal. When the gate allows changes, they are always planned before they are applied, and only on records your teams own.",
		Author:          Author{Name: "eurodns-gate", URL: sourceURL},
		Repository:      Repository{Type: "git", URL: sourceURL + ".git"},
		Homepage:        strings.TrimSuffix(p.GateURL, "/") + "/ui/",
		Server: Server{
			Type:       "node",
			EntryPoint: entryPoint,
			MCPConfig: MCPConfig{
				Command: "node",
				Args:    []string{"${__dirname}/" + entryPoint},
				Env:     env,
			},
		},
		ToolsGenerated: true,
		Keywords:       []string{"dns", "eurodns", "zones", "records"},
		License:        "MIT",
		Compatibility: Compatibility{
			Platforms: []string{"darwin", "win32", "linux"},
			Runtimes:  map[string]string{"node": ">=18.0.0"},
		},
	}
}

// Build returns the .mcpb archive for p.
func Build(p Params) ([]byte, error) {
	if p.GateURL == "" || p.MCPURL == "" || p.Issuer == "" || p.ClientID == "" {
		return nil, errors.New("mcpb: gate URL, MCP URL, issuer and client id are required")
	}
	m := NewManifest(p)
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	pkg, err := json.MarshalIndent(map[string]any{"name": m.Name, "version": m.Version, "private": true, "type": "commonjs", "main": entryPoint}, "", "  ")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"manifest.json", append(manifest, '\n')},
		{"package.json", append(pkg, '\n')},
		{entryPoint, relaySource},
	} {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: modTime}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
