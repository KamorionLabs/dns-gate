package server

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/mcpb"
)

var visitRe = regexp.MustCompile(`visit (\S+)`)

// TestClaudeDesktopSignInWithSAML runs the relay of the bundle of a gate
// whose UI login is SAML: the relay signs in at the gate authorization
// server, the browser (here the test) goes through the SAML login and the
// consent page, and the relay then calls the MCP tools with a gate token.
func TestClaudeDesktopSignInWithSAML(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	e := newSAMLEnv(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
	})
	b := browser()
	e.login(t, b, "alice@example.com", "DNS-Writers")

	resp, err := b.Get(e.base + "/api/v1/connect/claude-desktop.mcpb")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("bundle: %d %s", resp.StatusCode, bundle)
	}
	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var m mcpb.Manifest
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		p := filepath.Join(dir, "ext", filepath.FromSlash(f.Name))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if f.Name == "manifest.json" {
			_ = json.Unmarshal(data, &m)
		}
	}
	env := m.Server.MCPConfig.Env
	if env["DNS_GATE_ISSUER"] != e.base || env["DNS_GATE_CLIENT_ID"] != RelayClientID {
		t.Fatalf("bundle sign-in settings: %v", env)
	}

	args := make([]string, len(m.Server.MCPConfig.Args))
	for i, a := range m.Server.MCPConfig.Args {
		args[i] = strings.ReplaceAll(a, "${__dirname}", filepath.Join(dir, "ext"))
	}
	cmd := exec.Command(node, args...)
	cmd.Env = append(os.Environ(), "DNS_GATE_TOKEN_DIR="+filepath.Join(dir, "tokens"), "DNS_GATE_NO_BROWSER=1", "DNS_GATE_LOGIN_TIMEOUT=20")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Wait()
	})
	lines := make(chan map[string]any, 32)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var msg map[string]any
			_ = json.Unmarshal(sc.Bytes(), &msg)
			lines <- msg
		}
		close(lines)
	}()
	send := func(s string) { _, _ = io.WriteString(stdin, s+"\n") }
	recv := func(match func(map[string]any) bool) map[string]any {
		t.Helper()
		timeout := time.After(15 * time.Second)
		for {
			select {
			case msg, ok := <-lines:
				if !ok {
					t.Fatalf("relay exited; stderr:\n%s", stderr.String())
				}
				if match(msg) {
					return msg
				}
			case <-timeout:
				t.Fatalf("no message; stderr:\n%s", stderr.String())
			}
		}
	}
	byID := func(id float64) func(map[string]any) bool {
		return func(m map[string]any) bool { return m["id"] == id }
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-desktop-test","version":"0"}}}`)
	recv(byID(1))
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if res, _ := recv(byID(2))["result"].(map[string]any); res == nil || len(res["tools"].([]any)) != 0 {
		t.Fatalf("tools/list while signed out: %v", res)
	}

	var signIn string
	deadline := time.Now().Add(10 * time.Second)
	for signIn == "" && time.Now().Before(deadline) {
		if m := visitRe.FindStringSubmatch(stderr.String()); m != nil {
			signIn = m[1]
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !strings.HasPrefix(signIn, e.base+oauthAuthorizePath+"?") {
		t.Fatalf("sign-in URL: %q\n%s", signIn, stderr.String())
	}
	resp, err = b.Get(signIn)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("consent page: %d %s", resp.StatusCode, page)
	}
	form := consentForm(t, string(page))
	form.Set("decision", "allow")
	req, _ := http.NewRequest("POST", e.base+oauthAuthorizePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.base)
	resp, err = b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loopback, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loopback.Hostname() != "localhost" {
		t.Fatalf("consent redirect: %d %s", resp.StatusCode, loopback)
	}
	resp, err = http.Get(loopback.String())
	if err != nil {
		t.Fatal(err)
	}
	done, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(done), "Signed in") {
		t.Fatalf("loopback: %d %s\n%s", resp.StatusCode, done, stderr.String())
	}

	recv(func(m map[string]any) bool { return m["method"] == "notifications/tools/list_changed" })
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_zones","arguments":{}}}`)
	call := recv(byID(3))
	res, _ := call["result"].(map[string]any)
	if res == nil || res["isError"] == true || !strings.Contains(mustJSON(res["structuredContent"]), "example.com") {
		t.Fatalf("list_zones: %v\n%s", call, stderr.String())
	}
	saved, _ := os.ReadFile(filepath.Join(dir, "tokens", strings.ReplaceAll(loopbackHost(e.base), ":", "_")+".json"))
	var st map[string]any
	if err := json.Unmarshal(saved, &st); err != nil || st["refresh_token"] == nil || st["issuer"] != e.base {
		t.Fatalf("saved tokens: %v %s", err, saved)
	}
}

func loopbackHost(base string) string {
	u, _ := url.Parse(base)
	return u.Host
}
