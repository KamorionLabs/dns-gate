package server

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/mcpb"
)

// bundleRelay is the relay of a downloaded bundle, run as Claude Desktop
// does: messages are written on its stdin and read back by id.
type bundleRelay struct {
	send   func(string)
	recv   func(id float64) map[string]any
	stderr *lockedBuffer
	exited <-chan error
}

// startBundleRelay downloads the bundle of e, saves tok as the signed-in
// token and starts the relay. The browser sign-in is covered by
// internal/mcpb/relay.test.js.
func startBundleRelay(t *testing.T, e *env, tok string) *bundleRelay {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	r := e.do(t, "GET", "/api/v1/connect/claude-desktop.mcpb", tok, "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 {
		t.Fatalf("bundle: %d %s", r.StatusCode, b)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
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
	u, _ := url.Parse(env["DNS_GATE_MCP_URL"])
	tokens := filepath.Join(dir, "tokens")
	saved, _ := json.Marshal(map[string]any{
		"issuer": env["DNS_GATE_ISSUER"], "client_id": env["DNS_GATE_CLIENT_ID"], "scope": "openid offline_access",
		"access_token": tok, "expires_at": time.Now().Add(time.Hour).UnixMilli(),
	})
	_ = os.MkdirAll(tokens, 0o700)
	if err := os.WriteFile(filepath.Join(tokens, strings.ReplaceAll(u.Host, ":", "_")+".json"), saved, 0o600); err != nil {
		t.Fatal(err)
	}

	args := make([]string, len(m.Server.MCPConfig.Args))
	for i, a := range m.Server.MCPConfig.Args {
		args[i] = strings.ReplaceAll(a, "${__dirname}", filepath.Join(dir, "ext"))
	}
	cmd := exec.Command(node, args...)
	cmd.Env = append(os.Environ(), "DNS_GATE_TOKEN_DIR="+tokens, "DNS_GATE_NO_BROWSER=1")
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
	exited := make(chan error, 1)
	lines := make(chan map[string]any, 256)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var msg map[string]any
			_ = json.Unmarshal(sc.Bytes(), &msg)
			lines <- msg
		}
		close(lines)
		exited <- cmd.Wait()
	}()
	t.Cleanup(func() {
		stdin.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	var mu sync.Mutex
	pending := map[float64]map[string]any{}
	rl := &bundleRelay{stderr: stderr, exited: exited}
	rl.send = func(s string) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = io.WriteString(stdin, s+"\n")
	}
	var recvMu sync.Mutex
	rl.recv = func(id float64) map[string]any {
		t.Helper()
		recvMu.Lock()
		defer recvMu.Unlock()
		if msg, ok := pending[id]; ok {
			delete(pending, id)
			return msg
		}
		timeout := time.After(90 * time.Second)
		for {
			select {
			case msg, ok := <-lines:
				if !ok {
					t.Fatalf("relay exited; stderr:\n%s", stderr.String())
				}
				mid, isNum := msg["id"].(float64)
				if !isNum {
					continue
				}
				if mid == id {
					return msg
				}
				pending[mid] = msg
			case <-timeout:
				t.Fatalf("no response %v; stderr:\n%s", id, stderr.String())
			}
		}
	}
	return rl
}

// TestClaudeDesktopRelayAgainstGate runs the relay of a downloaded bundle,
// as Claude Desktop does, against the real /mcp handler. The browser sign-in
// is covered by internal/mcpb/relay.test.js; here the token is already saved.
func TestClaudeDesktopRelayAgainstGate(t *testing.T) {
	e := mcpEnv(t, false)
	rl := startBundleRelay(t, e, e.token("writer"))
	send, recv, stderr := rl.send, rl.recv, rl.stderr

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-desktop-test","version":"0"}}}`)
	init := recv(1)
	if res, _ := init["result"].(map[string]any); res == nil || res["serverInfo"].(map[string]any)["name"] != "dns-gate" || res["instructions"] == nil {
		t.Fatalf("initialize: %v", init)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if res, _ := recv(2)["result"].(map[string]any); res == nil || len(res["tools"].([]any)) == 0 {
		t.Fatalf("tools/list: %v", res)
	}
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_zones","arguments":{}}}`)
	call := recv(3)
	res, _ := call["result"].(map[string]any)
	if res == nil || res["isError"] == true || !strings.Contains(mustJSON(res["structuredContent"]), "example.com") {
		t.Fatalf("list_zones: %v", call)
	}
	if strings.Contains(stderr.String(), "visit ") {
		t.Fatalf("browser sign-in requested with a saved token:\n%s", stderr.String())
	}
}

// lockedBuffer collects the stderr of a child process safely.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
