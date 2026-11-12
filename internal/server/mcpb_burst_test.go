package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

// TestRelayBurstAgainstGate sends a burst of parallel tool calls through the
// relay, as an agent fanning out list_rrsets does, against the gate with the
// default MCP rate limit: the relay waits for the limit instead of failing.
func TestRelayBurstAgainstGate(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 120}
	})
	rl := startBundleRelay(t, e, e.token("writer"))
	rl.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"burst","version":"0"}}}`)
	rl.recv(1)
	rl.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	const n = 50
	for i := 0; i < n; i++ {
		rl.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"list_zones","arguments":{}}}`, 100+i))
	}
	failed := map[string]int{}
	for i := 0; i < n; i++ {
		msg := rl.recv(float64(100 + i))
		if res, _ := msg["result"].(map[string]any); res == nil || res["isError"] == true {
			failed[mustJSON(msg["error"])+mustJSON(msg["result"])]++
		}
	}
	if len(failed) > 0 {
		t.Errorf("calls failed in a burst of %d: %v", n, failed)
	}
	rl.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	rl.recv(2)
	if strings.Contains(rl.stderr.String(), "unexpected error") {
		t.Errorf("relay error:\n%s", rl.stderr.String())
	}
}

// TestMCPRateLimitRetryAfter checks that a refused MCP request says when
// the next one is accepted, rather than a fixed delay.
func TestMCPRateLimitRetryAfter(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 60}
	})
	tok := e.token("writer")
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	for i := 0; i < 20; i++ { // a burst of 15 at 60 per minute
		r := e.do(t, "POST", "/mcp", tok, body, hdr)
		r.Body.Close()
		if r.StatusCode == http.StatusTooManyRequests {
			if got := r.Header.Get("Retry-After"); got != "1" {
				t.Fatalf("Retry-After = %q, want 1 (one token per second)", got)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q", ct)
			}
			return
		}
	}
	t.Fatal("no 429 after the burst")
}
