package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines(t *testing.T) []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, l := range bytes.Split(bytes.TrimSpace(b.buf.Bytes()), []byte{'\n'}) {
		if len(l) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// TestAuditRequestContext drives real requests through the server and checks
// the stdout lines: request context of every event, the same event id in the
// store, and the published JSON Schema.
func TestAuditRequestContext(t *testing.T) {
	e := newEnv(t)
	out := &syncBuffer{}
	jl, err := audit.NewJSONWith(out, audit.Options{HashChain: true})
	if err != nil {
		t.Fatal(err)
	}
	e.server.cfg.Audit = &audit.Tee{Primary: jl, Store: appender{e.audit}}

	ua := map[string]string{"User-Agent": "terraform-provider-eurodns/0.4 " + strings.Repeat("x", 400)}
	e.do(t, "GET", "/dns-zones/example.com", "", "", ua)
	e.do(t, "GET", "/dns-zones/example.org", e.token("writer"), "", ua)
	e.do(t, "GET", "/dns-zones/example.com", "", "", map[string]string{"X-App-Id": "app", "X-Api-Key": "nope", "User-Agent": "lego"})

	e.idp.LoginClaims = map[string]any{"sub": "writer", "email": "writer@example.com"}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(e.srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	u, _ := url.Parse(e.srv.URL)
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == csrfCookie {
			csrf = c.Value
		}
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/zones/example.com/plan", strings.NewReader(`{"changes":[{"host":"www","type":"A","ttl":300,"values":["192.0.2.9"]}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gate-CSRF", csrf)
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("User-Agent", "browser")
	if resp, err = client.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	lines := out.lines(t)
	want := []struct{ action, decision, reason, method, ua string }{
		{"getDnsZone", "deny", "unauthenticated", "", "terraform-provider-eurodns/0.4 "},
		{"getDnsZone", "deny", "forbidden", "oidc", "terraform-provider-eurodns/0.4 "},
		{"getDnsZone", "deny", "unauthenticated", "virtual-key", "lego"},
		{"api.plan", "allow", "", "oidc-session", "browser"},
	}
	if len(lines) != len(want) {
		t.Fatalf("%d lines: %v", len(lines), lines)
	}
	rs := loadAuditSchema(t)
	for i, w := range want {
		l := lines[i]
		if err := rs.Validate(l); err != nil {
			t.Errorf("line %d does not match the schema: %v\n%v", i, err, l)
		}
		am, _ := l["auth_method"].(string)
		if l["action"] != w.action || l["decision"] != w.decision || l["source_ip"] != "127.0.0.1" || am != w.method ||
			!strings.HasPrefix(l["user_agent"].(string), w.ua) || len(l["user_agent"].(string)) > audit.MaxUserAgent {
			t.Errorf("line %d: %v", i, l)
		}
		if w.reason != "" && l["reason"] != w.reason {
			t.Errorf("line %d reason: %v", i, l["reason"])
		}
		stored := e.audit.events[i]
		if stored.EventID != l["event_id"] || stored.SourceIP != "127.0.0.1" || stored.AuthMethod != w.method {
			t.Errorf("store event %d: %+v", i, stored)
		}
	}
	var buf bytes.Buffer
	for _, l := range lines {
		b, _ := json.Marshal(l)
		buf.Write(append(b, '\n'))
	}
	if rep, err := audit.Verify(&buf); err != nil || !rep.OK() || rep.Chains[0].Events != len(want) {
		t.Fatalf("chain: %+v %v", rep, err)
	}
}

type appender struct{ m *memAudit }

func (a appender) AppendAudit(ctx context.Context, e audit.Event) error {
	a.m.Log(ctx, e)
	return nil
}

func loadAuditSchema(t *testing.T) *jsonschema.Resolved {
	t.Helper()
	raw, err := os.ReadFile("../../api/audit-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
