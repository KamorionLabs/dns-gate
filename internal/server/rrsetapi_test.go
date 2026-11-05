package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

func (e *env) lastApplied(t *testing.T) uiapi.RRsetChange {
	t.Helper()
	e.ops.mu.Lock()
	defer e.ops.mu.Unlock()
	if len(e.ops.applied) == 0 || len(e.ops.applied[len(e.ops.applied)-1]) != 1 {
		t.Fatalf("applied: %+v", e.ops.applied)
	}
	return e.ops.applied[len(e.ops.applied)-1][0]
}

func decode[T any](t *testing.T, r *http.Response) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRRsetGet(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/WWW/a", tok, "", nil)
	rs := decode[uiapi.RRset](t, r)
	want := dns.ContentHash(dns.RRset{Key: dns.Key{Host: "www", Type: "A"}})
	if r.StatusCode != 200 || rs.Hash != want || r.Header.Get("ETag") != `"`+want+`"` || rs.Values == nil {
		t.Fatalf("get: %d %q %+v", r.StatusCode, r.Header.Get("ETag"), rs)
	}
	for path, status := range map[string]int{
		"/api/v1/zones/example.com/rrsets/api/A":     404,
		"/api/v1/zones/example.org/rrsets/www/A":     403,
		"/api/v1/zones/example.com/rrsets/www/A-1":   400,
		"/api/v1/zones/example.com/rrsets/a.*/A":     400,
		"/api/v1/zones/example.com/rrsets/www/A/x":   404,
		"/api/v1/zones/example.com/rrsets//A":        404,
		"/api/v1/zones/not_a_zone/rrsets/www/A":      400,
		"/api/v1/zones/example.com/rrsets/*.app/TXT": 404,
	} {
		if r := e.do(t, "GET", path, tok, "", nil); r.StatusCode != status {
			t.Errorf("GET %s: %d, want %d", path, r.StatusCode, status)
		}
	}

	e.ops.version = 4
	r = e.do(t, "GET", "/api/v1/zones/example.com/rrsets", tok, "", nil)
	inv := decode[uiapi.ZoneInventory](t, r)
	if r.StatusCode != 200 || r.Header.Get("ETag") != `"v4"` || inv.RRsets[0].Hash != want {
		t.Fatalf("inventory: %d %q %+v", r.StatusCode, r.Header.Get("ETag"), inv)
	}
}

func TestRRsetPutDelete(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	e.ops.version = 3
	r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/App/cname", tok, `{"ttl":600,"values":["target.example.net."]}`, map[string]string{"If-None-Match": "*"})
	rs := decode[uiapi.RRset](t, r)
	c := e.lastApplied(t)
	if r.StatusCode != 200 || !c.MustNotExist || c.ExpectedHash != "" || c.Host != "app" || c.Type != "CNAME" || c.TTL != 600 || e.ops.calls[0] != 3 {
		t.Fatalf("create: %d %+v %v", r.StatusCode, c, e.ops.calls)
	}
	if rs.Host != "app" || rs.Hash == "" || r.Header.Get("ETag") != `"`+rs.Hash+`"` {
		t.Fatalf("create response: %q %+v", r.Header.Get("ETag"), rs)
	}

	r = e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.9"]}`, map[string]string{"If-Match": `W/"abc"`})
	if c = e.lastApplied(t); r.StatusCode != 200 || c.ExpectedHash != "abc" || c.MustNotExist || c.Values[0] != "192.0.2.9" {
		t.Fatalf("update: %d %+v", r.StatusCode, c)
	}

	r = e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/@/A", tok, `{"alias":{"target":"d1.cloudfront.net.","hosted_zone_id":"Z2FDTNDATAQYW2"}}`, nil)
	if c = e.lastApplied(t); r.StatusCode != 200 || c.Alias == nil || c.Alias.HostedZoneID != "Z2FDTNDATAQYW2" || c.Host != "@" {
		t.Fatalf("alias: %d %+v", r.StatusCode, c)
	}

	r = e.do(t, "DELETE", "/api/v1/zones/example.com/rrsets/www/A", tok, "", map[string]string{"If-Match": `"abc"`})
	if c = e.lastApplied(t); r.StatusCode != 204 || !c.Delete || c.ExpectedHash != "abc" {
		t.Fatalf("delete: %d %+v", r.StatusCode, c)
	}

	n := len(e.ops.applied)
	for _, tc := range []struct {
		method, path, body string
		hdr                map[string]string
		status             int
	}{
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"ttl":600}`, nil, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"],"alias":{"target":"x."}}`, nil, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"],"extra":1}`, nil, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"]}`, map[string]string{"If-Match": "*"}, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"]}`, map[string]string{"If-Match": `"a", "b"`}, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"]}`, map[string]string{"If-Match": `"a"`, "If-None-Match": "*"}, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"]}`, map[string]string{"If-None-Match": `"a"`}, 400},
		{"DELETE", "/api/v1/zones/example.com/rrsets/www/A", "", map[string]string{"If-None-Match": "*"}, 400},
		{"PUT", "/api/v1/zones/unknown.example/rrsets/www/A", `{"values":["192.0.2.1"]}`, nil, 404},
		{"POST", "/api/v1/zones/example.com/rrsets/www/A", `{}`, nil, 405},
		{"PUT", "/api/v1/zones/example.com/rrsets/www/A", `{"values":["192.0.2.1"]}`, map[string]string{"Authorization": ""}, 401},
	} {
		tk := tok
		if _, ok := tc.hdr["Authorization"]; ok {
			tk = ""
		}
		r := e.do(t, tc.method, tc.path, tk, tc.body, tc.hdr)
		if r.StatusCode != tc.status {
			t.Errorf("%s %s %s %v: %d, want %d", tc.method, tc.path, tc.body, tc.hdr, r.StatusCode, tc.status)
		}
		if tc.status == 400 && reason(t, r) != "invalid" {
			t.Errorf("%s %s %s: 400 reason is not invalid", tc.method, tc.path, tc.body)
		}
	}
	if len(e.ops.applied) != n {
		t.Fatalf("invalid requests reached the engine: %+v", e.ops.applied[n:])
	}
}

func TestRRsetErrorMapping(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	for _, tc := range []struct {
		reason zonewrite.Reason
		status int
		want   string
	}{
		{zonewrite.ReasonPrecondition, 412, "precondition"},
		{zonewrite.ReasonLocked, 423, "zone_locked"},
		{zonewrite.ReasonForeignRRset, 409, "foreign_rrset"},
		{zonewrite.ReasonTainted, 409, "tainted"},
		{zonewrite.ReasonNotOwner, 403, "not_owner"},
		{zonewrite.ReasonForbidden, 403, "forbidden"},
		{zonewrite.ReasonInvalid, 400, "invalid"},
		{zonewrite.ReasonUpstream, 502, "upstream"},
		{zonewrite.ReasonNotFound, 404, "not_found"},
	} {
		e.ops.applyErrs = []error{&zonewrite.Error{Reason: tc.reason, Message: "refused"}}
		r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, nil)
		if got := reason(t, r); r.StatusCode != tc.status || got != tc.want {
			t.Errorf("%s: %d %s, want %d %s", tc.reason, r.StatusCode, got, tc.status, tc.want)
		}
		if tc.reason == zonewrite.ReasonLocked && r.Header.Get("Retry-After") == "" {
			t.Error("zone_locked without Retry-After")
		}
	}
	e.ops.applyErrs = []error{errors.New("boom")}
	if r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, nil); r.StatusCode != 500 {
		t.Errorf("internal error: %d", r.StatusCode)
	}
}

func TestRRsetPutRetriesOnZoneVersionRace(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	e.ops.version = 10
	e.ops.applyErrs = []error{&zonewrite.Error{Reason: zonewrite.ReasonPrecondition, Message: "zone changed"}}
	e.ops.bumpOnErr = true
	r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, nil)
	if r.StatusCode != 200 || len(e.ops.calls) != 2 || e.ops.calls[0] != 10 || e.ops.calls[1] != 11 {
		t.Fatalf("retry: %d %v", r.StatusCode, e.ops.calls)
	}

	e.ops.calls = nil
	e.ops.bumpOnErr = false
	e.ops.applyErrs = []error{&zonewrite.Error{Reason: zonewrite.ReasonPrecondition, Message: "hash mismatch"}}
	r = e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, map[string]string{"If-Match": `"old"`})
	if r.StatusCode != 412 || len(e.ops.calls) != 1 {
		t.Fatalf("hash precondition must not be retried: %d %v", r.StatusCode, e.ops.calls)
	}
}

func TestRESTPlanApply(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) { c.MCP.PlanTTL = config.Duration(10 * time.Minute) })
	tok := e.token("writer")
	body := `{"changes":[{"host":"app","type":"CNAME","ttl":600,"values":["target.example.net."],"must_not_exist":true}]}`
	plan := func() uiapi.PlanResult {
		t.Helper()
		r := e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, body, nil)
		p := decode[uiapi.PlanResult](t, r)
		if r.StatusCode != 200 || !p.Allowed || !strings.HasPrefix(p.PlanID, "plan-") {
			t.Fatalf("plan: %d %+v", r.StatusCode, p)
		}
		return p
	}
	apply := func(tok, zone, id string) *http.Response {
		return e.do(t, "POST", "/api/v1/zones/"+zone+"/apply", tok, `{"plan_id":"`+id+`"}`, nil)
	}

	p := plan()
	if r := apply(e.token("admin"), "example.com", p.PlanID); r.StatusCode != 403 {
		t.Fatalf("foreign apply: %d", r.StatusCode)
	}
	r := apply(tok, "example.com", p.PlanID)
	res := decode[uiapi.PlanResult](t, r)
	if r.StatusCode != 200 || res.PlanID != p.PlanID || !e.lastApplied(t).MustNotExist {
		t.Fatalf("apply: %d %+v", r.StatusCode, res)
	}
	if r := apply(tok, "example.com", p.PlanID); r.StatusCode != 404 || reason(t, r) != "not_found" {
		t.Fatalf("reused plan: %d", r.StatusCode)
	}

	p = plan()
	if r := apply(tok, "example.org", p.PlanID); r.StatusCode != 404 {
		t.Fatalf("plan applied to another zone: %d", r.StatusCode)
	}

	p = plan()
	e.ops.version += 2
	if r := apply(tok, "example.com", p.PlanID); r.StatusCode != 412 || reason(t, r) != "precondition" {
		t.Fatalf("stale plan: %d", r.StatusCode)
	}

	p = plan()
	e.offset = 11 * time.Minute
	if r := apply(tok, "example.com", p.PlanID); r.StatusCode != 410 || reason(t, r) != "plan_expired" {
		t.Fatalf("expired plan: %d", r.StatusCode)
	}
	e.offset = 0

	for _, b := range []string{`{"changes":[]}`, `{}`, `{"changes":[{"host":"a","type":"A"}],"x":1}`} {
		if r := e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, b, nil); r.StatusCode != 400 {
			t.Errorf("plan %s: %d", b, r.StatusCode)
		}
	}
	if r := e.do(t, "POST", "/api/v1/zones/unknown.example/plan", tok, body, nil); r.StatusCode != 404 {
		t.Errorf("plan on an unmanaged zone: %d", r.StatusCode)
	}
	if r := apply(tok, "example.com", ""); r.StatusCode != 400 {
		t.Errorf("apply without plan_id: %d", r.StatusCode)
	}

	found := map[string]bool{}
	for _, ev := range e.audit.events {
		if ev.Extra["via"] == "api" {
			found[ev.Action+"/"+ev.Decision] = true
		}
	}
	for _, want := range []string{"api.plan/allow", "api.apply/allow", "api.apply/deny", "api.apply/error"} {
		if !found[want] {
			t.Errorf("audit event %s missing: %v", want, found)
		}
	}
}

func TestPlansSharedAcrossInstances(t *testing.T) {
	e := newEnv(t)
	other, err := New(e.server.cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(other.Handler())
	t.Cleanup(srv2.Close)
	tok := e.token("writer")
	r := e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, `{"changes":[{"host":"app","type":"A","ttl":600,"values":["192.0.2.1"]}]}`, nil)
	p := decode[uiapi.PlanResult](t, r)
	req, _ := http.NewRequest("POST", srv2.URL+"/api/v1/zones/example.com/apply", strings.NewReader(`{"plan_id":"`+p.PlanID+`"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("plan of instance 1 applied on instance 2: %d", resp.StatusCode)
	}
}

func TestRRsetSessionMutations(t *testing.T) {
	e := newEnvWith(t, func(c *config.Config) {
		c.Policy.EditMaxAge = config.Duration(15 * time.Minute)
		c.Issuers[0].CategoryClaim = "kind"
		c.Issuers[0].CategoryMap = map[string]string{"user": "human"}
	})
	e.idp.LoginClaims = map[string]any{"sub": "writer", "kind": "user", "auth_time": time.Now().Unix()}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(e.srv.URL + "/auth/login")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v %v", err, resp)
	}
	resp.Body.Close()
	u, _ := url.Parse(e.srv.URL)
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "gate_csrf" {
			csrf = c.Value
		}
	}
	send := func(token string) int {
		req, _ := http.NewRequest("PUT", e.srv.URL+"/api/v1/zones/example.com/rrsets/www/A", strings.NewReader(`{"ttl":600,"values":["192.0.2.1"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", e.srv.URL)
		if token != "" {
			req.Header.Set("X-Gate-CSRF", token)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if code := send(""); code != 403 || len(e.ops.applied) != 0 {
		t.Fatalf("session PUT without CSRF: %d", code)
	}
	if code := send(csrf); code != 200 || len(e.ops.applied) != 1 {
		t.Fatalf("session PUT with CSRF: %d", code)
	}
	e.offset = time.Hour
	if code := send(csrf); code != 403 || len(e.ops.applied) != 1 {
		t.Fatalf("session PUT without a recent login: %d", code)
	}
}

func TestGateInfoFeatures(t *testing.T) {
	e := newEnv(t)
	r := e.do(t, "GET", GateInfoPath, "", "", nil)
	var info struct{ Features []string }
	_ = json.NewDecoder(r.Body).Decode(&info)
	if !contains(info.Features, FeatureRRsetAPI) || !contains(info.Features, FeaturePlans) {
		t.Fatalf("features: %v", info.Features)
	}
}
