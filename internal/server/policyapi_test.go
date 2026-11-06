package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func policyEnv(t *testing.T, requireApproval bool) *env {
	return newEnvWith(t, func(c *config.Config) {
		c.Issuers[0].CategoryClaim = "kind"
		c.Issuers[0].CategoryMap = map[string]string{"user": "human"}
		c.Roles["padmin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose", "policy.approve"}}}}
		c.Roles["proposer"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose"}}}}
		c.Groups = map[string]config.Group{"admins": {Members: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"roles": {"Gate.PolicyAdmin"}}}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "padmin", Team: "dns", Groups: []string{"admins"}},
			config.Binding{Role: "proposer", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"carol", "ci"}}}}},
		)
		c.Policy = config.Policy{
			Editable: true, RequireApproval: &requireApproval, EditMaxAge: config.Duration(15 * time.Minute),
			Bounds: config.Bounds{Zones: []string{"example.com"}, Actions: []string{policy.ActionDNSRead, policy.ActionRecordWrite, policy.ActionUIRead}},
		}
	})
}

// human returns a token for a human who authenticated age ago.
func (e *env) human(sub string, age time.Duration, roles ...string) string {
	r := make([]any, len(roles))
	for i, x := range roles {
		r[i] = x
	}
	return e.idp.Sign(map[string]any{"sub": sub, "aud": "dns-gate", "kind": "user", "email": sub + "@example.com", "roles": r, "auth_time": time.Now().Add(-age).Unix()})
}

func (e *env) pipeline(sub string) string {
	return e.idp.Sign(map[string]any{"sub": sub, "aud": "dns-gate"})
}

func managedDoc(host string) uiapi.PolicyDocument {
	return uiapi.PolicyDocument{
		Groups: map[string]uiapi.Group{"operators": {Members: []uiapi.SubjectMatcher{{Issuer: "idp", Claims: map[string][]string{"roles": {"Gate.Operator"}}}}}},
		Roles: map[string]uiapi.Role{"web-writer": {Rules: []uiapi.Rule{{
			Zones: []string{"example.com"}, Actions: []string{policy.ActionRecordWrite},
			Records: &uiapi.RecordScope{Hosts: []string{host}, Types: []string{"CNAME"}},
		}}}},
		Bindings: []uiapi.Binding{{Role: "web-writer", Team: "web", Groups: []string{"operators"}}},
	}
}

func propose(t *testing.T, e *env, tok, parent string, doc uiapi.PolicyDocument) (*http.Response, uiapi.RevisionDetail) {
	t.Helper()
	b, _ := json.Marshal(uiapi.ProposeRequest{ParentID: parent, Document: doc, Comment: "test"})
	r := e.do(t, "POST", "/api/v1/policy/revisions", tok, string(b), nil)
	var raw json.RawMessage
	_ = json.NewDecoder(r.Body).Decode(&raw)
	var d uiapi.RevisionDetail
	_ = json.Unmarshal(raw, &d)
	var eb errorBody
	_ = json.Unmarshal(raw, &eb)
	r.Header.Set("X-Test-Reason", eb.Reason)
	return r, d
}

func post(t *testing.T, e *env, tok, path string) (int, string) {
	t.Helper()
	r := e.do(t, "POST", path, tok, `{"comment":"ok"}`, nil)
	return r.StatusCode, reason(t, r)
}

func TestPolicyWorkflow(t *testing.T) {
	e := policyEnv(t, true)
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	bob := e.human("bob", time.Minute, "Gate.PolicyAdmin")

	r, d := propose(t, e, alice, "", managedDoc("*.staging"))
	if r.StatusCode != 201 || d.Status != uiapi.RevisionProposed || d.Author.Subject != "idp:alice" || d.DiffYAML == "" || d.Stale {
		t.Fatalf("propose: %d %+v", r.StatusCode, d.RevisionSummary)
	}
	base := "/api/v1/policy/revisions/" + d.ID
	if code, why := post(t, e, alice, base+"/approve"); code != 403 || why != "self_approval" {
		t.Fatalf("self approval: %d %s", code, why)
	}
	if code, why := post(t, e, alice, base+"/activate"); code != 409 || why != "approval_required" {
		t.Fatalf("activate before approval: %d %s", code, why)
	}
	if code, _ := post(t, e, bob, base+"/approve"); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if code, why := post(t, e, bob, base+"/approve"); code != 409 || why != "already_decided" {
		t.Fatalf("double approval: %d %s", code, why)
	}
	if code, _ := post(t, e, bob, base+"/activate"); code != 200 {
		t.Fatalf("activate: %d", code)
	}
	if e.holder.Current().RevisionID != d.ID {
		t.Fatal("holder not refreshed after activation")
	}

	// The managed grant is effective.
	op := e.human("olga", time.Hour, "Gate.Operator")
	rr := e.do(t, "GET", "/api/v1/me", op, "", nil)
	var me uiapi.Me
	_ = json.NewDecoder(rr.Body).Decode(&me)
	if len(me.Groups) != 1 || me.Groups[0] != "operators" {
		t.Fatalf("me groups: %+v", me)
	}

	rr = e.do(t, "GET", "/api/v1/policy", alice, "", nil)
	var eff uiapi.EffectivePolicy
	_ = json.NewDecoder(rr.Body).Decode(&eff)
	if eff.Active == nil || eff.Active.ID != d.ID || eff.Managed == nil || !eff.Me.CanApprove || eff.Base.ConfigHash == "" && eff.Base.Zones == nil {
		t.Fatalf("effective: %+v", eff)
	}

	// Export and rollback.
	rr = e.do(t, "GET", base+"/export", alice, "", nil)
	var sb strings.Builder
	buf := make([]byte, 4096)
	n, _ := rr.Body.Read(buf)
	sb.Write(buf[:n])
	if !strings.Contains(sb.String(), "web-writer") || !strings.HasPrefix(rr.Header.Get("Content-Type"), "application/yaml") {
		t.Fatalf("export: %s", sb.String())
	}
	if code, _ := post(t, e, alice, base+"/rollback"); code != 201 {
		t.Fatalf("rollback: %d", code)
	}

	activations := 0
	for _, ev := range e.audit.events {
		if ev.Action == "policy.activate" && ev.Decision == "allow" && ev.Extra["revision_id"] == d.ID {
			activations++
		}
	}
	if activations != 1 {
		t.Fatal("activation not audited with its revision id")
	}
}

func TestPolicyStaleAndConcurrent(t *testing.T) {
	e := policyEnv(t, true)
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	bob := e.human("bob", time.Minute, "Gate.PolicyAdmin")
	carol := e.human("carol", time.Minute)

	_, p1 := propose(t, e, carol, "", managedDoc("a.staging"))
	_, p2 := propose(t, e, alice, "", managedDoc("b.staging"))
	_, p3 := propose(t, e, alice, "", managedDoc("c.staging"))
	for _, id := range []string{p1.ID, p2.ID, p3.ID} {
		if code, _ := post(t, e, bob, "/api/v1/policy/revisions/"+id+"/approve"); code != 200 {
			t.Fatalf("approve %s: %d", id, code)
		}
	}
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, id := range []string{p2.ID, p3.ID} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			codes[i], _ = post(t, e, bob, "/api/v1/policy/revisions/"+id+"/activate")
		}(i, id)
	}
	wg.Wait()
	if !((codes[0] == 200 && codes[1] == 409) || (codes[0] == 409 && codes[1] == 200)) {
		t.Fatalf("concurrent activation: %v", codes)
	}
	if code, why := post(t, e, bob, "/api/v1/policy/revisions/"+p1.ID+"/activate"); code != 409 || why != "stale_revision" {
		t.Fatalf("stale activation: %d %s", code, why)
	}
	if r, _ := propose(t, e, carol, "", managedDoc("d.staging")); r.StatusCode != 409 || r.Header.Get("X-Test-Reason") != "stale_revision" {
		t.Fatalf("stale proposal: %d", r.StatusCode)
	}
	rr := e.do(t, "GET", "/api/v1/policy/revisions/"+p1.ID, carol, "", nil)
	var d uiapi.RevisionDetail
	_ = json.NewDecoder(rr.Body).Decode(&d)
	if !d.Stale {
		t.Fatal("p1 should be reported stale")
	}
}

func TestPolicyStepUpAndPipelines(t *testing.T) {
	e := policyEnv(t, true)
	old := e.human("alice", time.Hour, "Gate.PolicyAdmin")
	if r, _ := propose(t, e, old, "", managedDoc("*.staging")); r.StatusCode != 403 || r.Header.Get("X-Test-Reason") != "reauth_required" {
		t.Fatalf("stale login: %d", r.StatusCode)
	}
	noAuthTime := e.idp.Sign(map[string]any{"sub": "alice", "aud": "dns-gate", "kind": "user", "roles": []any{"Gate.PolicyAdmin"}})
	if r, _ := propose(t, e, noAuthTime, "", managedDoc("*.staging")); r.StatusCode != 403 {
		t.Fatalf("no auth_time: %d", r.StatusCode)
	}
	ci := e.pipeline("ci")
	r, d := propose(t, e, ci, "", managedDoc("*.staging"))
	if r.StatusCode != 201 || d.Author.Category != "pipeline" {
		t.Fatalf("pipeline proposal: %d", r.StatusCode)
	}
	if code, why := post(t, e, ci, "/api/v1/policy/revisions/"+d.ID+"/approve"); code != 403 || why != "forbidden" {
		t.Fatalf("pipeline approval: %d %s", code, why)
	}
	if code, _ := post(t, e, ci, "/api/v1/policy/revisions/"+d.ID+"/reject"); code != 200 {
		t.Fatalf("author withdrawal: %d", code)
	}

	bad := managedDoc("*.staging")
	bad.Roles["web-writer"].Rules[0].Actions = []string{"policy.approve"}
	bb, _ := json.Marshal(uiapi.ProposeRequest{Document: bad})
	r = e.do(t, "POST", "/api/v1/policy/revisions", ci, string(bb), nil)
	var body errorBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	if r.StatusCode != 400 || body.Reason != "invalid_policy" || len(body.Errors) == 0 || body.Errors[0].Path != "roles.web-writer.rules[0].actions[0]" {
		t.Fatalf("invalid policy: %d %+v", r.StatusCode, body)
	}

	r = e.do(t, "POST", "/api/v1/policy/revisions", e.token("writer"), `{"parent_id":"","document":{}}`, nil)
	if r.StatusCode != 403 {
		t.Fatalf("propose without policy.propose: %d", r.StatusCode)
	}
}

func TestPolicyWithoutApproval(t *testing.T) {
	e := policyEnv(t, false)
	carol := e.human("carol", time.Minute)
	_, d := propose(t, e, carol, "", managedDoc("*.staging"))
	if code, _ := post(t, e, carol, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatalf("activate without approval: %d", code)
	}
}

func TestPolicyExplainWhoCanAndKeys(t *testing.T) {
	e := policyEnv(t, true)
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	bob := e.human("bob", time.Minute, "Gate.PolicyAdmin")
	_, d := propose(t, e, alice, "", managedDoc("*.staging"))

	req := `{"subject":{"issuer":"idp","claims":{"sub":["olga"],"roles":["Gate.Operator","X"]}},"action":"dns.record.write","zone":"example.com","host":"a.staging","type":"CNAME","revision_id":"` + d.ID + `"}`
	r := e.do(t, "POST", "/api/v1/policy/explain", alice, req, nil)
	var ex uiapi.ExplainResponse
	_ = json.NewDecoder(r.Body).Decode(&ex)
	if !ex.Allowed || ex.Layer != "managed" || ex.Groups[0] != "operators" {
		t.Fatalf("explain proposal: %+v", ex)
	}
	r = e.do(t, "POST", "/api/v1/policy/explain", alice, strings.Replace(req, `,"revision_id":"`+d.ID+`"`, "", 1), nil)
	_ = json.NewDecoder(r.Body).Decode(&ex)
	if ex.Allowed {
		t.Fatal("explain on the active policy must deny (proposal not active)")
	}
	r = e.do(t, "GET", "/api/v1/policy/who-can?zone=example.com&host=a.staging&type=CNAME&revision_id="+d.ID, bob, "", nil)
	var wc uiapi.WhoCanResponse
	_ = json.NewDecoder(r.Body).Decode(&wc)
	found := false
	for _, en := range wc.Entries {
		found = found || (en.Role == "web-writer" && en.Layer == "managed")
	}
	if !found {
		t.Fatalf("who-can: %+v", wc)
	}

	r = e.do(t, "POST", "/api/v1/policy/virtual-keys/generate", alice, "", nil)
	var k uiapi.GeneratedKey
	_ = json.NewDecoder(r.Body).Decode(&k)
	sum := sha256.Sum256([]byte(k.Key))
	if r.StatusCode != 200 || len(k.Key) < 40 || k.KeySHA256 != hex.EncodeToString(sum[:]) || !strings.HasPrefix(k.AppID, "vk-") {
		t.Fatalf("generate: %d %+v", r.StatusCode, k)
	}
	for _, ev := range e.audit.events {
		if ev.Action == "policy.generate_key" {
			if b, _ := json.Marshal(ev); strings.Contains(string(b), k.Key) {
				t.Fatal("generated key leaked in the audit log")
			}
		}
	}
}

func TestPolicyCSRFAndReauthLogin(t *testing.T) {
	e := policyEnv(t, true)
	e.idp.LoginClaims = map[string]any{"sub": "alice", "kind": "user", "roles": []any{"Gate.PolicyAdmin"}, "auth_time": time.Now().Unix()}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(e.srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d %s", resp.StatusCode, resp.Request.URL)
	}
	u, _ := url.Parse(e.srv.URL)
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "gate_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("csrf cookie not set at login")
	}
	b, _ := json.Marshal(uiapi.ProposeRequest{Document: managedDoc("*.staging")})
	send := func(token, origin string) int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/policy/revisions", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Gate-CSRF", token)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if code := send("", e.srv.URL); code != 403 {
		t.Fatalf("missing CSRF header: %d", code)
	}
	if code := send("forged", e.srv.URL); code != 403 {
		t.Fatalf("forged CSRF header: %d", code)
	}
	if code := send(csrf, "https://evil.example.net"); code != 403 {
		t.Fatalf("cross-origin: %d", code)
	}
	if code := send(csrf, e.srv.URL); code != 201 {
		t.Fatalf("valid mutation: %d", code)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noFollow.Get(e.srv.URL + "/auth/login?reauth=1&return_to=/ui/policy")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("prompt") != "login" || loc.Query().Get("max_age") != "900" {
		t.Fatalf("reauth redirect: %s", loc)
	}
}
