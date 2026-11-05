package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

const (
	workloadsSC = "sc://org/proj/workloads-pipelines"
	pipelineX   = "sc://org/proj/dns-gate-x"
	teamRegex   = "^sc://[^/]+/[^/]+/(dns-gate-[a-z0-9-]+)$"
)

func delegationEnv(t *testing.T, requireApproval bool) *env {
	return newEnvWith(t, func(c *config.Config) {
		c.Issuers[0].CategoryClaim = "kind"
		c.Issuers[0].CategoryMap = map[string]string{"user": "human"}
		c.Roles["padmin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose", "policy.approve"}}}}
		c.Roles["proposer"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose"}}}}
		c.Roles["apps-writer"] = config.Role{Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{policy.ActionRecordWrite}, Records: &config.RecordScope{Hosts: []string{"*.apps"}, Types: []string{"CNAME"}}}}}
		c.Groups = map[string]config.Group{"admins": {Members: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"roles": {"Gate.PolicyAdmin"}}}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "padmin", Team: "dns", Groups: []string{"admins"}},
			config.Binding{Role: "proposer", Team: "web", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"carol"}}}}},
		)
		c.Policy = config.Policy{
			Editable: true, RequireApproval: &requireApproval, EditMaxAge: config.Duration(15 * time.Minute),
			Bounds: config.Bounds{Zones: []string{"example.com", "example.org"}, Actions: []string{policy.ActionDNSRead, policy.ActionRecordWrite, policy.ActionRecordAdopt, policy.ActionUIRead}},
			Delegations: []config.Delegation{{
				Name:     "workloads-pipelines",
				Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {workloadsSC}}}},
				Allow: config.DelegationAllow{
					Zones:           []string{"example.com"},
					Actions:         []string{policy.ActionDNSRead, policy.ActionRecordWrite, policy.ActionUIRead},
					Records:         &config.RecordScope{Hosts: []string{"**.apps"}, Types: []string{"CNAME", "TXT"}},
					BindingSubjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"sc://org/proj/dns-gate-*"}}}},
					Teams:           config.DelegationTeams{FromSubject: &config.TeamFrom{Claim: "sub", Regex: teamRegex}},
					Roles:           []string{"apps-writer"},
					MaxObjects:      6,
				},
			}},
		}
	})
}

func pipelineRole(host string) string {
	return fmt.Sprintf(`{"rules":[{"zones":["example.com"],"actions":["dns.read","dns.record.write"],"records":{"hosts":[%q],"types":["CNAME"]}}],"managed_by":"terraform"}`, host)
}

func pipelineBinding(role, sub, team string) string {
	return fmt.Sprintf(`{"role":%q,"team":%q,"subjects":[{"issuer":"idp","claims":{"sub":[%q]}}],"managed_by":"terraform"}`, role, team, sub)
}

func (e *env) put(t *testing.T, tok, path, body string, hdr map[string]string) (*http.Response, uiapi.DelegatedResult, errorBody) {
	t.Helper()
	r := e.do(t, "PUT", path, tok, body, hdr)
	var raw json.RawMessage
	_ = json.NewDecoder(r.Body).Decode(&raw)
	var res uiapi.DelegatedResult
	var eb errorBody
	_ = json.Unmarshal(raw, &res)
	_ = json.Unmarshal(raw, &eb)
	return r, res, eb
}

func (e *env) auditActions() []string {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	var out []string
	for _, ev := range e.audit.events {
		out = append(out, ev.Action+":"+ev.Decision)
	}
	return out
}

func hasAction(actions []string, a string) bool {
	for _, x := range actions {
		if x == a {
			return true
		}
	}
	return false
}

func TestDelegatedRoleAndBinding(t *testing.T) {
	e := delegationEnv(t, true)
	ci := e.pipeline(workloadsSC)

	// The delegated subject has no binding: it authenticates through its delegation.
	r := e.do(t, "GET", "/api/v1/policy/delegated", ci, "", nil)
	var idx uiapi.DelegatedIndex
	_ = json.NewDecoder(r.Body).Decode(&idx)
	if r.StatusCode != 200 || len(idx.Delegations) != 1 || idx.Delegations[0].Name != "workloads-pipelines" {
		t.Fatalf("index: %d %+v", r.StatusCode, idx)
	}

	r, res, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), map[string]string{"If-None-Match": "*"})
	if r.StatusCode != 200 || !res.Changed || res.Object == nil || res.Object.Owner.Delegation != "workloads-pipelines" || res.Object.Owner.ManagedBy != "terraform" || res.Object.Owner.CreatedBy != "idp:"+workloadsSC {
		t.Fatalf("put role: %d %+v %+v", r.StatusCode, res, eb)
	}
	if e.holder.Current().RevisionID != res.RevisionID || r.Header.Get("ETag") != res.Object.ETag {
		t.Fatalf("revision not active without approval: %s vs %s", e.holder.Current().RevisionID, res.RevisionID)
	}
	roleETag := res.Object.ETag

	// Idempotent: the same body changes nothing and creates no revision.
	r, again, _ := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), nil)
	if r.StatusCode != 200 || again.Changed || again.RevisionID != res.RevisionID || again.Object.ETag != roleETag {
		t.Fatalf("idempotent put: %d %+v", r.StatusCode, again)
	}
	// Create-only on an existing role, and a stale If-Match.
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), map[string]string{"If-None-Match": "*"}); r.StatusCode != 412 || eb.Reason != "precondition" {
		t.Fatalf("if-none-match on existing: %d %s", r.StatusCode, eb.Reason)
	}
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("y.apps"), map[string]string{"If-Match": `"stale"`}); r.StatusCode != 412 || eb.Reason != "precondition" {
		t.Fatalf("stale if-match: %d %s", r.StatusCode, eb.Reason)
	}

	// Binding: team derived from the bound subject.
	r, bres, eb := e.put(t, ci, "/api/v1/policy/delegated/bindings/dns-gate-x", pipelineBinding("dns-gate-x", pipelineX, "dns-gate-x"), map[string]string{"If-None-Match": "*"})
	if r.StatusCode != 200 || !bres.Changed {
		t.Fatalf("put binding: %d %+v", r.StatusCode, eb)
	}
	// The same binding with team_from equal to the delegation rule is valid too.
	tf := fmt.Sprintf(`{"role":"dns-gate-x","team":"","team_from":{"claim":"sub","regex":%q},"subjects":[{"issuer":"idp","claims":{"sub":[%q]}}]}`, teamRegex, pipelineX)
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/bindings/dns-gate-x-tf", tf, nil); r.StatusCode != 200 {
		t.Fatalf("put binding team_from: %d %+v", r.StatusCode, eb)
	}

	// The bound pipeline gets the role and its own team; it can write x.apps CNAME only.
	snap := e.holder.Current()
	res2 := snap.Resolve("idp", map[string]any{"sub": pipelineX})
	if len(res2.Roles) != 1 || res2.Roles[0] != "dns-gate-x" || len(res2.Teams) != 1 || res2.Teams[0] != "dns-gate-x" {
		t.Fatalf("resolve: %+v", res2)
	}
	if !snap.Decide(res2.Roles, policy.ActionRecordWrite, "example.com", &dns.Key{Host: "x.apps", Type: "CNAME"}).Allowed {
		t.Fatal("bound pipeline cannot write its own name")
	}
	if snap.Decide(res2.Roles, policy.ActionRecordWrite, "example.com", &dns.Key{Host: "y.apps", Type: "CNAME"}).Allowed {
		t.Fatal("bound pipeline can write another name")
	}
	me := e.do(t, "GET", "/api/v1/me", e.pipeline(pipelineX), "", nil)
	if me.StatusCode != 200 {
		t.Fatalf("bound pipeline /me: %d", me.StatusCode)
	}

	// GET with ETag.
	r = e.do(t, "GET", "/api/v1/policy/delegated/bindings/dns-gate-x", ci, "", nil)
	var obj uiapi.DelegatedObject
	_ = json.NewDecoder(r.Body).Decode(&obj)
	if r.StatusCode != 200 || obj.Binding == nil || obj.Binding.Team != "dns-gate-x" || r.Header.Get("ETag") != obj.ETag {
		t.Fatalf("get binding: %d %+v", r.StatusCode, obj)
	}

	acts := e.auditActions()
	for _, want := range []string{"policy.delegated.put_role:allow", "policy.delegated.put_binding:allow", "policy.activate:allow", "policy.delegated.put_role:deny"} {
		if !hasAction(acts, want) {
			t.Errorf("audit %s missing: %v", want, acts)
		}
	}

	// Humans see the delegated objects and the revision diff names them.
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	r = e.do(t, "GET", "/api/v1/policy", alice, "", nil)
	var eff uiapi.EffectivePolicy
	_ = json.NewDecoder(r.Body).Decode(&eff)
	if eff.Managed == nil || eff.Managed.Delegated == nil || len(eff.Managed.Delegated.Roles) != 1 || len(eff.Base.Delegations) != 1 {
		t.Fatalf("effective policy: %+v", eff.Managed)
	}
	r = e.do(t, "GET", "/api/v1/policy/revisions/"+bres.RevisionID, alice, "", nil)
	var det uiapi.RevisionDetail
	_ = json.NewDecoder(r.Body).Decode(&det)
	if !strings.Contains(det.DiffYAML, "dns-gate-x") || det.Status != uiapi.RevisionSuperseded || det.Author.Subject != "idp:"+workloadsSC {
		t.Fatalf("revision detail: %s %s\n%s", det.Status, det.Author.Subject, det.DiffYAML)
	}

	// Delete: the role is still used by bindings.
	r = e.do(t, "DELETE", "/api/v1/policy/delegated/roles/dns-gate-x", ci, "", nil)
	if r.StatusCode != 400 || reason(t, r) != "invalid_policy" {
		t.Fatalf("delete used role: %d", r.StatusCode)
	}
	for _, p := range []string{"bindings/dns-gate-x", "bindings/dns-gate-x-tf", "roles/dns-gate-x"} {
		if r := e.do(t, "DELETE", "/api/v1/policy/delegated/"+p, ci, "", nil); r.StatusCode != 200 {
			t.Fatalf("delete %s: %d %s", p, r.StatusCode, reason(t, r))
		}
	}
	if r := e.do(t, "DELETE", "/api/v1/policy/delegated/roles/dns-gate-x", ci, "", nil); r.StatusCode != 404 {
		t.Fatalf("delete missing: %d", r.StatusCode)
	}
	if res := e.holder.Current().Resolve("idp", map[string]any{"sub": pipelineX}); len(res.Roles) != 0 {
		t.Fatalf("binding still effective after delete: %+v", res)
	}
}

func TestDelegatedLimits(t *testing.T) {
	e := delegationEnv(t, true)
	ci := e.pipeline(workloadsSC)
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/ok", pipelineRole("x.apps"), nil); r.StatusCode != 200 {
		t.Fatalf("setup: %d %+v", r.StatusCode, eb)
	}
	cases := []struct {
		name, path, body, reason string
	}{
		{"zone outside delegation", "roles/r1", `{"rules":[{"zones":["example.org"],"actions":["dns.record.write"],"records":{"hosts":["a.apps"],"types":["CNAME"]}}]}`, "invalid_policy"},
		{"action outside delegation", "roles/r2", `{"rules":[{"zones":["example.com"],"actions":["dns.record.adopt"],"records":{"hosts":["a.apps"],"types":["CNAME"]}}]}`, "invalid_policy"},
		{"policy action", "roles/r3", `{"rules":[{"zones":["example.com"],"actions":["policy.approve"],"records":{"hosts":["a.apps"],"types":["CNAME"]}}]}`, "invalid_policy"},
		{"host outside delegation", "roles/r4", pipelineRole("www"), "invalid_policy"},
		{"whole zone", "roles/r5", `{"rules":[{"zones":["example.com"],"actions":["dns.record.write"]}]}`, "invalid_policy"},
		{"type outside delegation", "roles/r6", `{"rules":[{"zones":["example.com"],"actions":["dns.record.write"],"records":{"hosts":["a.apps"],"types":["A"]}}]}`, "invalid_policy"},
		{"base role name", "roles/writer", pipelineRole("x.apps"), "name_taken"},
		{"subject outside delegation", "bindings/b1", pipelineBinding("ok", "sc://org/proj/other", "dns-gate-x"), "invalid_policy"},
		{"glob wider than delegation", "bindings/b2", pipelineBinding("ok", "sc://org/*", "dns-gate-x"), "invalid_policy"},
		{"team of another pipeline", "bindings/b3", pipelineBinding("ok", pipelineX, "dns-gate-y"), "invalid_policy"},
		{"fixed team outside names", "bindings/b4", pipelineBinding("ok", pipelineX, "web"), "invalid_policy"},
		{"other team_from", "bindings/b5", fmt.Sprintf(`{"role":"ok","team":"","team_from":{"claim":"sub","regex":"^(.+)$"},"subjects":[{"issuer":"idp","claims":{"sub":[%q]}}]}`, pipelineX), "invalid_policy"},
		{"base role not allowed", "bindings/b6", pipelineBinding("writer", pipelineX, "dns-gate-x"), "invalid_policy"},
		{"unknown field", "bindings/b7", `{"role":"ok","team":"x","bogus":1}`, "bad_request"},
	}
	for _, c := range cases {
		r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/"+c.path, c.body, nil)
		if r.StatusCode < 400 || eb.Reason != c.reason {
			t.Errorf("%s: %d %s %+v", c.name, r.StatusCode, eb.Reason, eb.Errors)
		}
	}
	// allow.roles: a base role within the delegation may be bound.
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/bindings/shared", pipelineBinding("apps-writer", pipelineX, "dns-gate-x"), nil); r.StatusCode != 200 {
		t.Fatalf("allowed base role: %d %+v", r.StatusCode, eb)
	}
	// max_objects: 6.
	for i := 0; i < 4; i++ {
		if r, _, eb := e.put(t, ci, fmt.Sprintf("/api/v1/policy/delegated/roles/n%d", i), pipelineRole("x.apps"), nil); r.StatusCode != 200 {
			t.Fatalf("role %d: %d %+v", i, r.StatusCode, eb)
		}
	}
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/n9", pipelineRole("x.apps"), nil); r.StatusCode != 400 || eb.Reason != "invalid_policy" {
		t.Fatalf("max_objects: %d %+v", r.StatusCode, eb)
	}

	// Identities outside the delegation.
	if r, _, eb := e.put(t, e.pipeline(pipelineX), "/api/v1/policy/delegated/roles/z", pipelineRole("x.apps"), nil); r.StatusCode != 403 {
		t.Fatalf("non-delegated subject: %d %+v", r.StatusCode, eb)
	}
	if r := e.do(t, "GET", "/api/v1/policy/delegated", e.pipeline("nobody"), "", nil); r.StatusCode != 403 {
		t.Fatalf("unbound subject: %d", r.StatusCode)
	}
	if !hasAction(e.auditActions(), "policy.delegated.put_binding:deny") {
		t.Error("denied delegated writes are not audited")
	}
}

func TestDelegatedObjectsAndHumans(t *testing.T) {
	e := delegationEnv(t, true)
	ci := e.pipeline(workloadsSC)
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	bob := e.human("bob", time.Minute, "Gate.PolicyAdmin")
	carol := e.human("carol", time.Minute)
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), nil); r.StatusCode != 200 {
		t.Fatalf("put role: %d %+v", r.StatusCode, eb)
	}
	_, res, _ := e.put(t, ci, "/api/v1/policy/delegated/bindings/dns-gate-x", pipelineBinding("dns-gate-x", pipelineX, "dns-gate-x"), nil)
	active := res.RevisionID

	// A human proposal from the UI omits the delegated section: it is kept.
	r, d := propose(t, e, alice, active, managedDoc("*.staging"))
	if r.StatusCode != 201 || d.Document.Delegated == nil || len(d.Document.Delegated.Roles) != 1 || strings.Contains(d.DiffYAML, "-      owner") {
		t.Fatalf("human proposal: %d %+v\n%s", r.StatusCode, d.Document.Delegated, d.DiffYAML)
	}
	if code, _ := post(t, e, bob, "/api/v1/policy/revisions/"+d.ID+"/approve"); code != 200 {
		t.Fatal("approve")
	}
	if code, why := post(t, e, bob, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatalf("activate: %d %s", code, why)
	}
	if res := e.holder.Current().Resolve("idp", map[string]any{"sub": pipelineX}); len(res.Roles) != 1 {
		t.Fatalf("delegated binding lost by a human activation: %+v", res)
	}
	active = d.ID

	// Changing a delegated object in a proposal is refused.
	doc := managedDoc("*.staging")
	doc.Delegated = &uiapi.DelegatedObjects{Roles: map[string]uiapi.DelegatedRole{}}
	if r, _ := propose(t, e, alice, active, doc); r.StatusCode != 403 || r.Header.Get("X-Test-Reason") != "delegated_object" {
		t.Fatalf("edit of delegated objects: %d %s", r.StatusCode, r.Header.Get("X-Test-Reason"))
	}
	// A managed binding cannot use a delegated role.
	doc = managedDoc("*.staging")
	doc.Bindings = append(doc.Bindings, uiapi.Binding{Role: "dns-gate-x", Team: "web", Groups: []string{"operators"}})
	if r, _ := propose(t, e, alice, active, doc); r.StatusCode != 400 {
		t.Fatalf("managed binding on a delegated role: %d", r.StatusCode)
	}

	// Take over: policy.approve only.
	takeOver := func(tok string) (*http.Response, uiapi.RevisionDetail) {
		doc := managedDoc("*.staging")
		doc.Roles["dns-gate-x"] = uiapi.Role{Rules: []uiapi.Rule{{Zones: []string{"example.com"}, Actions: []string{policy.ActionRecordWrite}, Records: &uiapi.RecordScope{Hosts: []string{"x.apps"}, Types: []string{"CNAME"}}}}}
		doc.Bindings = append(doc.Bindings, uiapi.Binding{Role: "dns-gate-x", Team: "dns-gate-x", Subjects: []uiapi.SubjectMatcher{{Issuer: "idp", Claims: map[string][]string{"sub": {pipelineX}}}}})
		b, _ := json.Marshal(uiapi.ProposeRequest{ParentID: active, Document: doc, Comment: "take over", TakeOver: []string{"roles/dns-gate-x", "bindings/dns-gate-x"}})
		r := e.do(t, "POST", "/api/v1/policy/revisions", tok, string(b), nil)
		var d uiapi.RevisionDetail
		_ = json.NewDecoder(r.Body).Decode(&d)
		return r, d
	}
	if r, _ := takeOver(carol); r.StatusCode != 403 {
		t.Fatalf("take over by a proposer: %d", r.StatusCode)
	}
	r, d = takeOver(alice)
	if r.StatusCode != 201 || d.Document.Delegated != nil {
		t.Fatalf("take over: %d %+v", r.StatusCode, d.Document.Delegated)
	}
	if !hasAction(e.auditActions(), "policy.delegated.take_over:allow") {
		t.Error("take over not audited")
	}
	_, _ = post(t, e, bob, "/api/v1/policy/revisions/"+d.ID+"/approve")
	if code, why := post(t, e, bob, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatalf("activate take over: %d %s", code, why)
	}
	// The pipeline no longer owns the objects.
	if r := e.do(t, "GET", "/api/v1/policy/delegated/roles/dns-gate-x", ci, "", nil); r.StatusCode != 404 {
		t.Fatalf("get taken over role: %d", r.StatusCode)
	}
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), map[string]string{"If-None-Match": "*"}); r.StatusCode != 409 || eb.Reason != "name_taken" {
		t.Fatalf("recreate taken over role: %d %s", r.StatusCode, eb.Reason)
	}
}

func TestDelegatedRollbackKeepsDelegatedObjects(t *testing.T) {
	e := delegationEnv(t, false)
	ci := e.pipeline(workloadsSC)
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	_, d := propose(t, e, alice, "", managedDoc("*.staging"))
	if code, _ := post(t, e, alice, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatal("activate")
	}
	_, res, _ := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), nil)
	r := e.do(t, "POST", "/api/v1/policy/revisions/"+d.ID+"/rollback", alice, `{"comment":"back"}`, nil)
	var rb uiapi.RevisionDetail
	_ = json.NewDecoder(r.Body).Decode(&rb)
	if r.StatusCode != 201 || rb.ParentID != res.RevisionID || rb.Document.Delegated == nil || len(rb.Document.Delegated.Roles) != 1 {
		t.Fatalf("rollback: %d %+v", r.StatusCode, rb.Document.Delegated)
	}
}

// TestPolicyAdminAloneWithoutApproval: with require_approval false a policy
// admin proposes and activates alone, and delegated writes never need it.
func TestPolicyAdminAloneWithoutApproval(t *testing.T) {
	e := delegationEnv(t, false)
	alice := e.human("alice", time.Minute, "Gate.PolicyAdmin")
	r, d := propose(t, e, alice, "", managedDoc("*.staging"))
	if r.StatusCode != 201 {
		t.Fatalf("propose: %d", r.StatusCode)
	}
	if code, why := post(t, e, alice, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatalf("admin activates alone: %d %s", code, why)
	}
	if e.holder.Current().RevisionID != d.ID {
		t.Fatal("not active")
	}
	// Still no self-approval, even when approval is optional.
	_, d2 := propose(t, e, alice, d.ID, managedDoc("*.dev"))
	if code, why := post(t, e, alice, "/api/v1/policy/revisions/"+d2.ID+"/approve"); code != 403 || why != "self_approval" {
		t.Fatalf("self approval: %d %s", code, why)
	}
	if code, _ := post(t, e, alice, "/api/v1/policy/revisions/"+d2.ID+"/activate"); code != 200 {
		t.Fatalf("activate second: %d", code)
	}
}

// conflictStore makes the first n activations lose a race, as when another
// replica activates a revision at the same time.
type conflictStore struct {
	store.Store
	mu sync.Mutex
	n  int
}

func (c *conflictStore) Activate(ctx context.Context, id, expected, by string, at time.Time) error {
	c.mu.Lock()
	lose := c.n > 0
	if lose {
		c.n--
	}
	c.mu.Unlock()
	if lose {
		return store.ErrConflict
	}
	return c.Store.Activate(ctx, id, expected, by, at)
}

func TestDelegatedConcurrency(t *testing.T) {
	e := delegationEnv(t, true)
	ci := e.pipeline(workloadsSC)
	cs := &conflictStore{Store: e.store, n: 2}
	e.server.cfg.PolicyStore = cs

	// Lost activations are retried server-side on the new active revision.
	if r, res, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-x", pipelineRole("x.apps"), nil); r.StatusCode != 200 || !res.Changed {
		t.Fatalf("put after conflicts: %d %+v", r.StatusCode, eb)
	}
	revs, _, _ := e.store.ListRevisions(context.Background(), uiapi.RevisionProposed, 50, "")
	if len(revs) != 0 {
		t.Fatalf("revisions that lost the race linger as proposals: %d", len(revs))
	}
	cs.mu.Lock()
	cs.n = maxDelegatedAttempts
	cs.mu.Unlock()
	if r, _, eb := e.put(t, ci, "/api/v1/policy/delegated/roles/dns-gate-y", pipelineRole("y.apps"), nil); r.StatusCode != 409 || eb.Reason != "policy_busy" {
		t.Fatalf("exhausted retries: %d %s", r.StatusCode, eb.Reason)
	}

	// Concurrent Terraform resources never lose an update.
	cs.mu.Lock()
	cs.n = 0
	cs.mu.Unlock()
	var wg sync.WaitGroup
	errs := make(chan string, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := pipelineBinding("dns-gate-x", fmt.Sprintf("sc://org/proj/dns-gate-p%d", i), fmt.Sprintf("dns-gate-p%d", i))
			req, _ := http.NewRequest("PUT", e.srv.URL+fmt.Sprintf("/api/v1/policy/delegated/bindings/p%d", i), strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+ci)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err.Error()
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				errs <- fmt.Sprintf("binding %d: %d", i, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	doc := e.holder.Current().Managed
	if doc == nil || doc.Delegated == nil || len(doc.Delegated.Bindings) != 5 {
		t.Fatalf("lost updates: %+v", doc)
	}
}

func TestDelegatedCSRFOnCookieSessions(t *testing.T) {
	e := delegationEnv(t, true)
	// PUT is now accepted on /api/v1/policy/delegated only.
	if r := e.do(t, "PUT", "/api/v1/policy/revisions", e.pipeline(workloadsSC), "{}", nil); r.StatusCode != 405 {
		t.Fatalf("PUT elsewhere: %d", r.StatusCode)
	}
}
