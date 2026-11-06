package server

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

func teamsEnv(t *testing.T, declared bool) *env {
	return newEnvWith(t, func(c *config.Config) {
		c.Bindings = append(c.Bindings, config.Binding{Role: "writer", Team: "edge", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"writer"}}}}})
		if declared {
			c.Teams = map[string]config.Team{
				"web":  {Description: "Web shop"},
				"ops":  {Description: "Operations"},
				"edge": {Description: "Edge"},
			}
		}
	})
}

func (e *env) lastTeams() []string {
	e.ops.mu.Lock()
	defer e.ops.mu.Unlock()
	if len(e.ops.teams) == 0 {
		return nil
	}
	return e.ops.teams[len(e.ops.teams)-1]
}

func TestMeDefaultTeamAndTeamHeader(t *testing.T) {
	e := teamsEnv(t, true)
	tok := e.token("writer")
	r := e.do(t, "GET", "/api/v1/me", tok, "", map[string]string{TeamHeader: "edge"})
	var me uiapi.Me
	_ = json.NewDecoder(r.Body).Decode(&me)
	if me.DefaultTeam != "web" || strings.Join(me.Teams, ",") != "web,edge" {
		t.Fatalf("me: %+v", me)
	}
	if r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, map[string]string{TeamHeader: "ops"}); r.StatusCode != 403 || reason(t, r) != "not_team_member" {
		t.Fatalf("foreign team: %d", r.StatusCode)
	}
	if r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, map[string]string{TeamHeader: "edge"}); r.StatusCode != 200 {
		t.Fatalf("own team: %d", r.StatusCode)
	}
	if got := e.lastTeams(); strings.Join(got, ",") != "edge" {
		t.Fatalf("write teams %v", got)
	}
	if r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", tok, `{"ttl":600,"values":["192.0.2.1"]}`, nil); r.StatusCode != 200 || strings.Join(e.lastTeams(), ",") != "web,edge" {
		t.Fatalf("default: %d %v", r.StatusCode, e.lastTeams())
	}
}

func TestPlanApplyTeam(t *testing.T) {
	e := teamsEnv(t, true)
	tok := e.token("writer")
	body := `{"changes":[{"host":"api","type":"A","values":["192.0.2.1"]}],"team":"edge"}`
	r := e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, body, nil)
	var plan uiapi.PlanResult
	_ = json.NewDecoder(r.Body).Decode(&plan)
	if r.StatusCode != 200 || plan.PlanID == "" || plan.Team != "edge" || strings.Join(e.lastTeams(), ",") != "edge" {
		t.Fatalf("plan: %d %+v %v", r.StatusCode, plan, e.lastTeams())
	}
	if r := e.do(t, "POST", "/api/v1/zones/example.com/apply", tok, `{"plan_id":"`+plan.PlanID+`","team":"web"}`, nil); r.StatusCode != 400 || reason(t, r) != "team_mismatch" {
		t.Fatalf("mismatch: %d", r.StatusCode)
	}
	r = e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, body, nil)
	_ = json.NewDecoder(r.Body).Decode(&plan)
	r = e.do(t, "POST", "/api/v1/zones/example.com/apply", tok, `{"plan_id":"`+plan.PlanID+`"}`, nil)
	var res uiapi.PlanResult
	_ = json.NewDecoder(r.Body).Decode(&res)
	if r.StatusCode != 200 || res.Team != "edge" || strings.Join(e.lastTeams(), ",") != "edge" {
		t.Fatalf("apply for the plan team: %d %+v %v", r.StatusCode, res, e.lastTeams())
	}
	if r := e.do(t, "POST", "/api/v1/zones/example.com/plan", tok, strings.Replace(body, `"edge"`, `"ops"`, 1), nil); r.StatusCode != 403 || reason(t, r) != "not_team_member" {
		t.Fatalf("plan for a foreign team: %d", r.StatusCode)
	}
}

func TestTeamsEndpoints(t *testing.T) {
	e := teamsEnv(t, false)
	ctx := context.Background()
	now := time.Now()
	for _, o := range []store.Ownership{
		{Zone: "example.com", Host: "www", Type: "A", Owner: "web", State: store.StateActive, CreatedAt: now, UpdatedAt: now},
		{Zone: "example.com", Host: "old", Type: "A", Owner: "legacy", State: store.StateActive, CreatedAt: now, UpdatedAt: now},
	} {
		if err := e.store.Put(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	_ = e.store.PutTombstone(ctx, store.Tombstone{Zone: "example.com", Host: "gone", Type: "A", Team: "web", DeletedAt: now, ExpiresAt: now.Add(time.Hour)})
	e.server.cfg.Tombstones = e.store
	tok := e.token("writer")
	r := e.do(t, "GET", "/api/v1/teams", tok, "", nil)
	var list uiapi.TeamList
	_ = json.NewDecoder(r.Body).Decode(&list)
	kinds := map[string]string{}
	for _, ti := range list.Teams {
		kinds[ti.Name] = ti.Kind
	}
	if r.StatusCode != 200 || list.Strict || kinds["web"] != uiapi.TeamKindAuto || kinds["legacy"] != uiapi.TeamKindStore {
		t.Fatalf("teams: %d %+v", r.StatusCode, list)
	}
	r = e.do(t, "GET", "/api/v1/teams/web", tok, "", nil)
	var d uiapi.TeamDetail
	_ = json.NewDecoder(r.Body).Decode(&d)
	if r.StatusCode != 200 || len(d.Owned) != 1 || d.Owned[0].RRsets != 1 || d.Owned[0].Tombstones != 1 || d.Roles[0] != "writer" {
		t.Fatalf("team detail: %d %+v", r.StatusCode, d)
	}
	if r := e.do(t, "GET", "/api/v1/teams/nobody", tok, "", nil); r.StatusCode != 404 {
		t.Fatalf("unknown team: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/teams", e.token("stranger"), "", nil); r.StatusCode != 403 {
		t.Fatalf("no binding: %d", r.StatusCode)
	}
}

type fakeTransfers struct {
	proposed []uiapi.TransferProposal
	subjects []*identity.Subject
	fail     error
}

func (f *fakeTransfers) ProposeTransfer(ctx context.Context, s *identity.Subject, zone string, req uiapi.TransferProposal) (*uiapi.Transfer, error) {
	f.proposed = append(f.proposed, req)
	f.subjects = append(f.subjects, s)
	return &uiapi.Transfer{ID: "tr-1", Kind: uiapi.TransferKindRRsets, Zone: zone, ToTeam: req.ToTeam, Status: uiapi.TransferProposed}, nil
}

func (f *fakeTransfers) ProposeRename(ctx context.Context, s *identity.Subject, from string, req uiapi.TeamRenameRequest) (*uiapi.Transfer, error) {
	return &uiapi.Transfer{ID: "tr-2", Kind: uiapi.TransferKindRename, FromTeam: from, ToTeam: req.To, Status: uiapi.TransferProposed}, nil
}

func (f *fakeTransfers) GetTransfer(ctx context.Context, s *identity.Subject, id string) (*uiapi.Transfer, error) {
	if id != "tr-1" {
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonNotFound, Message: "unknown transfer"}
	}
	return &uiapi.Transfer{ID: id, Status: uiapi.TransferProposed}, nil
}

func (f *fakeTransfers) ListTransfers(ctx context.Context, s *identity.Subject, q store.TransferQuery) (*uiapi.TransferPage, error) {
	return &uiapi.TransferPage{Transfers: []uiapi.Transfer{{ID: "tr-1", Zone: q.Zone, Status: q.Status, FromTeam: "web"}}}, nil
}

func (f *fakeTransfers) DecideTransfer(ctx context.Context, s *identity.Subject, id string, approve bool, comment string) (*uiapi.Transfer, error) {
	if f.fail != nil {
		return &uiapi.Transfer{ID: id, Status: uiapi.TransferFailed, Error: "changed"}, f.fail
	}
	st := uiapi.TransferRejected
	if approve {
		st = uiapi.TransferApplied
	}
	return &uiapi.Transfer{ID: id, Status: st, DecisionComment: comment}, nil
}

func TestTransferRoutes(t *testing.T) {
	e := teamsEnv(t, true)
	tok := e.token("writer")
	if r := e.do(t, "GET", "/api/v1/transfers", tok, "", nil); r.StatusCode != 501 {
		t.Fatalf("without transfers: %d", r.StatusCode)
	}
	ft := &fakeTransfers{}
	e.server.cfg.Transfers = ft
	r := e.do(t, "POST", "/api/v1/zones/example.com/transfers", tok, `{"rrsets":[{"host":"www","type":"A"}],"to_team":"ops","comment":"move"}`, map[string]string{TeamHeader: "edge"})
	var tr uiapi.Transfer
	_ = json.NewDecoder(r.Body).Decode(&tr)
	if r.StatusCode != 201 || tr.ID != "tr-1" || len(ft.proposed) != 1 || strings.Join(ft.subjects[0].Teams, ",") != "edge" {
		t.Fatalf("propose: %d %+v", r.StatusCode, tr)
	}
	if r := e.do(t, "POST", "/api/v1/zones/example.com/transfers", tok, `{"rrsets":[],"to":"ops"}`, nil); r.StatusCode != 400 || reason(t, r) != "invalid" {
		t.Fatalf("unknown field: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/api/v1/zones/unknown.example/transfers", tok, `{}`, nil); r.StatusCode != 404 {
		t.Fatalf("unmanaged zone: %d", r.StatusCode)
	}
	r = e.do(t, "GET", "/api/v1/transfers?zone=example.com&status=proposed", tok, "", nil)
	var page uiapi.TransferPage
	_ = json.NewDecoder(r.Body).Decode(&page)
	if r.StatusCode != 200 || len(page.Transfers) != 1 || page.Transfers[0].Zone != "example.com" {
		t.Fatalf("list: %d %+v", r.StatusCode, page)
	}
	if r := e.do(t, "GET", "/api/v1/transfers?status=done", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("bad status: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/transfers/tr-9", tok, "", nil); r.StatusCode != 404 {
		t.Fatalf("unknown: %d", r.StatusCode)
	}
	r = e.do(t, "POST", "/api/v1/transfers/tr-1/approve", tok, `{"comment":"ok"}`, nil)
	_ = json.NewDecoder(r.Body).Decode(&tr)
	if r.StatusCode != 200 || tr.Status != uiapi.TransferApplied || tr.DecisionComment != "ok" {
		t.Fatalf("approve: %d %+v", r.StatusCode, tr)
	}
	ft.fail = &zonewrite.Error{Reason: zonewrite.ReasonPrecondition, Message: "www A changed since the request"}
	r = e.do(t, "POST", "/api/v1/transfers/tr-1/approve", tok, "", nil)
	var failed struct {
		Reason   string          `json:"reason"`
		Transfer *uiapi.Transfer `json:"transfer"`
	}
	_ = json.NewDecoder(r.Body).Decode(&failed)
	if r.StatusCode != 412 || failed.Reason != "precondition" || failed.Transfer == nil || failed.Transfer.Status != uiapi.TransferFailed {
		t.Fatalf("failed apply: %d %+v", r.StatusCode, failed)
	}
	ft.fail = &zonewrite.Error{Reason: zonewrite.ReasonExpired, Message: "expired"}
	if r := e.do(t, "POST", "/api/v1/transfers/tr-1/reject", tok, "", nil); r.StatusCode != 410 {
		t.Fatalf("expired: %d", r.StatusCode)
	}
	r = e.do(t, "POST", "/api/v1/teams/web/rename", tok, `{"to":"edge","comment":"merge"}`, nil)
	_ = json.NewDecoder(r.Body).Decode(&tr)
	if r.StatusCode != 201 || tr.Kind != uiapi.TransferKindRename || tr.FromTeam != "web" {
		t.Fatalf("rename: %d %+v", r.StatusCode, tr)
	}
}

func TestProposeKeepsActiveTeams(t *testing.T) {
	e := policyEnv(t, false)
	carol := e.human("carol", time.Minute)
	doc := managedDoc("*.staging")
	doc.Teams = map[string]uiapi.Team{"ops-eu": {Description: "Ops Europe", Members: uiapi.TeamMembers{Groups: []string{"operators"}}}}
	r, d := propose(t, e, carol, "", doc)
	if r.StatusCode != 201 {
		t.Fatalf("propose: %d %s", r.StatusCode, r.Header.Get("X-Test-Reason"))
	}
	if code, _ := post(t, e, carol, "/api/v1/policy/revisions/"+d.ID+"/activate"); code != 200 {
		t.Fatalf("activate: %d", code)
	}
	_, d2 := propose(t, e, carol, d.ID, managedDoc("*.dev"))
	if _, ok := d2.Document.Teams["ops-eu"]; !ok {
		t.Fatalf("teams dropped by a proposal without them: %+v", d2.Document.Teams)
	}
	empty := managedDoc("*.dev")
	empty.Teams = map[string]uiapi.Team{}
	b, _ := json.Marshal(uiapi.ProposeRequest{ParentID: d.ID, Document: empty, Comment: "drop teams"})
	r = e.do(t, "POST", "/api/v1/policy/revisions", carol, strings.Replace(string(b), `"groups"`, `"teams":{},"groups"`, 1), nil)
	var d3 uiapi.RevisionDetail
	_ = json.NewDecoder(r.Body).Decode(&d3)
	if r.StatusCode != 201 || len(d3.Document.Teams) != 0 {
		t.Fatalf("explicit empty teams: %d %+v", r.StatusCode, d3.Document.Teams)
	}
}

type brokenRevision struct{}

func (brokenRevision) ActiveRevision(context.Context) (*store.PolicyRevision, error) {
	return &store.PolicyRevision{ID: "rev-broken", Document: []byte(`{"groups":{},"roles":{},"bindings":[{"role":"ghost","team":"web","groups":["nobody"]}],"virtual_keys":[]}`)}, nil
}

func TestHealthReportsAnUnloadedManagedPolicy(t *testing.T) {
	e := policyEnv(t, true)
	if err := e.holder.Refresh(context.Background(), brokenRevision{}); err == nil {
		t.Fatal("an invalid revision loaded")
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		r := e.do(t, "GET", path, "", "", nil)
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 || !strings.Contains(string(b), "managed policy not served") || strings.Contains(string(b), "rev-broken") || strings.Contains(string(b), "ghost") {
			t.Fatalf("%s must report the problem without its details: %d %q", path, r.StatusCode, b)
		}
	}
	r := e.do(t, "GET", "/api/v1/policy", e.human("alice", time.Minute, "Gate.PolicyAdmin"), "", nil)
	var eff uiapi.EffectivePolicy
	_ = json.NewDecoder(r.Body).Decode(&eff)
	if r.StatusCode != 200 || !strings.Contains(eff.LoadError, "rev-broken") {
		t.Fatalf("policy.read holders get the details: %d %q", r.StatusCode, eff.LoadError)
	}
}
