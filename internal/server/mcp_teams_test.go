package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

func mcpTeamsEnv(t *testing.T, writes bool) *env {
	return newEnvWith(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, AllowWrites: writes, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.Roles["auditor"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "ui.read"}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "writer", Team: "edge", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"writer"}}}}},
			config.Binding{Role: "auditor", Team: "ops", Subjects: []config.Subject{{Issuer: "idp", Claims: map[string]config.StringList{"sub": {"auditor"}}}}},
		)
		c.Teams = map[string]config.Team{"web": {Description: "Web shop"}, "ops": {Description: "Operations"}, "edge": {Description: "Edge"}}
	})
}

func TestMCPTeamTools(t *testing.T) {
	e := mcpTeamsEnv(t, false)
	ctx := context.Background()
	now := time.Now()
	if err := e.store.Put(ctx, store.Ownership{Zone: "example.com", Host: "www", Type: "A", Owner: "web", State: store.StateActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, e, e.token("writer"))
	tools := toolNames(t, cs)
	for _, n := range []string{"list_teams", "get_team"} {
		if tools[n] == nil || !tools[n].Annotations.ReadOnlyHint {
			t.Errorf("read tool %s missing or not read-only", n)
		}
	}
	if tools["transfer_list"] != nil || tools["transfer_propose"] != nil {
		t.Fatal("transfer tools without transfers")
	}
	var list teamsOut
	if res := call(t, cs, "list_teams", map[string]any{}, &list); res.IsError || strings.Join(list.MyTeams, ",") != "web,edge" || !list.Strict || list.RequireSecondApprover {
		t.Fatalf("list_teams: %s %+v", errText(res), list)
	}
	counts := map[string]int{}
	for _, ti := range list.Teams {
		counts[ti.Name] = ti.RRsets
		if ti.Members != nil {
			t.Fatalf("members without policy.read: %+v", ti)
		}
	}
	if counts["web"] != 1 || counts["edge"] != 0 {
		t.Fatalf("owned counts: %v", counts)
	}
	var d uiapi.TeamDetail
	if res := call(t, cs, "get_team", map[string]any{"team": "Web"}, &d); res.IsError || d.Description != "Web shop" || d.RRsets != 1 ||
		len(d.Owned) != 1 || d.Owned[0].Zone != "example.com" || len(d.Permissions) == 0 || d.Permissions[0].Role != "writer" {
		t.Fatalf("get_team of an own team: %s %+v", errText(res), d)
	}
	d = uiapi.TeamDetail{}
	if res := call(t, cs, "get_team", map[string]any{"team": "ops"}, &d); res.IsError || len(d.Permissions) != 0 {
		t.Fatalf("rules of another team without policy.read: %s %+v", errText(res), d)
	}
	if res := call(t, cs, "get_team", map[string]any{"team": "nobody"}, nil); !res.IsError || !strings.Contains(errText(res), "unknown team") {
		t.Fatalf("unknown team: %s", errText(res))
	}
	auditor := connect(t, e, e.token("auditor"))
	d = uiapi.TeamDetail{}
	if res := call(t, auditor, "get_team", map[string]any{"team": "web"}, &d); res.IsError || d.Members == nil || len(d.Permissions) == 0 {
		t.Fatalf("policy.read sees members and rules: %s %+v", errText(res), d)
	}
}

func TestMCPOwnershipInReads(t *testing.T) {
	e := mcpTeamsEnv(t, false)
	expires := time.Now().Add(time.Hour)
	e.engine.tombs = []uiapi.Tombstone{{Host: "old", Type: "A", Team: "ops", DeletedAt: time.Now(), ExpiresAt: expires}}
	ctx := context.Background()
	if err := e.store.Put(ctx, store.Ownership{Zone: "example.com", Host: "www", Type: "A", Owner: "web", State: store.StateActive}); err != nil {
		t.Fatal(err)
	}
	_ = e.store.PutTombstone(ctx, store.Tombstone{Zone: "example.com", Host: "old", Type: "A", Team: "ops", DeletedAt: time.Now(), ExpiresAt: expires})
	e.server.cfg.Tombstones = e.store

	cs := connect(t, e, e.token("writer"))
	var rs listRRsetsOut
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com"}, &rs); res.IsError || len(rs.Tombstones) != 1 || rs.Tombstones[0].Team != "ops" {
		t.Fatalf("list_rrsets tombstones: %s %+v", errText(res), rs)
	}
	rs = listRRsetsOut{}
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "owner": "web"}, &rs); res.IsError || len(rs.RRsets) != 1 || len(rs.Tombstones) != 0 {
		t.Fatalf("owner filter: %s %+v", errText(res), rs)
	}
	var got getRRsetOut
	if res := call(t, cs, "get_rrset", map[string]any{"zone": "example.com", "host": "www", "type": "A"}, &got); res.IsError ||
		got.RRset == nil || got.RRset.Owner != "web" || !strings.Contains(got.Ownership, "one of your teams: you may change it") {
		t.Fatalf("get_rrset own team: %s %+v", errText(res), got)
	}
	got = getRRsetOut{}
	if res := call(t, cs, "get_rrset", map[string]any{"zone": "example.com", "host": "old", "type": "A"}, &got); res.IsError ||
		got.Tombstone == nil || !strings.Contains(got.Ownership, "reserved for team ops") || !strings.Contains(got.Ownership, "transfer_propose") {
		t.Fatalf("get_rrset tombstone: %s %+v", errText(res), got)
	}

	auditor := connect(t, e, e.token("auditor"))
	got = getRRsetOut{}
	if res := call(t, auditor, "get_rrset", map[string]any{"zone": "example.com", "host": "www", "type": "A"}, &got); res.IsError ||
		!strings.Contains(got.Ownership, "you are not a member (your teams: ops)") {
		t.Fatalf("get_rrset of another team: %s %+v", errText(res), got)
	}
	var ex explainOut
	args := map[string]any{"issuer": "idp", "claims": map[string][]string{"sub": {"writer"}}, "action": "dns.record.write", "zone": "example.com", "host": "www", "type": "A"}
	if res := call(t, auditor, "explain", args, &ex); res.IsError || !ex.Allowed || strings.Join(ex.Teams, ",") != "web,edge" || ex.DefaultTeam != "web" ||
		ex.Owner != "web" || !strings.Contains(ex.Ownership, "one of the subject's teams") {
		t.Fatalf("explain own RRset: %s %+v", errText(res), ex)
	}
	args["host"] = "old"
	ex = explainOut{}
	if res := call(t, auditor, "explain", args, &ex); res.IsError || ex.ReservedFor != "ops" || !strings.Contains(ex.Ownership, "not_owner") {
		t.Fatalf("explain reserved RRset: %s %+v", errText(res), ex)
	}
}

func TestMCPWriteForTeam(t *testing.T) {
	e := mcpTeamsEnv(t, true)
	cs := connect(t, e, e.token("writer"))
	changes := []map[string]any{{"host": "app", "type": "CNAME", "ttl": 600, "values": []string{"target.example.net."}}}
	if res := call(t, cs, "plan_rrset_change", map[string]any{"zone": "example.com", "changes": changes, "team": "ops"}, nil); !res.IsError || !strings.Contains(errText(res), "not_team_member") {
		t.Fatalf("plan for a foreign team: %s", errText(res))
	}
	var plan uiapi.PlanResult
	if res := call(t, cs, "plan_rrset_change", map[string]any{"zone": "example.com", "changes": changes, "team": "edge"}, &plan); res.IsError || plan.Team != "edge" || strings.Join(e.lastTeams(), ",") != "edge" {
		t.Fatalf("plan for edge: %s %+v %v", errText(res), plan, e.lastTeams())
	}
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID, "team": "web"}, nil); !res.IsError || !strings.Contains(errText(res), "team_mismatch") {
		t.Fatalf("apply for another team: %s", errText(res))
	}
	call(t, cs, "plan_rrset_change", map[string]any{"zone": "example.com", "changes": changes, "team": "edge"}, &plan)
	var applied uiapi.PlanResult
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID}, &applied); res.IsError || applied.Team != "edge" || strings.Join(e.lastTeams(), ",") != "edge" {
		t.Fatalf("apply for the plan team: %s %+v %v", errText(res), applied, e.lastTeams())
	}
	call(t, cs, "plan_rrset_change", map[string]any{"zone": "example.com", "changes": changes}, &plan)
	if res := call(t, cs, "apply_rrset_change", map[string]any{"plan_id": plan.PlanID, "team": "edge"}, &applied); res.IsError || strings.Join(e.lastTeams(), ",") != "edge" {
		t.Fatalf("apply narrowing a default plan: %s %v", errText(res), e.lastTeams())
	}
	if res := call(t, cs, "adopt_preview", map[string]any{"zone": "example.com", "selection": map[string]any{"hosts": []string{"*"}}, "team": "ops"}, nil); !res.IsError || !strings.Contains(errText(res), "not_team_member") {
		t.Fatalf("adopt preview for a foreign team: %s", errText(res))
	}
	denied := false
	for _, ev := range e.audit.events {
		if ev.Action == "mcp.plan_rrset_change" && ev.Decision == "deny" && ev.Reason == "not_team_member" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("foreign team not audited")
	}
}

func TestMCPTransfers(t *testing.T) {
	e := mcpTeamsEnv(t, true)
	ft := &fakeTransfers{}
	e.server.cfg.Transfers = ft
	e.server.mcp = e.server.newMCP()
	cs := connect(t, e, e.token("writer"))
	tools := toolNames(t, cs)
	if tools["transfer_list"] == nil || !tools["transfer_list"].Annotations.ReadOnlyHint {
		t.Fatal("transfer_list missing or not read-only")
	}
	if a := tools["transfer_approve"]; a == nil || a.Annotations.ReadOnlyHint || a.Annotations.DestructiveHint == nil || !*a.Annotations.DestructiveHint {
		t.Fatalf("transfer_approve annotations: %+v", a)
	}
	var tr uiapi.Transfer
	args := map[string]any{"zone": "Example.com.", "rrsets": []map[string]string{{"host": "www", "type": "A"}}, "to_team": "Ops", "comment": "move", "team": "edge"}
	if res := call(t, cs, "transfer_propose", args, &tr); res.IsError || tr.ID != "tr-1" || tr.Zone != "example.com" || ft.proposed[0].ToTeam != "ops" ||
		strings.Join(ft.subjects[0].Teams, ",") != "edge" || ft.proposed[0].Apply {
		t.Fatalf("propose: %s %+v", errText(res), tr)
	}
	args["apply"] = true
	if res := call(t, cs, "transfer_propose", args, &tr); res.IsError || !ft.proposed[1].Apply {
		t.Fatalf("propose and apply: %s %+v", errText(res), ft.proposed)
	}
	delete(args, "apply")
	args["zone"] = "unknown.example"
	if res := call(t, cs, "transfer_propose", args, nil); !res.IsError || !strings.Contains(errText(res), "not managed") {
		t.Fatalf("unmanaged zone: %s", errText(res))
	}
	var page uiapi.TransferPage
	if res := call(t, cs, "transfer_list", map[string]any{"zone": "example.com", "status": "proposed"}, &page); res.IsError || len(page.Transfers) != 1 || page.Transfers[0].Zone != "example.com" {
		t.Fatalf("list: %s %+v", errText(res), page)
	}
	if res := call(t, cs, "transfer_list", map[string]any{"status": "done"}, nil); !res.IsError {
		t.Fatal("bad status accepted")
	}
	if res := call(t, cs, "transfer_list", map[string]any{"status": "applying"}, &page); res.IsError || page.Transfers[0].Status != uiapi.TransferApplying {
		t.Fatalf("applying filter: %s %+v", errText(res), page)
	}
	if res := call(t, cs, "transfer_approve", map[string]any{"id": "tr-1", "comment": "ok"}, &tr); res.IsError || tr.Status != uiapi.TransferApplied || tr.DecisionComment != "ok" {
		t.Fatalf("approve: %s %+v", errText(res), tr)
	}
	if res := call(t, cs, "transfer_reject", map[string]any{"id": "tr-1"}, &tr); res.IsError || tr.Status != uiapi.TransferRejected {
		t.Fatalf("reject: %s %+v", errText(res), tr)
	}
	ft.fail = &zonewrite.Error{Reason: zonewrite.ReasonPrecondition, Message: "www A changed since the request"}
	if res := call(t, cs, "transfer_approve", map[string]any{"id": "tr-1"}, nil); !res.IsError || !strings.Contains(errText(res), "precondition: www A changed since the request (transfer tr-1 is failed)") {
		t.Fatalf("failed apply: %s", errText(res))
	}
	ft.fail, ft.failStatus = &zonewrite.Error{Reason: zonewrite.ReasonLocked, Message: "zone locked"}, uiapi.TransferApplying
	if res := call(t, cs, "transfer_approve", map[string]any{"id": "tr-1"}, nil); !res.IsError || !strings.Contains(errText(res), "approved and applying: the gate retries it in the background") {
		t.Fatalf("applying: %s", errText(res))
	}

	ro := mcpTeamsEnv(t, false)
	ro.server.cfg.Transfers = ft
	ro.server.mcp = ro.server.newMCP()
	rtools := toolNames(t, connect(t, ro, ro.token("writer")))
	if rtools["transfer_list"] == nil || rtools["transfer_propose"] != nil || rtools["transfer_approve"] != nil {
		t.Fatal("transfer write tools exposed without allow_writes")
	}
}
