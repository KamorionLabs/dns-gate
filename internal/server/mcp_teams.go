package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

type getTeamIn struct {
	Team string `json:"team" jsonschema:"team name, as listed by list_teams"`
}

type transferListIn struct {
	Zone   string `json:"zone,omitempty" jsonschema:"managed zone; all the transfers you may see when omitted"`
	Status string `json:"status,omitempty" jsonschema:"proposed (the inbox), applying (approved, being applied or retried), applied, rejected, expired or failed"`
	Limit  int    `json:"limit,omitempty" jsonschema:"1 to 500, default 50"`
	Cursor string `json:"cursor,omitempty"`
}

type transferProposeIn struct {
	Zone    string           `json:"zone" jsonschema:"managed zone name"`
	RRsets  []uiapi.RRsetRef `json:"rrsets" jsonschema:"RRsets (host and type) owned by one team, or reserved for it by a tombstone"`
	ToTeam  string           `json:"to_team" jsonschema:"team that will own them"`
	Comment string           `json:"comment" jsonschema:"why they move, read by the approver"`
	Team    string           `json:"team,omitempty" jsonschema:"one of your teams to act for (list_teams), your teams when omitted"`
}

type transferDecideIn struct {
	ID      string `json:"id" jsonschema:"transfer id, e.g. tr-1780000000000-0a1b2c3d4e"`
	Comment string `json:"comment,omitempty"`
}

type explainOut struct {
	uiapi.ExplainResponse
	// Teams are the teams of the simulated subject, its default team first.
	Teams       []string `json:"teams"`
	DefaultTeam string   `json:"default_team,omitempty"`
	// Owner is the owner team of the RRset (host and type given, managed
	// zone); ReservedFor the team a tombstone reserves it for.
	Owner       string `json:"owner,omitempty"`
	ReservedFor string `json:"reserved_for,omitempty"`
	Ownership   string `json:"ownership,omitempty"`
}

// forTeam narrows the subject of a tool call to one of its teams; "" keeps
// it. A team the subject is not a member of is refused and audited.
func (m *mcpServer) forTeam(ctx context.Context, req *mcp.CallToolRequest, subj *identity.Subject, tool, zone, team string) (*identity.Subject, error) {
	out, e := forTeam(subj, team)
	if e != nil {
		m.audit(ctx, req, subj, tool, zone, "deny", e.reason, map[string]any{"team": team})
		return nil, fmt.Errorf("%s: %s", e.reason, e.msg)
	}
	return out, nil
}

// withTeam adds the selected team to audit details.
func withTeam(extra map[string]any, team string) map[string]any {
	if team != "" {
		extra["team"] = team
	}
	return extra
}

func untilText(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ownershipNote tells the caller whether and why it may change an RRset.
func (m *mcpServer) ownershipNote(subj *identity.Subject, zone string, unmanaged bool, rs *uiapi.RRset, tb *uiapi.Tombstone) string {
	reserved := ""
	if tb != nil {
		if slices.Contains(subj.Teams, tb.Team) {
			reserved = fmt.Sprintf("deleted recently: reserved for team %s, one of your teams, until %s", tb.Team, untilText(tb.ExpiresAt))
		} else {
			reserved = fmt.Sprintf("deleted recently: reserved for team %s until %s; only that team may create or adopt it again, others ask for a transfer (transfer_propose)", tb.Team, untilText(tb.ExpiresAt))
		}
	}
	switch {
	case unmanaged:
		return "the zone is not managed by the gate: read-only"
	case rs == nil:
		return reserved
	case rs.ReadOnly != "":
		return "read-only at the DNS provider (" + strings.ReplaceAll(rs.ReadOnly, "_", " ") + "): the gate does not write it"
	case rs.Protected:
		return "protected by the base policy: no role changes it through the gate"
	case rs.Status == uiapi.StatusForeign:
		if reserved != "" {
			return "not managed by the gate; " + reserved
		}
		return "not managed by the gate: adopt it first (adopt_preview, dns.record.adopt)"
	case rs.Status == uiapi.StatusTainted || rs.Status == uiapi.StatusMissing:
		return fmt.Sprintf("owned by team %s but changed outside the gate: writes are blocked until it is adopted again", rs.Owner)
	case rs.Status == uiapi.StatusPending:
		return fmt.Sprintf("owned by team %s; a write is being confirmed, wait for the next read of the zone", rs.Owner)
	case !slices.Contains(subj.Teams, rs.Owner):
		mine := "none"
		if len(subj.Teams) > 0 {
			mine = strings.Join(subj.Teams, ", ")
		}
		return fmt.Sprintf("owned by team %s: you are not a member (your teams: %s); ask for a transfer (transfer_propose), approved by another person who may write it through team %s or holds dns.ownership.approve on it", rs.Owner, mine, rs.Owner)
	case !m.s.cfg.Authz.AllowRRset(subj, policy.ActionRecordWrite, zone, dns.Key{Host: rs.Host, Type: rs.Type}):
		return fmt.Sprintf("owned by team %s, one of your teams, but your roles do not grant dns.record.write on it", rs.Owner)
	}
	return fmt.Sprintf("owned by team %s, one of your teams: you may change it", rs.Owner)
}

// explainOwnership adds to a policy simulation the teams of the simulated
// subject and the owner of the RRset.
func (m *mcpServer) explainOwnership(ctx context.Context, in explainIn, claims map[string]any) explainOut {
	snap := m.s.cfg.Policy.Current()
	zone := normZoneArg(in.Zone)
	out := explainOut{ExplainResponse: snap.Explain(in.Issuer, claims, in.Action, zone, in.Host, in.Type), Teams: []string{}}
	if strings.HasPrefix(out.Denied, "unknown issuer") || strings.HasPrefix(out.Denied, "issuer bound_claims") {
		return out
	}
	out.Teams = append(out.Teams, snap.Resolve(in.Issuer, claims).Teams...)
	for _, is := range m.s.cfg.Config.Issuers {
		if is.Name != in.Issuer || is.TeamClaim == "" {
			continue
		}
		for _, t := range policy.ClaimStrings(claims[is.TeamClaim]) {
			t = strings.ToLower(t)
			if t != "" && !slices.Contains(out.Teams, t) && (!snap.StrictTeams() || snap.KnownTeam(t)) {
				out.Teams = append(out.Teams, t)
			}
		}
	}
	if len(out.Teams) > 0 {
		out.DefaultTeam = out.Teams[0]
	}
	if in.Host == "" || in.Type == "" || !m.s.pol.Managed(zone) {
		return out
	}
	host, typ := strings.ToLower(strings.TrimSpace(in.Host)), strings.ToUpper(strings.TrimSpace(in.Type))
	if m.s.cfg.Ownership != nil {
		if list, err := m.s.cfg.Ownership.List(ctx, zone); err == nil {
			for _, o := range list {
				if o.Host == host && strings.EqualFold(o.Type, typ) {
					out.Owner = o.Owner
				}
			}
		}
	}
	if out.Owner == "" && m.s.cfg.Tombstones != nil {
		if list, err := m.s.cfg.Tombstones.ListTombstones(ctx, zone); err == nil {
			for _, t := range list {
				if t.Host == host && strings.EqualFold(t.Type, typ) && m.s.now().Before(t.ExpiresAt) {
					out.ReservedFor = t.Team
				}
			}
		}
	}
	switch {
	case out.Owner != "" && slices.Contains(out.Teams, out.Owner):
		out.Ownership = "owned by team " + out.Owner + ", one of the subject's teams"
	case out.Owner != "":
		out.Ownership = "owned by team " + out.Owner + ": the subject is not a member, its writes are refused (not_owner)"
	case out.ReservedFor != "" && slices.Contains(out.Teams, out.ReservedFor):
		out.Ownership = "deleted recently and reserved for team " + out.ReservedFor + ", one of the subject's teams"
	case out.ReservedFor != "":
		out.Ownership = "deleted recently and reserved for team " + out.ReservedFor + ": the subject may not create or adopt it (not_owner)"
	case out.DefaultTeam != "":
		out.Ownership = "not owned by a team: created by the subject, it would belong to its default team " + out.DefaultTeam
	}
	return out
}

// addTeamTools adds list_teams, get_team and, with transfers, transfer_list.
func (m *mcpServer) addTeamTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_teams",
		Description: "List the teams that own RRsets: declared in the policy, referenced without being declared, derived from claims (families), or only found in the ownership store, with their roles and the number of RRsets they own in the zones you can read. Your own teams are in the teams field of the answer, your default team (the one new RRsets go to) first.",
		Annotations: readOnly("List teams"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, teamsOut, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, teamsOut{}, err
		}
		readable := m.readable(subj)
		if len(readable) == 0 {
			return nil, teamsOut{}, errors.New("no readable zone")
		}
		out := teamsOut{TeamList: m.s.teamList(ctx, subj, readable), MyTeams: append([]string{}, subj.Teams...)}
		m.audit(ctx, req, subj, "list_teams", "", "allow", "", nil)
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_team",
		Description: "Describe a team: description, origin, members (with policy.read), roles and their rules per zone (with policy.read or as a member), RRsets and tombstones it owns per readable zone, and its pending transfers.",
		Annotations: readOnly("Get team"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getTeamIn) (*mcp.CallToolResult, uiapi.TeamDetail, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.TeamDetail{}, err
		}
		readable := m.readable(subj)
		if len(readable) == 0 {
			return nil, uiapi.TeamDetail{}, errors.New("no readable zone")
		}
		d, ok := m.s.teamDetail(ctx, subj, readable, strings.ToLower(strings.TrimSpace(in.Team)))
		if !ok {
			return nil, uiapi.TeamDetail{}, fmt.Errorf("unknown team %q", in.Team)
		}
		m.audit(ctx, req, subj, "get_team", "", "allow", "", map[string]any{"team": d.Name})
		return nil, *d, nil
	})

	if m.s.cfg.Transfers == nil {
		return
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "transfer_list",
		Description: "List the ownership transfer requests you may see, newest first: status proposed is the inbox (can_decide marks the ones you may approve or reject). A transfer is approved by another person (never the requester, even under another identity; humans only unless the gate allows machine approvers) who, for every RRset of the request, may write it through the roles of the owner team or holds dns.ownership.approve on it; a team rename by another policy.approve holder with dns.ownership.approve on every RRset of the team. Status applying: approved and being applied, retried by the gate in the background (error holds the last transient error).",
		Annotations: readOnly("List transfers"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in transferListIn) (*mcp.CallToolResult, uiapi.TransferPage, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.TransferPage{}, err
		}
		q := store.TransferQuery{Zone: normZoneArg(in.Zone), Status: in.Status, Cursor: in.Cursor, Limit: 50}
		switch q.Status {
		case "", uiapi.TransferProposed, uiapi.TransferApplying, uiapi.TransferApplied, uiapi.TransferRejected, uiapi.TransferExpired, uiapi.TransferFailed:
		default:
			return nil, uiapi.TransferPage{}, errors.New("status must be proposed, applying, applied, rejected, expired or failed")
		}
		if in.Limit > 0 {
			q.Limit = min(in.Limit, 500)
		}
		page, err := m.s.cfg.Transfers.ListTransfers(ctx, subj, q)
		if err != nil {
			return nil, uiapi.TransferPage{}, toolError(err)
		}
		m.audit(ctx, req, subj, "transfer_list", q.Zone, "allow", "", nil)
		return nil, *page, nil
	})
}

type teamsOut struct {
	uiapi.TeamList
	// MyTeams are the caller's teams, its default team first.
	MyTeams []string `json:"my_teams"`
}

// addTransferWriteTools adds the tools that propose and decide transfers.
func (m *mcpServer) addTransferWriteTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "transfer_propose",
		Description: "Ask for the transfer of RRsets of a zone to another team: every RRset must be owned by the same team (or reserved for it by a tombstone). For every RRset, you must be allowed to write it through the roles of one of the two teams, or hold dns.ownership.approve on it. Nothing moves until another person approves (transfer_approve): someone who, for every RRset, may write it through the roles of the owner team or holds dns.ownership.approve on it; humans only unless the gate allows machine approvers. A comment is required.",
		Annotations: &mcp.ToolAnnotations{Title: "Propose a transfer", DestructiveHint: ptr(false), IdempotentHint: false, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in transferProposeIn) (*mcp.CallToolResult, uiapi.Transfer, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, uiapi.Transfer{}, err
		}
		zone := normZoneArg(in.Zone)
		if !m.s.pol.Managed(zone) {
			return nil, uiapi.Transfer{}, fmt.Errorf("zone %q is not managed by the gate", zone)
		}
		if subj, err = m.forTeam(ctx, req, subj, "transfer_propose", zone, in.Team); err != nil {
			return nil, uiapi.Transfer{}, err
		}
		if e := m.s.stepUp(subj, nil); e != nil {
			return nil, uiapi.Transfer{}, errors.New(e.msg)
		}
		t, err := m.s.cfg.Transfers.ProposeTransfer(ctx, subj, zone, uiapi.TransferProposal{RRsets: in.RRsets, ToTeam: strings.ToLower(strings.TrimSpace(in.ToTeam)), Comment: in.Comment})
		if err != nil {
			m.audit(ctx, req, subj, "transfer_propose", zone, "deny", reasonOf(err), withTeam(map[string]any{"to_team": in.ToTeam}, in.Team))
			return nil, uiapi.Transfer{}, toolError(err)
		}
		m.audit(ctx, req, subj, "transfer_propose", zone, "allow", "", withTeam(map[string]any{"transfer_id": t.ID}, in.Team))
		return nil, *t, nil
	})

	decide := func(approve bool) func(context.Context, *mcp.CallToolRequest, transferDecideIn) (*mcp.CallToolResult, uiapi.Transfer, error) {
		tool := "transfer_reject"
		if approve {
			tool = "transfer_approve"
		}
		return func(ctx context.Context, req *mcp.CallToolRequest, in transferDecideIn) (*mcp.CallToolResult, uiapi.Transfer, error) {
			subj, err := m.subject(ctx, req)
			if err != nil {
				return nil, uiapi.Transfer{}, err
			}
			if e := m.s.stepUp(subj, nil); e != nil {
				return nil, uiapi.Transfer{}, errors.New(e.msg)
			}
			t, err := m.s.cfg.Transfers.DecideTransfer(ctx, subj, strings.TrimSpace(in.ID), approve, in.Comment)
			if err != nil {
				m.audit(ctx, req, subj, tool, "", "deny", reasonOf(err), map[string]any{"transfer_id": in.ID})
				if ze, ok := zonewrite.AsError(err); ok && t != nil {
					if t.Status == uiapi.TransferApplying {
						return nil, uiapi.Transfer{}, fmt.Errorf("%s: %s (transfer %s is approved and applying: the gate retries it in the background, check it later with transfer_list)", ze.Reason, ze.Message, t.ID)
					}
					return nil, uiapi.Transfer{}, fmt.Errorf("%s: %s (transfer %s is %s)", ze.Reason, ze.Message, t.ID, t.Status)
				}
				return nil, uiapi.Transfer{}, toolError(err)
			}
			m.audit(ctx, req, subj, tool, t.Zone, "allow", "", map[string]any{"transfer_id": t.ID, "status": t.Status})
			return nil, *t, nil
		}
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "transfer_approve",
		Description: "Approve a proposed transfer (transfer_list, can_decide): the RRsets move to the target team at once, if none changed since the request; otherwise the transfer fails. When the zone is locked or the store or provider is unavailable, the transfer stays applying and the gate retries it in the background. Allowed to another person than the requester (even under another identity), humans only unless the gate allows machine approvers, who for every RRset may write it through the roles of the owner team or holds dns.ownership.approve on it; a team rename needs another policy.approve holder with dns.ownership.approve on every RRset of the team. Confirm with the user first.",
		Annotations: &mcp.ToolAnnotations{Title: "Approve a transfer", DestructiveHint: ptr(true), IdempotentHint: false, OpenWorldHint: ptr(false)},
	}, decide(true))
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "transfer_reject",
		Description: "Reject a proposed transfer, or withdraw your own request. Same rule as transfer_approve, except that the requester may withdraw. A comment saying why helps the requester.",
		Annotations: &mcp.ToolAnnotations{Title: "Reject a transfer", DestructiveHint: ptr(false), IdempotentHint: false, OpenWorldHint: ptr(false)},
	}, decide(false))
}
