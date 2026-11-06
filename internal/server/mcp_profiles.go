package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

const profileToolNote = " Zone profiles are account-wide templates of a EuroDNS account (records, URL and mail forwards) that EuroDNS applies to a domain when it arrives, for example after a transfer; they name no domain. Requires dns.zone.profile on every zone (\"*\"), usually held by administrators only. provider is the id of a EuroDNS provider of the gate, optional when there is only one."

type profileListIn struct {
	Provider string `json:"provider,omitempty" jsonschema:"EuroDNS provider id; optional when the gate has one EuroDNS provider"`
}

type profileIDIn struct {
	Provider string `json:"provider,omitempty" jsonschema:"EuroDNS provider id; optional when the gate has one EuroDNS provider"`
	ID       int64  `json:"id" jsonschema:"zone profile id, as listed by list_zone_profiles"`
}

type profileWriteIn struct {
	Provider     string                    `json:"provider,omitempty" jsonschema:"EuroDNS provider id; optional when the gate has one EuroDNS provider"`
	ID           int64                     `json:"id,omitempty" jsonschema:"zone profile id; update_zone_profile only"`
	Name         string                    `json:"name" jsonschema:"profile name"`
	Records      []uiapi.ZoneProfileRecord `json:"records" jsonschema:"records of the profile, hosts relative to the domain"`
	URLForwards  []map[string]any          `json:"url_forwards,omitempty" jsonschema:"EuroDNS URL forwards: forwardType (FRAME, HTTP301, HTTP302), host, url, and title, keywords, description for FRAME; on update, omit to keep the current ones, [] removes them"`
	MailForwards []map[string]any          `json:"mail_forwards,omitempty" jsonschema:"EuroDNS mail forwards: source (left part of the address, * for catch-all), destination; on update, omit to keep the current ones, [] removes them"`
}

type profileListOut struct {
	Provider string                     `json:"provider"`
	Profiles []uiapi.ZoneProfileSummary `json:"profiles"`
}

type profileOut struct {
	Provider string `json:"provider"`
	// Profile is the EuroDNS ZoneProfilePage (id, name, records,
	// urlForwards, mailForwards, report).
	Profile any   `json:"profile,omitempty"`
	Valid   *bool `json:"valid,omitempty"`
}

func (in profileWriteIn) profile() (*eurodnsprov.ZoneProfile, error) {
	doc := map[string]any{"name": in.Name, "records": in.Records}
	if in.Records == nil {
		doc["records"] = []uiapi.ZoneProfileRecord{}
	}
	if in.URLForwards != nil {
		doc["urlForwards"] = in.URLForwards
	}
	if in.MailForwards != nil {
		doc["mailForwards"] = in.MailForwards
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var p eurodnsprov.ZoneProfile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, errors.New("invalid zone profile: " + err.Error())
	}
	return &p, nil
}

// asJSONValue turns a profile into plain JSON values for structured output.
func asJSONValue(p *eurodnsprov.ZoneProfile) any {
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

// runProfileTool runs a zone profile operation for an MCP tool.
func (m *mcpServer) runProfileTool(ctx context.Context, req *mcp.CallToolRequest, tool string, c profileCall) (*profileResult, error) {
	subj, err := m.subject(ctx, req)
	if err != nil {
		return nil, err
	}
	rec := func(ctx context.Context, provider, decision, reason string, extra map[string]any, changes []uiapi.Change) {
		e := m.s.profileEvent(ctx, subj, "mcp."+tool, provider, decision, reason, extra, changes)
		e.Extra["via"], e.Extra["mcp_client"] = "mcp", clientName(req)
		m.s.cfg.Audit.Log(ctx, e)
	}
	out, err := m.s.runProfile(ctx, subj, c, rec)
	if err != nil {
		_, body := m.s.profileErrorBody(ctx, err)
		if body.Details != nil {
			if b, jerr := json.Marshal(body.Details); jerr == nil {
				return nil, fmt.Errorf("%s: %s: %s", body.Reason, body.Message, b)
			}
		}
		return nil, fmt.Errorf("%s: %s", body.Reason, body.Message)
	}
	return out, nil
}

func (m *mcpServer) addProfileReadTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_zone_profiles",
		Description: "List the zone profiles (id and name) of a EuroDNS account." + profileToolNote,
		Annotations: readOnly("List zone profiles"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in profileListIn) (*mcp.CallToolResult, profileListOut, error) {
		out, err := m.runProfileTool(ctx, req, "list_zone_profiles", profileCall{Op: profileList, Provider: in.Provider, AllPages: true})
		if err != nil {
			return nil, profileListOut{}, err
		}
		res := profileListOut{Provider: out.Provider, Profiles: make([]uiapi.ZoneProfileSummary, 0, len(out.List))}
		for _, p := range out.List {
			res.Profiles = append(res.Profiles, uiapi.ZoneProfileSummary{ID: p.ID, Name: p.Name})
		}
		return nil, res, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_zone_profile",
		Description: "Get a zone profile of a EuroDNS account: its records, URL and mail forwards." + profileToolNote,
		Annotations: readOnly("Get a zone profile"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in profileIDIn) (*mcp.CallToolResult, profileOut, error) {
		if in.ID <= 0 {
			return nil, profileOut{}, errors.New("id is required")
		}
		out, err := m.runProfileTool(ctx, req, "get_zone_profile", profileCall{Op: profileGet, Provider: in.Provider, ID: in.ID})
		if err != nil {
			return nil, profileOut{}, err
		}
		return nil, profileOut{Provider: out.Provider, Profile: asJSONValue(out.Profile)}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "check_zone_profile",
		Description: "Validate a zone profile with EuroDNS without saving it: returns the profile as EuroDNS reads it and its validation report (valid false lists the errors). Use it before create_zone_profile or update_zone_profile." + profileToolNote,
		Annotations: readOnly("Check a zone profile"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in profileWriteIn) (*mcp.CallToolResult, profileOut, error) {
		p, err := in.profile()
		if err != nil {
			return nil, profileOut{}, err
		}
		out, err := m.runProfileTool(ctx, req, "check_zone_profile", profileCall{Op: profileCheck, Provider: in.Provider, Profile: p})
		if err != nil {
			return nil, profileOut{}, err
		}
		res := profileOut{Provider: out.Provider, Profile: asJSONValue(out.Profile)}
		if out.Profile.Report != nil {
			v := out.Profile.Report.Valid()
			res.Valid = &v
		}
		return nil, res, nil
	})
}

func (m *mcpServer) addProfileWriteTools(srv *mcp.Server) {
	write := func(title string, destructive bool) *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{Title: title, DestructiveHint: ptr(destructive), IdempotentHint: false, OpenWorldHint: ptr(true)}
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_zone_profile",
		Description: "Create a zone profile in a EuroDNS account, to prepare the arrival of a domain (transfer): check it first (check_zone_profile) and confirm with the user. Returns the profile with its id." + profileToolNote,
		Annotations: write("Create a zone profile", false),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in profileWriteIn) (*mcp.CallToolResult, profileOut, error) {
		p, err := in.profile()
		if err != nil {
			return nil, profileOut{}, err
		}
		out, err := m.runProfileTool(ctx, req, "create_zone_profile", profileCall{Op: profileCreate, Provider: in.Provider, Profile: p})
		if err != nil {
			return nil, profileOut{}, err
		}
		return nil, profileOut{Provider: out.Provider, Profile: asJSONValue(out.Profile)}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "update_zone_profile",
		Description: "Replace a zone profile of a EuroDNS account: give its name and all its records (with their isDynDns and proxy options); URL and mail forwards left out are kept, [] removes them. Check it first and confirm with the user. Domains it was already applied to do not change. Needs a recent login for humans." + profileToolNote,
		Annotations: write("Update a zone profile", true),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in profileWriteIn) (*mcp.CallToolResult, profileOut, error) {
		if in.ID <= 0 {
			return nil, profileOut{}, errors.New("id is required")
		}
		p, err := in.profile()
		if err != nil {
			return nil, profileOut{}, err
		}
		out, err := m.runProfileTool(ctx, req, "update_zone_profile", profileCall{Op: profileUpdate, Provider: in.Provider, ID: in.ID, Profile: p, KeepForwards: true})
		if err != nil {
			return nil, profileOut{}, err
		}
		return nil, profileOut{Provider: out.Provider, Profile: asJSONValue(out.Profile)}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete_zone_profile",
		Description: "Delete a zone profile of a EuroDNS account; confirm with the user first. Domains it was already applied to do not change." + profileToolNote,
		Annotations: write("Delete a zone profile", true),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in profileIDIn) (*mcp.CallToolResult, profileOut, error) {
		if in.ID <= 0 {
			return nil, profileOut{}, errors.New("id is required")
		}
		out, err := m.runProfileTool(ctx, req, "delete_zone_profile", profileCall{Op: profileDelete, Provider: in.Provider, ID: in.ID})
		if err != nil {
			return nil, profileOut{}, err
		}
		return nil, profileOut{Provider: out.Provider}, nil
	})
}
