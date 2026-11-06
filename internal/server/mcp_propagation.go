package server

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/KamorionLabs/dns-gate/internal/propagation"
)

type checkPropagationIn struct {
	Zone   string `json:"zone" jsonschema:"managed zone name, e.g. example.com"`
	Host   string `json:"host" jsonschema:"host relative to the zone, @ for the apex"`
	Type   string `json:"type" jsonschema:"record type, e.g. A"`
	Expect string `json:"expect,omitempty" jsonschema:"optional content hash just written (new_hash of apply_rrset_change), or absent after a deletion: the check is refused when the RRset still differs after a fresh provider read"`
}

// addPropagationTool registers check_propagation. Like the REST endpoint it
// is a read: no audit event.
func (m *mcpServer) addPropagationTool(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "check_propagation",
		Description: "Check whether an RRset of a managed zone is visible in the DNS: asks the authoritative name servers of the zone and public resolvers around the world, " +
			"and compares each answer with the RRset as read from the provider. Per server: status (match, stale: other values or TTL still cached, missing: no record, error, " +
			"indeterminate: alias addresses not tied to the target), values, remaining TTL and latency; summary.converged is true once every server that answered matches, " +
			"an authoritative one at least, and summary.max_ttl_left bounds when stale caches expire. After apply_rrset_change, pass the new_hash of the change as expect (absent after a deletion). " +
			"Resolvers keep the previous answer until its TTL runs out: check again later rather than in a loop (results are cached for a few seconds and checks are rate limited).",
		Annotations: &mcp.ToolAnnotations{Title: "Check DNS propagation", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in checkPropagationIn) (*mcp.CallToolResult, propagation.Result, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, propagation.Result{}, err
		}
		host := in.Host
		if host == "" {
			host = "@"
		}
		res, e := m.s.checkPropagation(ctx, subj, in.Zone, host, in.Type, in.Expect)
		if e != nil {
			return nil, propagation.Result{}, errors.New(e.msg)
		}
		return nil, *res, nil
	})
}
