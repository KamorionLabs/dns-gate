package zonewrite

import (
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
)

// grants records the provider folder through which the policy granted the
// RRset actions of one request, so that its audit event carries the folder
// of the authorization (not of a later decision).
type grants struct{ folder string }

// allowRRset is Authz.AllowRRset recording in g, when not nil, the folder of
// the first grant made through a folder rule.
func (e *engine) allowRRset(g *grants, s *identity.Subject, action, zone string, k dns.Key) bool {
	fg, ok := e.cfg.Authz.(policy.FolderGrants)
	if !ok {
		return e.cfg.Authz.AllowRRset(s, action, zone, k)
	}
	allowed, folder := fg.AllowRRsetFolder(s, action, zone, k)
	if allowed && folder != "" && g != nil && g.folder == "" {
		g.folder = folder
	}
	return allowed
}

// extra adds the recorded folder to an audit extra, as "folder".
func (g *grants) extra(extra map[string]any) map[string]any {
	if g == nil || g.folder == "" {
		return extra
	}
	if extra == nil {
		extra = map[string]any{}
	}
	extra["folder"] = g.folder
	return extra
}
