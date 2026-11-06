package zonewrite

import (
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// withGrantFolder adds to extra, as "folder", the provider folder through
// which the policy granted s one of actions on an RRset of changes (the
// first action granted for each change), when the authorizer selects zones
// by folder.
func (e *engine) withGrantFolder(s *identity.Subject, zone string, changes []uiapi.Change, extra map[string]any, actions ...string) map[string]any {
	fg, ok := e.cfg.Authz.(policy.FolderGrants)
	if !ok {
		return extra
	}
	for _, c := range changes {
		k := dns.Key{Host: c.Host, Type: c.Type}
		for _, a := range actions {
			if f := fg.GrantFolder(s, a, zone, k); f != "" {
				if extra == nil {
					extra = map[string]any{}
				}
				extra["folder"] = f
				return extra
			}
		}
	}
	return extra
}
