package policy

import (
	"fmt"
	"sort"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/glob"
)

// IneffectiveProfileGrants lists the rules of a layer ("" for both) that
// grant dns.zone.profile where it has no effect: on zones not covering "*"
// or with a record scope. Entries are "<role>.rules[<i>]", sorted.
func (s *Snapshot) IneffectiveProfileGrants(layer string) []string {
	var out []string
	for name, cr := range s.roles {
		if layer != "" && cr.layer != layer {
			continue
		}
		for i, r := range cr.role.Rules {
			if contains(r.Actions, ActionZoneProfile) && (!glob.Covered(r.Zones, "*") || r.Records != nil) {
				out = append(out, fmt.Sprintf("%s.rules[%d]", name, i))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ProtectedRecord returns the protected entry matching a host and a type
// in any zone: the records of a zone profile are applied to domains the
// gate does not know in advance, so the zones of the entry are ignored.
func (s *Snapshot) ProtectedRecord(host, typ string) (config.Protected, bool) {
	k := normKey(dns.Key{Host: host, Type: typ})
	for _, p := range s.protected {
		if hostMatches(p.Hosts, k.Host) && typeMatches(p.Types, k.Type) {
			return p, true
		}
	}
	return config.Protected{}, false
}
