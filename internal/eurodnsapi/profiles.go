package eurodnsapi

import (
	"fmt"
	"strings"

	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// ProfileAccount returns the EuroDNS account of the zone profile
// operations: the provider named id or, when id is empty, the only provider
// of kind eurodns. Unknown providers are not found; a provider of another
// kind, or several EuroDNS providers without id, are invalid requests.
func (f *Facade) ProfileAccount(id string) (*eurodnsprov.Provider, error) {
	var eps []*eurodnsprov.Provider
	for _, p := range f.cfg.Accounts {
		ep, ok := p.(*eurodnsprov.Provider)
		if id != "" && p.ID() == id {
			if !ok {
				return nil, &zonewrite.Error{Reason: ReasonInvalidProvider,
					Message: fmt.Sprintf("provider %s is of kind %s: zone profiles exist only on EuroDNS providers", id, p.Kind())}
			}
			return ep, nil
		}
		if ok {
			eps = append(eps, ep)
		}
	}
	switch {
	case id != "":
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonNotFound, Message: "unknown provider " + id}
	case len(eps) == 1:
		return eps[0], nil
	case len(eps) == 0:
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonNotFound, Message: "no EuroDNS provider: zone profiles exist only on EuroDNS providers"}
	}
	ids := make([]string, 0, len(eps))
	for _, ep := range eps {
		ids = append(ids, ep.ID())
	}
	return nil, &zonewrite.Error{Reason: ReasonInvalidProvider,
		Message: "several EuroDNS providers (" + strings.Join(ids, ", ") + "): name one in the " + ProviderHeader + " header or use /api/v1/providers/{provider}/zone-profiles"}
}

// ReasonInvalidProvider refuses a zone profile operation on a provider
// that is not of kind eurodns, or without provider among several.
const ReasonInvalidProvider zonewrite.Reason = "invalid_provider"

// ProviderHeader names the provider of an account-wide EuroDNS operation
// (zone profiles) when several EuroDNS providers are configured.
const ProviderHeader = "X-DNS-Gate-Provider"
