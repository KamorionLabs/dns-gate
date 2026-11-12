package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/propagation"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// TargetResolver resolves the targets of RRsets (propagation.Checker).
type TargetResolver interface {
	ResolveTargets(ctx context.Context, subject string, names []string) (map[string]propagation.Target, error)
}

// resolveNote is appended to the description of the read tools that take
// resolve.
const resolveNote = " With resolve=true, each target of a CNAME, alias, APEX, MX, NS, SRV or PTR RRset is resolved through public resolvers: " +
	"status (live, nxdomain, nodata, servfail, timeout, skipped), CNAME chain, addresses, and takeover_risk when a target that does not resolve " +
	"belongs to a third-party service where the name can be claimed again (a deleted CloudFront distribution, S3 bucket, Azure app…). " +
	"Resolutions are cached for a minute, at most 256 targets per call, and calls that resolve are rate limited like check_propagation. " +
	"target_owner labels the target with who runs it when the gate configuration knows (target_owners)."

// errResolveUnavailable is returned when resolve=true and the gate has no
// resolver (propagation disabled).
var errResolveUnavailable = errors.New("resolve is not available: the DNS propagation check is disabled on this gate")

// errResolveRateLimited is returned when the subject resolved too many
// targets recently, or too many resolutions run in the process.
var errResolveRateLimited = errors.New("rate_limited: too many target resolutions, retry in a few seconds or without resolve")

// errResolveFailed hides an unexpected resolver error.
var errResolveFailed = errors.New("target resolution failed")

// targetResolver is the resolver of the gate, nil when propagation is
// disabled.
func (s *Server) targetResolver() TargetResolver {
	if tr, ok := s.cfg.Propagation.(TargetResolver); ok && tr != nil {
		return tr
	}
	return nil
}

// rrsetTargets returns the absolute names an RRset points to.
func rrsetTargets(zone string, rs *uiapi.RRset) []string {
	if rs.Alias != nil && rs.Alias.Target != "" {
		// Route53 alias targets are absolute, with or without trailing dot.
		return []string{strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rs.Alias.Target)), ".") + "."}
	}
	var out []string
	for _, v := range rs.Values {
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		var name string
		switch strings.ToUpper(rs.Type) {
		case "CNAME", "APEX", "NS", "PTR", "DNAME":
			name = f[0]
		case "MX":
			if len(f) == 2 {
				name = f[1]
			}
		case "SRV":
			if len(f) == 4 {
				name = f[3]
			}
		default:
			continue
		}
		if name == "" || name == "." {
			continue
		}
		if n := propagation.AbsTarget(zone, name); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// labelTargets sets target_owner on the RRsets whose target matches the
// target_owners table: the first target that matches, in value order.
func (s *Server) labelTargets(zone string, sets []uiapi.RRset) {
	owners := s.cfg.Config.TargetOwners
	if len(owners) == 0 {
		return
	}
	for i := range sets {
		if sets[i].Type == dns.TypeURLForward {
			continue
		}
		for _, n := range rrsetTargets(zone, &sets[i]) {
			if o := config.MatchTargetOwner(owners, n); o != "" {
				sets[i].TargetOwner = o
				break
			}
		}
	}
}

// resolveTargets fills Targets on the RRsets that point to names, in one
// rate-limited call for the subject.
func (s *Server) resolveTargets(ctx context.Context, subj *identity.Subject, zone string, sets []uiapi.RRset) error {
	tr := s.targetResolver()
	if tr == nil {
		return errResolveUnavailable
	}
	per := make([][]string, len(sets))
	var all []string
	for i := range sets {
		per[i] = rrsetTargets(zone, &sets[i])
		all = append(all, per[i]...)
	}
	if len(all) == 0 {
		return nil
	}
	res, err := tr.ResolveTargets(ctx, subj.String(), all)
	switch {
	case errors.Is(err, propagation.ErrRateLimited), errors.Is(err, propagation.ErrBusy):
		return errResolveRateLimited
	case err != nil:
		return errResolveFailed
	}
	for i := range sets {
		for _, n := range per[i] {
			t, ok := res[n]
			if !ok {
				continue
			}
			sets[i].Targets = append(sets[i].Targets, uiapi.TargetResolution{
				Name: t.Name, Status: t.Status, Chain: t.Chain, Addresses: t.Addresses, Resolver: t.Resolver,
				TakeoverRisk: t.TakeoverRisk, Error: t.Error, Cached: t.Cached,
			})
		}
	}
	return nil
}

// decorateTargets labels the targets of sets and, with resolve, resolves
// them.
func (s *Server) decorateTargets(ctx context.Context, subj *identity.Subject, zone string, sets []uiapi.RRset, resolve bool) error {
	s.labelTargets(zone, sets)
	if !resolve {
		return nil
	}
	return s.resolveTargets(ctx, subj, zone, sets)
}

// writeResolveError answers a REST request whose resolve failed.
func writeResolveError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errResolveUnavailable):
		writeError(w, http.StatusBadRequest, "resolve_unavailable", err.Error())
	case errors.Is(err, errResolveRateLimited):
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many target resolutions, retry in a few seconds or without resolve")
	default:
		writeError(w, http.StatusBadGateway, "upstream", err.Error())
	}
}

// The propagation checker resolves targets.
var _ TargetResolver = (*propagation.Checker)(nil)
