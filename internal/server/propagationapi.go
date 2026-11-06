package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/propagation"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation?expect=<hash>
// asks the authoritative name servers of a managed zone and the public
// resolvers of the configuration for one RRset (dns.read on that RRset) and
// compares their answers with the RRset as read from the provider. A read:
// no audit event, a debug log line.
const routePropagation = routeRRset + "/propagation"

// expectAbsent is the expect value of a check after a deletion.
const expectAbsent = "absent"

// rereadsPerMinute bounds the provider reads a subject triggers with an
// expect the inventory does not have yet.
const rereadsPerMinute = 6

// Propagator checks the propagation of an RRset (propagation.Checker).
type Propagator interface {
	Check(ctx context.Context, subject string, req propagation.Request) (*propagation.Result, error)
}

// newPropagator builds the checker of the propagation section, nil when
// it is disabled.
func newPropagator(c Config) Propagator {
	p := c.Config.Propagation
	if !p.On() {
		return nil
	}
	return propagation.New(propagation.Options{
		Resolvers: propagationResolvers(p.Resolvers), QueryTimeout: p.QueryTimeout.D(), Timeout: p.Timeout.D(),
		Concurrency: p.Concurrency, CacheTTL: p.CacheTTL.D(), RequestsPerMinute: p.RequestsPerMinute,
		MaxInFlight: p.MaxInFlight, Now: c.Now, Log: c.Log,
	})
}

func propagationResolvers(rs []config.PropagationResolver) []propagation.Resolver {
	out := make([]propagation.Resolver, 0, len(rs))
	for _, r := range rs {
		out = append(out, propagation.Resolver{Name: r.Name, Address: r.Address, Location: r.Location, Country: r.Country, Region: r.Region, Filtering: r.Filtering})
	}
	return out
}

func (s *Server) handlePropagation(w http.ResponseWriter, r *http.Request, subj *identity.Subject, zone, host, typ string) {
	res, e := s.checkPropagation(r.Context(), subj, zone, host, typ, r.URL.Query().Get("expect"))
	if e != nil {
		switch e.status {
		case http.StatusTooManyRequests:
			w.Header().Set("Retry-After", "10")
		case http.StatusServiceUnavailable:
			w.Header().Set("Retry-After", "5")
		}
		s.writePolicyError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

// checkPropagation runs a check for subj. expect, when set, is the content
// hash the caller just wrote (or "absent" after a deletion). The inventory
// is a cache of this process: when it differs from expect (another replica
// or Lambda instance wrote, or the read after the write failed), the zone
// is read again from the provider, at most rereadsPerMinute times a minute
// per subject; a content still different is a 412 precondition.
func (s *Server) checkPropagation(ctx context.Context, subj *identity.Subject, zoneIn, hostIn, typeIn, expect string) (*propagation.Result, *policyError) {
	zone, key, msg := rrsetKey(zoneIn, hostIn, typeIn)
	switch {
	case msg != "":
		return nil, perr(http.StatusBadRequest, "invalid", msg)
	case s.cfg.Propagation == nil:
		return nil, perr(http.StatusNotImplemented, "not_implemented", "propagation checks are disabled (propagation.enabled)")
	case !s.pol.Managed(zone):
		return nil, perr(http.StatusNotFound, "not_found", "zone not managed by the gate")
	case !s.cfg.Authz.AllowRRset(subj, policy.ActionDNSRead, zone, key):
		return nil, perr(http.StatusForbidden, "forbidden", "dns.read not granted on "+zone+" "+key.String())
	}
	if _, err := propagation.QueryType(key.Type); err != nil {
		return nil, perr(http.StatusBadRequest, "invalid", "record type "+key.Type+" cannot be checked")
	}
	req := propagation.Request{Zone: zone, Host: key.Host, Type: key.Type}
	expect = normalizeETag(strings.TrimSpace(expect))
	if e := s.expectedRRset(ctx, subj, zone, key, &req); e != nil {
		return nil, e
	}
	if expect != "" && !expectMatches(expect, req) && s.rereads.allow(subj.String()) {
		if _, _, err := s.cfg.Engine.ReadZone(ctx, subj, zone, "api.propagation"); err == nil {
			if e := s.expectedRRset(ctx, subj, zone, key, &req); e != nil {
				return nil, e
			}
		}
	}
	if expect != "" && !expectMatches(expect, req) {
		return nil, perr(http.StatusPreconditionFailed, "precondition", "the RRset no longer has the expected content: read it again")
	}
	if ns, err := s.cfg.Engine.RRset(ctx, subj, zone, dns.Key{Host: dns.Apex, Type: "NS"}); err == nil && ns.Status != uiapi.StatusMissing {
		req.NameServers = ns.Values
	}
	res, err := s.cfg.Propagation.Check(ctx, subj.String(), req)
	switch {
	case errors.Is(err, propagation.ErrRateLimited):
		return nil, perr(http.StatusTooManyRequests, "rate_limited", "too many propagation checks, retry in a few seconds")
	case errors.Is(err, propagation.ErrBusy):
		return nil, perr(http.StatusServiceUnavailable, "busy", "too many propagation checks running, retry in a few seconds")
	case errors.Is(err, propagation.ErrUnsupportedType):
		return nil, perr(http.StatusBadRequest, "invalid", "record type "+key.Type+" cannot be checked")
	case err != nil:
		s.log.Error("propagation check", "zone", zone, "err", err)
		return nil, perr(http.StatusBadGateway, "upstream", "propagation check failed")
	}
	s.log.Debug("propagation", "subject", subj.String(), "zone", zone, "host", key.Host, "type", key.Type,
		"cached", res.Cached, "match", res.Summary.Match, "total", res.Summary.Total, "converged", res.Summary.Converged)
	return res, nil
}

// expectedRRset sets the expected RRset of req from the inventory of this
// process (nil when the RRset does not exist).
func (s *Server) expectedRRset(ctx context.Context, subj *identity.Subject, zone string, key dns.Key, req *propagation.Request) *policyError {
	req.Expected, req.Hash = nil, ""
	got, err := s.cfg.Engine.RRset(ctx, subj, zone, key)
	switch ze, _ := zonewrite.AsError(err); {
	case err == nil:
		if got.Status != uiapi.StatusMissing {
			rs := withHash(*got)
			req.Expected = &dns.RRset{Key: key, TTL: rs.TTL, Values: rs.Values, Alias: rs.Alias}
			req.Hash = rs.Hash
		}
	case ze != nil && ze.Reason == zonewrite.ReasonNotFound:
	case ze != nil && ze.Reason == zonewrite.ReasonForbidden:
		return perr(http.StatusForbidden, "forbidden", ze.Message)
	default:
		s.log.Error("propagation inventory", "zone", zone, "err", err)
		return perr(http.StatusBadGateway, "upstream", "inventory unavailable")
	}
	return nil
}

func expectMatches(expect string, req propagation.Request) bool {
	if expect == expectAbsent {
		return req.Expected == nil
	}
	return req.Expected != nil && expect == req.Hash
}

// withNewHashes sets the content hash of every RRset an apply created or
// updated, so that clients can check its propagation with expect.
func withNewHashes(res *uiapi.PlanResult) {
	for i, c := range res.Changes {
		if c.Op != "create" && c.Op != "update" {
			continue
		}
		res.Changes[i].NewHash = dns.ContentHash(dns.RRset{Key: dns.Key{Host: c.Host, Type: c.Type}, TTL: c.NewTTL, Values: c.NewValues, Alias: c.NewAlias, Forward: c.NewForward})
	}
}
