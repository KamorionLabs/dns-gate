package propagation

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// Statuses of a resolved target.
const (
	// TargetLive: the target resolves to addresses (A or AAAA), directly or
	// at the end of its CNAME chain.
	TargetLive = "live"
	// TargetNXDomain: the target, or a name of its chain, does not exist.
	TargetNXDomain = "nxdomain"
	// TargetNoData: the name exists but has no address.
	TargetNoData = "nodata"
	// TargetServFail: the resolvers could not resolve it (SERVFAIL,
	// REFUSED, an answer filtered by the resolver).
	TargetServFail = "servfail"
	// TargetTimeout: no answer in time, or the call ran out of time before
	// the target was asked.
	TargetTimeout = "timeout"
	// TargetSkipped: beyond MaxTargets in one call, not asked.
	TargetSkipped = "skipped"
)

// Bounds of a target resolution.
const (
	// MaxTargets is the number of distinct targets one call resolves; the
	// others are skipped.
	MaxTargets = 256
	// DefaultTargetTimeout bounds a whole call.
	DefaultTargetTimeout = 10 * time.Second
	// DefaultTargetCacheTTL is how long a resolved target is reused.
	DefaultTargetCacheTTL = time.Minute
	// maxTargetAddresses bounds the addresses reported per target.
	maxTargetAddresses = 8
	// maxResolverAttempts is the resolvers asked for one target before
	// giving up on errors.
	maxResolverAttempts = 2
)

// Target is a name an RRset points to (a CNAME, an alias, a EuroDNS APEX)
// and how it resolves.
type Target struct {
	// Name is the target, absolute with a trailing dot.
	Name   string `json:"name"`
	Status string `json:"status"`
	// Chain is the CNAME chain followed from the target, in order.
	Chain []string `json:"chain,omitempty"`
	// Addresses are the A and AAAA records at the end of the chain.
	Addresses []string `json:"addresses,omitempty"`
	// Resolver is the resolver that gave the answer.
	Resolver string `json:"resolver,omitempty"`
	// TakeoverRisk names the third-party service of a target that does not
	// resolve: whoever claims that name at the service (a deleted
	// distribution, bucket or app) would serve the host.
	TakeoverRisk string `json:"takeover_risk,omitempty"`
	Error        string `json:"error,omitempty"`
	Cached       bool   `json:"cached,omitempty"`
}

// takeoverSuffixes are services whose names can be claimed again by anyone
// once released: a dangling record towards them is a takeover risk.
var takeoverSuffixes = []struct{ suffix, service string }{
	{"cloudfront.net", "AWS CloudFront"},
	{"s3.amazonaws.com", "AWS S3"},
	{"amazonaws.com", "AWS"},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk"},
	{"awsapprunner.com", "AWS App Runner"},
	{"azurewebsites.net", "Azure App Service"},
	{"cloudapp.net", "Azure Cloud Services"},
	{"cloudapp.azure.com", "Azure"},
	{"trafficmanager.net", "Azure Traffic Manager"},
	{"blob.core.windows.net", "Azure Blob Storage"},
	{"azureedge.net", "Azure CDN"},
	{"azurefd.net", "Azure Front Door"},
	{"azurestaticapps.net", "Azure Static Web Apps"},
	{"azure-api.net", "Azure API Management"},
	{"herokuapp.com", "Heroku"},
	{"herokudns.com", "Heroku"},
	{"github.io", "GitHub Pages"},
	{"netlify.app", "Netlify"},
	{"netlify.com", "Netlify"},
	{"vercel.app", "Vercel"},
	{"vercel-dns.com", "Vercel"},
	{"pantheonsite.io", "Pantheon"},
	{"myshopify.com", "Shopify"},
	{"wpengine.com", "WP Engine"},
	{"ghost.io", "Ghost"},
	{"readthedocs.io", "Read the Docs"},
	{"surge.sh", "Surge"},
	{"bitbucket.io", "Bitbucket"},
	{"firebaseapp.com", "Firebase"},
	{"web.app", "Firebase"},
	{"appspot.com", "Google App Engine"},
	{"storage.googleapis.com", "Google Cloud Storage"},
	{"fastly.net", "Fastly"},
	{"zendesk.com", "Zendesk"},
	{"helpscoutdocs.com", "Help Scout"},
	{"statuspage.io", "Statuspage"},
	{"unbouncepages.com", "Unbounce"},
	{"webflow.io", "Webflow"},
}

// TakeoverService returns the third-party service a name belongs to, "" if
// none is known.
func TakeoverService(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, s := range takeoverSuffixes {
		if n == s.suffix || strings.HasSuffix(n, "."+s.suffix) {
			return s.service
		}
	}
	return ""
}

// ResolveTargets resolves targets for subject through the configured
// resolvers, recursively, following their CNAME chains. The names come
// from the content of zones read from a provider, never from the caller.
// Targets resolved less than DefaultTargetCacheTTL ago are reused; a call
// that has to ask anything counts once against the rate limit of subject
// (ErrRateLimited) and once against MaxInFlight (ErrBusy). At most
// MaxTargets distinct targets are asked; the call is bounded by
// DefaultTargetTimeout, and what is not answered by then is a timeout.
// The result is keyed by the absolute target name.
func (c *Checker) ResolveTargets(ctx context.Context, subject string, names []string) (map[string]Target, error) {
	out := map[string]Target{}
	var todo []string
	for _, n := range names {
		n = absTarget(n)
		if n == "" {
			continue
		}
		if _, ok := out[n]; ok || slices.Contains(todo, n) {
			continue
		}
		if len(out)+len(todo) >= MaxTargets {
			out[n] = Target{Name: n, Status: TargetSkipped, Error: "too many targets in one call"}
			continue
		}
		if t, ok := c.cachedTarget(n); ok {
			out[n] = t
			continue
		}
		todo = append(todo, n)
	}
	if len(todo) == 0 {
		return out, nil
	}
	if !c.allow(subject) {
		return nil, ErrRateLimited
	}
	select {
	case c.inflight <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	defer func() { <-c.inflight }()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultTargetTimeout)
	defer cancel()
	res := make([]Target, len(todo))
	sem := make(chan struct{}, c.opt.Concurrency)
	var wg sync.WaitGroup
	for i, n := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				res[i] = Target{Name: n, Status: TargetTimeout, Error: "not asked before the deadline"}
				return
			}
			defer func() { <-sem }()
			res[i] = c.resolveOne(ctx, n)
		}()
	}
	wg.Wait()
	for _, t := range res {
		if t.Status != TargetTimeout || t.Error != "not asked before the deadline" {
			c.storeTarget(t)
		}
		out[t.Name] = t
	}
	return out, nil
}

func absTarget(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if n == "" || n == "." {
		return ""
	}
	n = mdns.Fqdn(n)
	if len(n) > 254 || !hostnameRe.MatchString(n) {
		return ""
	}
	return n
}

// hostnameRe accepts host names (letters, digits, hyphens, underscores for
// service labels), each label 1 to 63 characters.
var hostnameRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+$`)

// resolveOne asks the resolvers in their configured order, unfiltered ones
// first, until one gives a usable answer.
func (c *Checker) resolveOne(ctx context.Context, name string) Target {
	rs := slices.Clone(c.opt.Resolvers)
	slices.SortStableFunc(rs, func(a, b Resolver) int {
		switch {
		case a.Filtering == b.Filtering:
			return 0
		case a.Filtering:
			return 1
		}
		return -1
	})
	t := Target{Name: name, Status: TargetTimeout, Error: "no resolver"}
	for i, r := range rs {
		if i >= maxResolverAttempts || ctx.Err() != nil {
			break
		}
		t = c.askTarget(ctx, r, name)
		if t.Status != TargetServFail && t.Status != TargetTimeout {
			break
		}
	}
	if t.Status == TargetNXDomain || t.Status == TargetNoData {
		for _, n := range append([]string{name}, t.Chain...) {
			if s := TakeoverService(n); s != "" {
				t.TakeoverRisk = s
			}
		}
	}
	return t
}

// askTarget asks one resolver for the A records of name, then AAAA when
// the name has no A record.
func (c *Checker) askTarget(ctx context.Context, r Resolver, name string) Target {
	t := Target{Name: name, Resolver: r.Name}
	addr := resolverAddr(r.Address)
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		rep := c.exchange(ctx, addr, name, qtype, true)
		if rep.err != nil {
			t.Status, t.Error = TargetTimeout, exchangeError(rep.err)
			if t.Error != "timeout" {
				t.Status = TargetServFail
			}
			return t
		}
		m := rep.msg
		if blocked(m) {
			t.Status, t.Error = TargetServFail, "filtered by the resolver"+ede(m)
			return t
		}
		vals, chain, _ := records(m, name, qtype)
		if len(chain) > len(t.Chain) {
			t.Chain = chain
		}
		switch m.Rcode {
		case mdns.RcodeSuccess:
		case mdns.RcodeNameError:
			t.Status = TargetNXDomain
			return t
		default:
			t.Status, t.Error = TargetServFail, strings.ToLower(mdns.RcodeToString[m.Rcode])+ede(m)
			return t
		}
		if len(vals) > 0 {
			if len(vals) > maxTargetAddresses {
				vals = vals[:maxTargetAddresses]
			}
			t.Status, t.Addresses = TargetLive, vals
			return t
		}
	}
	t.Status = TargetNoData
	return t
}

func (c *Checker) cachedTarget(name string) (Target, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.targets[name]
	if !ok || !c.opt.Now().Before(e.expires) {
		return Target{}, false
	}
	t := e.t
	t.Cached = true
	t.Chain, t.Addresses = slices.Clone(t.Chain), slices.Clone(t.Addresses)
	return t, true
}

func (c *Checker) storeTarget(t Target) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opt.Now()
	if c.targets == nil {
		c.targets = map[string]cachedTarget{}
	}
	if len(c.targets) >= maxTargetCacheEntries {
		for k, e := range c.targets {
			if !now.Before(e.expires) {
				delete(c.targets, k)
			}
		}
		if len(c.targets) >= maxTargetCacheEntries {
			clear(c.targets)
		}
	}
	c.targets[t.Name] = cachedTarget{t: t, expires: now.Add(DefaultTargetCacheTTL)}
}

const maxTargetCacheEntries = 8192

type cachedTarget struct {
	t       Target
	expires time.Time
}

// AbsTarget returns a target name read from zone as an absolute lowercase
// name: a name without trailing dot is relative to zone, as EuroDNS stores
// it.
func AbsTarget(zone, name string) string { return absName(zone, name) }
