// Package propagation checks whether a change is visible in the DNS: it asks
// the authoritative name servers of a zone and a list of public resolvers
// for one RRset and compares their answers with the RRset as read from the
// provider.
//
// Only names of managed zones are queried, built by the gate from a zone and
// a host it validated, and only the configured resolvers and the name
// servers of the zone are contacted: a check is never an open resolver.
// Answers of public resolvers come from their caches: a resolver keeps the
// previous answer until its TTL runs out, which is what a check shows.
package propagation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/KamorionLabs/dns-gate/internal/dns"
)

// Statuses of an answer.
const (
	// StatusMatch: the answer is the expected content (no record for an
	// RRset that does not exist).
	StatusMatch = "match"
	// StatusStale: other records than the expected ones, typically the
	// previous content still cached.
	StatusStale = "stale"
	// StatusMissing: no record while the RRset exists (NXDOMAIN or NODATA,
	// possibly a cached negative answer).
	StatusMissing = "missing"
	// StatusError: no usable answer (timeout, SERVFAIL, REFUSED, lame name
	// server).
	StatusError = "error"
)

// Kinds of the servers asked.
const (
	KindAuthoritative = "authoritative"
	KindResolver      = "resolver"
)

// Defaults of Options.
const (
	DefaultQueryTimeout      = 2 * time.Second
	DefaultTimeout           = 6 * time.Second
	DefaultConcurrency       = 16
	DefaultCacheTTL          = 10 * time.Second
	DefaultRequestsPerMinute = 30
	maxNameServers           = 8
	maxCNAMEChain            = 8
	maxCacheEntries          = 1024
)

var (
	// ErrRateLimited is returned when a subject asked for too many checks
	// not served from the cache.
	ErrRateLimited = errors.New("propagation: too many checks, retry in a few seconds")
	// ErrUnsupportedType is returned for a record type that cannot be asked.
	ErrUnsupportedType = errors.New("propagation: record type not supported")

	errInvalidValue = errors.New("invalid value")
)

// Lookup resolves the name servers of a zone and their addresses
// (net.DefaultResolver).
type Lookup interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configure a Checker. Zero values take the defaults.
type Options struct {
	// Resolvers are the public resolvers asked, DefaultResolvers when empty.
	Resolvers []Resolver
	// QueryTimeout bounds one query, Timeout a whole check.
	QueryTimeout time.Duration
	Timeout      time.Duration
	// Concurrency bounds the servers asked at once by one check.
	Concurrency int
	// CacheTTL is how long the result of a check is reused for the same
	// RRset content.
	CacheTTL time.Duration
	// RequestsPerMinute bounds the checks of one subject that are not
	// served from the cache.
	RequestsPerMinute int
	// Lookup resolves the name servers, net.DefaultResolver when nil.
	Lookup Lookup
	// NameServerPort is the port of the authoritative servers (53).
	NameServerPort uint16
	// AllowPrivateNameServers accepts authoritative servers at private,
	// loopback or link-local addresses (tests). Otherwise they are skipped,
	// so that the NS records of a zone cannot point the gate at an internal
	// host.
	AllowPrivateNameServers bool
	Now                     func() time.Time
	Log                     *slog.Logger
}

// Request is the RRset to check.
type Request struct {
	Zone string
	// Host is relative to the zone, dns.Apex for the apex.
	Host string
	Type string
	// Expected is the RRset as read from the provider, nil when it does not
	// exist (a deletion).
	Expected *dns.RRset
	// Hash identifies the expected content (dns.ContentHash), "" when absent.
	Hash string
	// NameServers are the apex NS of the zone as read from the provider; the
	// NS of the zone are looked up when empty.
	NameServers []string
}

// Expected is the reference of a check.
type Expected struct {
	Exists bool     `json:"exists"`
	Hash   string   `json:"hash,omitempty"`
	TTL    int      `json:"ttl,omitempty"`
	Values []string `json:"values"`
	// AliasTarget is the name an alias (Route53) or APEX (EuroDNS) RRset
	// resolves: its addresses are compared instead of values.
	AliasTarget string `json:"alias_target,omitempty"`
}

// Answer is the answer of one server.
type Answer struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Location string `json:"location,omitempty"`
	Country  string `json:"country,omitempty"`
	Region   string `json:"region,omitempty"`
	Status   string `json:"status"`
	// Values are the records of the asked type at the end of the CNAME
	// chain, in comparison form (TXT as raw content).
	Values []string `json:"values"`
	// CNAMEs is the CNAME chain followed from the name, if any.
	CNAMEs []string `json:"cnames,omitempty"`
	// TTLLeft is the remaining TTL of the records, or of the negative
	// answer (SOA minimum), in seconds.
	TTLLeft   *int   `json:"ttl_left,omitempty"`
	Rcode     string `json:"rcode,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	TCP       bool   `json:"tcp,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Summary counts the answers.
type Summary struct {
	Total   int `json:"total"`
	Match   int `json:"match"`
	Stale   int `json:"stale"`
	Missing int `json:"missing"`
	Error   int `json:"error"`
	// Converged: every server that answered has the expected content.
	Converged bool `json:"converged"`
	// MaxTTLLeft is the longest TTL left among the stale and missing
	// answers: a bound on when those caches expire.
	MaxTTLLeft int `json:"max_ttl_left"`
}

// Result is the outcome of a check.
type Result struct {
	Zone      string    `json:"zone"`
	Host      string    `json:"host"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	QueryType string    `json:"query_type"`
	Expected  Expected  `json:"expected"`
	CheckedAt time.Time `json:"checked_at"`
	Cached    bool      `json:"cached"`
	Summary   Summary   `json:"summary"`
	Answers   []Answer  `json:"answers"`
}

// Checker runs checks. It is safe for concurrent use.
type Checker struct {
	opt     Options
	group   singleflight.Group
	mu      sync.Mutex
	cache   map[string]cached
	buckets map[string]*bucket
}

type cached struct {
	res     Result
	expires time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a Checker.
func New(opt Options) *Checker {
	if len(opt.Resolvers) == 0 {
		opt.Resolvers = DefaultResolvers
	}
	if opt.QueryTimeout <= 0 {
		opt.QueryTimeout = DefaultQueryTimeout
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = DefaultConcurrency
	}
	if opt.CacheTTL <= 0 {
		opt.CacheTTL = DefaultCacheTTL
	}
	if opt.RequestsPerMinute <= 0 {
		opt.RequestsPerMinute = DefaultRequestsPerMinute
	}
	if opt.Lookup == nil {
		opt.Lookup = net.DefaultResolver
	}
	if opt.NameServerPort == 0 {
		opt.NameServerPort = 53
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	return &Checker{opt: opt, cache: map[string]cached{}, buckets: map[string]*bucket{}}
}

// Resolvers returns the public resolvers asked.
func (c *Checker) Resolvers() []Resolver { return slices.Clone(c.opt.Resolvers) }

// QueryType is the type asked for an RRset type ("A" for a EuroDNS APEX
// RRset), ErrUnsupportedType when it cannot be asked.
func QueryType(typ string) (uint16, error) {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if typ == "APEX" {
		return mdns.TypeA, nil
	}
	t, ok := mdns.StringToType[typ]
	if !ok {
		return 0, ErrUnsupportedType
	}
	switch t {
	case mdns.TypeANY, mdns.TypeAXFR, mdns.TypeIXFR, mdns.TypeOPT, mdns.TypeTSIG, mdns.TypeMAILA, mdns.TypeMAILB, mdns.TypeNone:
		return 0, ErrUnsupportedType
	}
	return t, nil
}

// Check checks an RRset for subject. A result computed less than CacheTTL
// ago for the same content is returned with Cached set; other checks count
// against the rate limit of subject.
func (c *Checker) Check(ctx context.Context, subject string, req Request) (*Result, error) {
	qtype, err := QueryType(req.Type)
	if err != nil {
		return nil, err
	}
	key := cacheKey(req)
	if res, ok := c.cached(key); ok {
		return res, nil
	}
	if !c.allow(subject) {
		return nil, ErrRateLimited
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		if res, ok := c.cached(key); ok {
			return res, nil
		}
		res := c.run(context.WithoutCancel(ctx), req, qtype)
		c.store(key, *res)
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	res := *v.(*Result)
	res.Answers = slices.Clone(res.Answers)
	return &res, nil
}

func cacheKey(req Request) string {
	h := req.Hash
	if req.Expected == nil {
		h = "absent"
	}
	return strings.Join([]string{strings.ToLower(req.Zone), strings.ToLower(req.Host), strings.ToUpper(req.Type), h, strings.Join(req.NameServers, ",")}, "|")
}

func (c *Checker) cached(key string) (*Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || !c.opt.Now().Before(e.expires) {
		return nil, false
	}
	res := e.res
	res.Cached = true
	res.Answers = slices.Clone(res.Answers)
	return &res, true
}

func (c *Checker) store(key string, res Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opt.Now()
	if len(c.cache) >= maxCacheEntries {
		for k, e := range c.cache {
			if !now.Before(e.expires) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= maxCacheEntries {
			clear(c.cache)
		}
	}
	c.cache[key] = cached{res: res, expires: now.Add(c.opt.CacheTTL)}
}

// allow is a token bucket per subject: RequestsPerMinute, with a burst of a
// quarter of it (at least 5).
func (c *Checker) allow(subject string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opt.Now()
	rate := float64(c.opt.RequestsPerMinute) / 60
	burst := max(float64(c.opt.RequestsPerMinute)/4, 5)
	b := c.buckets[subject]
	if b == nil {
		if len(c.buckets) > 10000 {
			for k, o := range c.buckets {
				if now.Sub(o.last) > 10*time.Minute {
					delete(c.buckets, k)
				}
			}
		}
		b = &bucket{tokens: burst, last: now}
		c.buckets[subject] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type server struct {
	Answer
	addr string
}

type reply struct {
	msg *mdns.Msg
	rtt time.Duration
	tcp bool
	err error
}

// run asks every server, in parallel, within Timeout.
func (c *Checker) run(ctx context.Context, req Request, qtype uint16) *Result {
	ctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()
	zone := dns.NormalizeZone(req.Zone)
	host := dns.NormalizeHost(req.Host, zone)
	name := fqdn(zone, host)
	exp := expectedOf(zone, qtype, req)
	res := &Result{
		Zone: zone, Host: host, Type: strings.ToUpper(req.Type), Name: name, QueryType: mdns.TypeToString[qtype],
		Expected: exp, CheckedAt: c.opt.Now().UTC(),
	}

	servers := c.nameServers(ctx, zone, req.NameServers)
	auth := len(servers)
	for _, r := range c.opt.Resolvers {
		servers = append(servers, server{addr: resolverAddr(r.Address), Answer: Answer{
			Kind: KindResolver, Name: r.Name, Address: r.Address, Location: r.Location, Country: r.Country, Region: r.Region,
		}})
	}

	replies := make([]reply, len(servers))
	targets := make([]reply, len(servers))
	sem := make(chan struct{}, c.opt.Concurrency)
	var wg sync.WaitGroup
	for i := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				replies[i] = reply{err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			recurse := i >= auth
			replies[i] = c.exchange(ctx, servers[i].addr, name, qtype, recurse)
			if recurse && exp.AliasTarget != "" {
				targets[i] = c.exchange(ctx, servers[i].addr, exp.AliasTarget, qtype, true)
			}
		}()
	}
	wg.Wait()

	var authAddrs []string
	answers := make([]Answer, len(servers))
	for i, s := range servers {
		a := s.Answer
		fill(&a, name, qtype, replies[i], i < auth)
		answers[i] = a
		if i < auth && a.Status == "" && len(a.CNAMEs) == 0 {
			authAddrs = append(authAddrs, a.Values...)
		}
	}
	for i := range answers {
		a := &answers[i]
		if a.Status != "" {
			continue
		}
		switch {
		case exp.AliasTarget != "":
			a.Status = aliasStatus(a, i < auth, authAddrs, targets[i], exp.AliasTarget, qtype)
		default:
			a.Status = valueStatus(a, exp)
		}
	}
	res.Answers = answers
	res.Summary = summarize(answers)
	c.opt.Log.Debug("propagation check", "zone", zone, "host", host, "type", res.Type,
		"match", res.Summary.Match, "total", res.Summary.Total, "converged", res.Summary.Converged)
	return res
}

func resolverAddr(a string) string {
	if ap, err := netip.ParseAddrPort(a); err == nil {
		return ap.String()
	}
	return net.JoinHostPort(a, "53")
}

func expectedOf(zone string, qtype uint16, req Request) Expected {
	e := Expected{Values: []string{}}
	s := req.Expected
	if s == nil {
		return e
	}
	e.Exists, e.Hash, e.TTL = true, req.Hash, s.TTL
	switch {
	case s.Alias != nil:
		e.AliasTarget = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.Alias.Target)), ".") + "."
	case strings.EqualFold(req.Type, "APEX") && len(s.Values) > 0:
		e.AliasTarget = absName(zone, s.Values[0])
	default:
		vals := make([]string, 0, len(s.Values))
		for _, v := range s.Values {
			vals = append(vals, canonicalValue(zone, qtype, v))
		}
		e.Values = canonicalSet(vals)
	}
	return e
}

// nameServers resolves the authoritative servers of zone: the given NS
// names, else the NS looked up, one address each (IPv4 first).
func (c *Checker) nameServers(ctx context.Context, zone string, names []string) []server {
	if len(names) == 0 {
		ns, err := c.opt.Lookup.LookupNS(ctx, zone+".")
		if err != nil {
			c.opt.Log.Debug("propagation: name servers lookup", "zone", zone, "err", err)
		}
		for _, n := range ns {
			names = append(names, n.Host)
		}
	}
	seen := map[string]bool{}
	var hosts []string
	for _, n := range names {
		h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	if len(hosts) > maxNameServers {
		hosts = hosts[:maxNameServers]
	}
	out := make([]server, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = server{Answer: Answer{Kind: KindAuthoritative, Name: h}}
			lctx, cancel := context.WithTimeout(ctx, c.opt.QueryTimeout)
			defer cancel()
			addrs, err := c.opt.Lookup.LookupNetIP(lctx, "ip", h+".")
			if err != nil {
				out[i].Status, out[i].Error = StatusError, "name server address not found"
				return
			}
			addr, ok := pickAddr(addrs, c.opt.AllowPrivateNameServers)
			if !ok {
				out[i].Status, out[i].Error = StatusError, "no public address for the name server"
				return
			}
			out[i].Address = addr.String()
			out[i].addr = netip.AddrPortFrom(addr, c.opt.NameServerPort).String()
		}()
	}
	wg.Wait()
	return out
}

func pickAddr(addrs []netip.Addr, private bool) (netip.Addr, bool) {
	var v6 netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !private && !publicAddr(a) {
			continue
		}
		if a.Is4() {
			return a, true
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	return v6, v6.IsValid()
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func publicAddr(a netip.Addr) bool {
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(a)
}

// exchange asks one server over UDP with EDNS0, and again over TCP when
// the answer is truncated or UDP failed before the timeout (an ICMP
// unreachable, a filtered port).
func (c *Checker) exchange(ctx context.Context, addr, name string, qtype uint16, recurse bool) reply {
	if addr == "" {
		return reply{err: errors.New("no address")}
	}
	m := new(mdns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = recurse
	m.SetEdns0(1232, false)
	cl := &mdns.Client{Net: "udp", Timeout: c.opt.QueryTimeout, UDPSize: 1232}
	r, rtt, err := cl.ExchangeContext(ctx, m, addr)
	if err == nil && r.Truncated || err != nil && retryTCP(ctx, err) {
		tcp := &mdns.Client{Net: "tcp", Timeout: c.opt.QueryTimeout}
		r2, rtt2, err2 := tcp.ExchangeContext(ctx, m, addr)
		return reply{msg: r2, rtt: rtt + rtt2, tcp: true, err: err2}
	}
	return reply{msg: r, rtt: rtt, err: err}
}

// fill reads a reply into a: the records of name (following CNAMEs), their
// TTL, or the error status.
func fill(a *Answer, name string, qtype uint16, r reply, authoritative bool) {
	a.Values = []string{}
	if a.Status != "" {
		return
	}
	a.LatencyMS, a.TCP = r.rtt.Milliseconds(), r.tcp
	if r.err != nil {
		a.Status, a.Error = StatusError, exchangeError(r.err)
		return
	}
	m := r.msg
	a.Rcode = mdns.RcodeToString[m.Rcode]
	if m.Rcode != mdns.RcodeSuccess && m.Rcode != mdns.RcodeNameError {
		a.Status, a.Error = StatusError, strings.ToLower(a.Rcode)+ede(m)
		return
	}
	if authoritative && !m.Authoritative {
		a.Status, a.Error = StatusError, "not authoritative for the zone (lame delegation)"
		return
	}
	vals, cnames, ttl := records(m, name, qtype)
	a.Values, a.CNAMEs = vals, cnames
	if len(vals) == 0 && len(cnames) == 0 {
		ttl = negativeTTL(m)
	}
	if ttl >= 0 {
		a.TTLLeft = &ttl
	}
}

func retryTCP(ctx context.Context, err error) bool {
	var ne net.Error
	return ctx.Err() == nil && !(errors.As(err, &ne) && ne.Timeout()) && !errors.Is(err, context.DeadlineExceeded)
}

func exchangeError(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return "network error: " + oe.Op
	}
	return "no answer"
}

// ede renders the extended DNS error of a refusal (RFC 8914).
func ede(m *mdns.Msg) string {
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if e, ok := o.(*mdns.EDNS0_EDE); ok {
			s := mdns.ExtendedErrorCodeToString[e.InfoCode]
			if s == "" {
				s = fmt.Sprintf("code %d", e.InfoCode)
			}
			return " (" + strings.ToLower(s) + ")"
		}
	}
	return ""
}

// records returns the values of qtype at name or at the end of its CNAME
// chain, the chain, and the smallest TTL of what was used (-1 if none).
func records(m *mdns.Msg, name string, qtype uint16) ([]string, []string, int) {
	ttl := -1
	use := func(t uint32) {
		if ttl < 0 || int(t) < ttl {
			ttl = int(t)
		}
	}
	cur := strings.ToLower(name)
	var cnames []string
	if qtype != mdns.TypeCNAME {
		for range maxCNAMEChain {
			next := ""
			for _, rr := range m.Answer {
				if c, ok := rr.(*mdns.CNAME); ok && strings.EqualFold(c.Hdr.Name, cur) {
					next = strings.ToLower(c.Target)
					use(c.Hdr.Ttl)
					break
				}
			}
			if next == "" || slices.Contains(cnames, next) {
				break
			}
			cnames = append(cnames, next)
			cur = next
		}
	}
	vals := []string{}
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, cur) {
			vals = append(vals, canonicalRR(rr))
			use(rr.Header().Ttl)
		}
	}
	return canonicalSet(vals), cnames, ttl
}

// negativeTTL is how long a negative answer is cached: the smaller of the
// SOA TTL and its minimum (RFC 2308), -1 without SOA.
func negativeTTL(m *mdns.Msg) int {
	for _, rr := range m.Ns {
		if soa, ok := rr.(*mdns.SOA); ok {
			return int(min(soa.Hdr.Ttl, soa.Minttl))
		}
	}
	return -1
}

func valueStatus(a *Answer, exp Expected) string {
	switch {
	case !exp.Exists && len(a.Values) == 0 && len(a.CNAMEs) == 0:
		return StatusMatch
	case !exp.Exists:
		return StatusStale
	case len(a.Values) == 0 && len(a.CNAMEs) == 0:
		return StatusMissing
	case len(a.CNAMEs) == 0 && slices.Equal(a.Values, exp.Values):
		return StatusMatch
	}
	return StatusStale
}

// aliasStatus compares the addresses of an alias with those of its target:
// the authoritative answers, and the target asked from the same resolver
// (its addresses can depend on the location of the resolver, a CDN, or
// rotate, a load balancer). Sharing an address is a match.
func aliasStatus(a *Answer, authoritative bool, authAddrs []string, target reply, targetName string, qtype uint16) string {
	switch {
	case len(a.CNAMEs) > 0:
		return StatusStale
	case len(a.Values) == 0:
		return StatusMissing
	case authoritative:
		return StatusMatch
	}
	ref := slices.Clone(authAddrs)
	if target.err == nil && target.msg != nil && target.msg.Rcode == mdns.RcodeSuccess {
		vals, _, _ := records(target.msg, targetName, qtype)
		ref = append(ref, vals...)
	}
	if len(ref) == 0 {
		a.Error = "the alias target could not be resolved"
		return StatusError
	}
	if intersects(a.Values, ref) {
		return StatusMatch
	}
	return StatusStale
}

func summarize(answers []Answer) Summary {
	s := Summary{Total: len(answers)}
	for _, a := range answers {
		switch a.Status {
		case StatusMatch:
			s.Match++
		case StatusStale:
			s.Stale++
		case StatusMissing:
			s.Missing++
		default:
			s.Error++
		}
		if (a.Status == StatusStale || a.Status == StatusMissing) && a.TTLLeft != nil && *a.TTLLeft > s.MaxTTLLeft {
			s.MaxTTLLeft = *a.TTLLeft
		}
	}
	s.Converged = s.Match > 0 && s.Stale == 0 && s.Missing == 0
	return s
}
