package propagation

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/KamorionLabs/dns-gate/internal/dns"
)

type zoneData map[string][]string

type fakeServer struct {
	addr     string
	port     uint16
	queries  atomic.Int32
	mu       sync.Mutex
	handlers map[string]func(*mdns.Msg, *mdns.Msg, bool)
}

func (f *fakeServer) handle(name string, qtype uint16, h func(req, resp *mdns.Msg, tcp bool)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[strings.ToLower(name)+"/"+mdns.TypeToString[qtype]] = h
}

func startServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{handlers: map[string]func(*mdns.Msg, *mdns.Msg, bool){}}
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
		pc = nil
	}
	if pc == nil {
		t.Fatal("no port for udp and tcp")
	}
	f.addr = pc.LocalAddr().String()
	f.port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	serve := func(tcp bool) mdns.HandlerFunc {
		return func(w mdns.ResponseWriter, req *mdns.Msg) {
			f.queries.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			f.mu.Lock()
			h := f.handlers[strings.ToLower(q.Name)+"/"+mdns.TypeToString[q.Qtype]]
			f.mu.Unlock()
			if h == nil {
				resp.Rcode = mdns.RcodeRefused
			} else {
				h(req, resp, tcp)
			}
			_ = w.WriteMsg(resp)
		}
	}
	udp := &mdns.Server{PacketConn: pc, Handler: serve(false)}
	tcpSrv := &mdns.Server{Listener: ln, Handler: serve(true)}
	var wg sync.WaitGroup
	wg.Add(2)
	udp.NotifyStartedFunc, tcpSrv.NotifyStartedFunc = wg.Done, wg.Done
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	wg.Wait()
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcpSrv.Shutdown()
	})
	return f
}

func rr(t *testing.T, s string) mdns.RR {
	t.Helper()
	r, err := mdns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func answer(t *testing.T, aa bool, rrs ...string) func(req, resp *mdns.Msg, tcp bool) {
	return func(req, resp *mdns.Msg, _ bool) {
		resp.Authoritative = aa
		for _, s := range rrs {
			resp.Answer = append(resp.Answer, rr(t, s))
		}
	}
}

func negative(t *testing.T, rcode int, aa bool) func(req, resp *mdns.Msg, tcp bool) {
	return func(req, resp *mdns.Msg, _ bool) {
		resp.Rcode, resp.Authoritative = rcode, aa
		resp.Ns = []mdns.RR{rr(t, "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 60")}
	}
}

type fakeLookup struct {
	ns    []string
	addrs map[string][]netip.Addr
}

func (l fakeLookup) LookupNS(_ context.Context, _ string) ([]*net.NS, error) {
	if len(l.ns) == 0 {
		return nil, errors.New("no ns")
	}
	out := make([]*net.NS, 0, len(l.ns))
	for _, n := range l.ns {
		out = append(out, &net.NS{Host: n})
	}
	return out, nil
}

func (l fakeLookup) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	a, ok := l.addrs[strings.TrimSuffix(host, ".")]
	if !ok {
		return nil, errors.New("not found")
	}
	return a, nil
}

type env struct {
	auth      *fakeServer
	resolvers []*fakeServer
	checker   *Checker
	now       time.Time
}

func newEnv(t *testing.T, n int, tweak func(*Options)) *env {
	t.Helper()
	e := &env{auth: startServer(t), now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	opt := Options{
		QueryTimeout: 300 * time.Millisecond, Timeout: 2 * time.Second, NameServerPort: e.auth.port,
		AllowPrivateNameServers: true, Now: func() time.Time { return e.now },
		Lookup: fakeLookup{ns: []string{"ns1.dns.test."}, addrs: map[string][]netip.Addr{"ns1.dns.test": {netip.MustParseAddr("127.0.0.1")}}},
	}
	for i := range n {
		s := startServer(t)
		e.resolvers = append(e.resolvers, s)
		opt.Resolvers = append(opt.Resolvers, Resolver{Name: "r" + strconv.Itoa(i), Address: s.addr, Location: "Paris", Country: "FR", Region: RegionEurope})
	}
	if tweak != nil {
		tweak(&opt)
	}
	e.checker = New(opt)
	return e
}

func (e *env) check(t *testing.T, req Request) *Result {
	t.Helper()
	res, err := e.checker.Check(context.Background(), "tester", req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func byName(res *Result) map[string]Answer {
	out := map[string]Answer{}
	for _, a := range res.Answers {
		out[a.Name] = a
	}
	return out
}

func aRequest(values ...string) Request {
	s := &dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 300, Values: values}
	return Request{Zone: "example.com", Host: "www", Type: "A", Expected: s, Hash: dns.ContentHash(*s)}
}

func TestCheckStatuses(t *testing.T) {
	e := newEnv(t, 4, nil)
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1", "www.example.com. 300 IN A 192.0.2.2"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 250 IN A 192.0.2.2", "www.example.com. 250 IN A 192.0.2.1"))
	e.resolvers[1].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 120 IN A 192.0.2.9"))
	e.resolvers[2].handle("www.example.com.", mdns.TypeA, negative(t, mdns.RcodeNameError, false))
	e.resolvers[3].handle("www.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, _ bool) {
		resp.Rcode = mdns.RcodeRefused
		resp.SetEdns0(1232, false)
		opt := resp.IsEdns0()
		opt.Option = append(opt.Option, &mdns.EDNS0_EDE{InfoCode: mdns.ExtendedErrorCodeCensored})
	})

	res := e.check(t, aRequest("192.0.2.2", "192.0.2.1"))
	got := byName(res)
	if a := got["ns1.dns.test"]; a.Kind != KindAuthoritative || a.Status != StatusMatch || a.Address != "127.0.0.1" || *a.TTLLeft != 300 {
		t.Errorf("authoritative: %+v", a)
	}
	if a := got["r0"]; a.Status != StatusMatch || *a.TTLLeft != 250 || !slices.Equal(a.Values, []string{"192.0.2.1", "192.0.2.2"}) || a.Region != RegionEurope || a.Rcode != "NOERROR" {
		t.Errorf("r0: %+v", a)
	}
	if a := got["r1"]; a.Status != StatusStale || *a.TTLLeft != 120 || a.Values[0] != "192.0.2.9" {
		t.Errorf("r1: %+v", a)
	}
	if a := got["r2"]; a.Status != StatusMissing || *a.TTLLeft != 60 || a.Rcode != "NXDOMAIN" {
		t.Errorf("r2: %+v", a)
	}
	if a := got["r3"]; a.Status != StatusError || a.Error != "refused (censored)" {
		t.Errorf("r3: %+v", a)
	}
	want := Summary{Total: 5, Match: 2, Stale: 1, Missing: 1, Error: 1, MaxTTLLeft: 120}
	if res.Summary != want || res.Name != "www.example.com." || res.QueryType != "A" || !res.Expected.Exists || res.Cached {
		t.Errorf("summary: %+v %+v", res.Summary, res)
	}
	if !res.CheckedAt.Equal(e.now) {
		t.Errorf("checked at %v", res.CheckedAt)
	}
}

func TestCheckRecursionAndAuthority(t *testing.T) {
	e := newEnv(t, 1, nil)
	e.auth.handle("www.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, _ bool) {
		if req.RecursionDesired {
			resp.Rcode = mdns.RcodeRefused
			return
		}
		resp.Answer = []mdns.RR{rr(t, "www.example.com. 300 IN A 192.0.2.1")}
	})
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, _ bool) {
		if !req.RecursionDesired || req.IsEdns0() == nil {
			resp.Rcode = mdns.RcodeRefused
			return
		}
		resp.Answer = []mdns.RR{rr(t, "www.example.com. 300 IN A 192.0.2.1")}
	})
	got := byName(e.check(t, aRequest("192.0.2.1")))
	if a := got["ns1.dns.test"]; a.Status != StatusError || !strings.Contains(a.Error, "lame") {
		t.Errorf("answer without AA: %+v", a)
	}
	if a := got["r0"]; a.Status != StatusMatch {
		t.Errorf("resolver: %+v", a)
	}
}

func TestCheckTimeoutAndUnreachable(t *testing.T) {
	e := newEnv(t, 1, func(o *Options) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		o.Resolvers = append(o.Resolvers, Resolver{Name: "silent", Address: pc.LocalAddr().String()})
		o.Lookup = fakeLookup{ns: []string{"ns1.dns.test.", "ns2.dns.test.", "ns3.dns.test."}, addrs: map[string][]netip.Addr{
			"ns1.dns.test": {netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")},
			"ns3.dns.test": {},
		}}
	})
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 300 IN A 192.0.2.1"))
	start := time.Now()
	res := e.check(t, aRequest("192.0.2.1"))
	if time.Since(start) > 2*time.Second {
		t.Errorf("check took %v", time.Since(start))
	}
	got := byName(res)
	if a := got["silent"]; a.Status != StatusError || a.Error != "timeout" {
		t.Errorf("silent: %+v", a)
	}
	if a := got["ns1.dns.test"]; a.Status != StatusMatch || a.Address != "127.0.0.1" {
		t.Errorf("ns1 (IPv4 preferred): %+v", a)
	}
	if a := got["ns2.dns.test"]; a.Status != StatusError || a.Error != "name server address not found" {
		t.Errorf("ns2: %+v", a)
	}
	if a := got["ns3.dns.test"]; a.Status != StatusError || a.Error != "no public address for the name server" {
		t.Errorf("ns3: %+v", a)
	}
	if !res.Summary.Converged || res.Summary.Match != 2 || res.Summary.Error != 3 {
		t.Errorf("summary: %+v", res.Summary)
	}
}

func TestCheckSkipsPrivateNameServers(t *testing.T) {
	e := newEnv(t, 1, func(o *Options) { o.AllowPrivateNameServers = false })
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 300 IN A 192.0.2.1"))
	res := e.check(t, aRequest("192.0.2.1"))
	if a := byName(res)["ns1.dns.test"]; a.Status != StatusError || a.Address != "" || e.auth.queries.Load() != 0 {
		t.Errorf("private name server asked: %+v (%d queries)", a, e.auth.queries.Load())
	}
	for _, a := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fd00::1", "0.0.0.0", "224.0.0.1"} {
		if PublicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s is public", a)
		}
	}
	if !PublicAddr(netip.MustParseAddr("205.251.192.1")) {
		t.Error("public address refused")
	}
}

func TestCheckGivenNameServers(t *testing.T) {
	e := newEnv(t, 1, func(o *Options) {
		o.Lookup = fakeLookup{addrs: map[string][]netip.Addr{"ns-1.awsdns-1.org": {netip.MustParseAddr("127.0.0.1")}}}
	})
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1"))
	req := aRequest("192.0.2.1")
	req.NameServers = []string{"NS-1.awsdns-1.org.", "ns-1.awsdns-1.org"}
	res := e.check(t, req)
	if len(res.Answers) != 2 || res.Answers[0].Name != "ns-1.awsdns-1.org" || res.Answers[0].Status != StatusMatch {
		t.Errorf("answers: %+v", res.Answers)
	}
}

func TestCheckTCPFallback(t *testing.T) {
	e := newEnv(t, 1, nil)
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, tcp bool) {
		if !tcp {
			resp.Truncated = true
			return
		}
		resp.Answer = []mdns.RR{rr(t, "www.example.com. 300 IN A 192.0.2.1")}
	})
	if a := byName(e.check(t, aRequest("192.0.2.1")))["r0"]; a.Status != StatusMatch || !a.TCP {
		t.Errorf("truncated answer: %+v", a)
	}
}

func TestCheckTXT(t *testing.T) {
	long := strings.Repeat("a", 300)
	e := newEnv(t, 3, nil)
	answers := answer(t, false, `example.com. 300 IN TXT "v=spf1 " "include:_spf.example.net -all"`, `example.com. 300 IN TXT "`+long[:255]+`" "`+long[255:]+`"`, `example.com. 300 IN TXT "say \"hi\""`)
	e.auth.handle("example.com.", mdns.TypeTXT, func(req, resp *mdns.Msg, tcp bool) { answers(req, resp, tcp); resp.Authoritative = true })
	e.resolvers[0].handle("example.com.", mdns.TypeTXT, answers)
	e.resolvers[1].handle("example.com.", mdns.TypeTXT, answer(t, false, `example.com. 300 IN TXT "v=spf1 include:_spf.example.net -all"`))
	e.resolvers[2].handle("example.com.", mdns.TypeTXT, answer(t, false, `example.com. 300 IN TXT "v=spf1 include:_spf.example.net -all" "`+long+`"`))
	for name, values := range map[string][]string{
		"route53": {"v=spf1 include:_spf.example.net -all", long, `say "hi"`},
		"eurodns": {`"v=spf1 include:_spf.example.net -all"`, `"` + long[:255] + `" "` + long[255:] + `"`, `"say \"hi\""`},
	} {
		s := &dns.RRset{Key: dns.Key{Host: "@", Type: "TXT"}, TTL: 300, Values: values}
		res := e.check(t, Request{Zone: "example.com", Host: "@", Type: "TXT", Expected: s, Hash: name})
		got := byName(res)
		if got["ns1.dns.test"].Status != StatusMatch || got["r0"].Status != StatusMatch || got["r1"].Status != StatusStale || got["r2"].Status != StatusStale {
			t.Errorf("%s: %+v", name, res.Answers)
		}
	}
}

func TestCheckMXAndRelativeTargets(t *testing.T) {
	e := newEnv(t, 1, nil)
	e.auth.handle("example.com.", mdns.TypeMX, answer(t, true, "example.com. 300 IN MX 20 Backup.Example.NET.", "example.com. 300 IN MX 10 mail.example.com."))
	e.resolvers[0].handle("example.com.", mdns.TypeMX, answer(t, false, "example.com. 300 IN MX 10 MAIL.example.com.", "example.com. 300 IN MX 20 backup.example.net."))
	s := &dns.RRset{Key: dns.Key{Host: "@", Type: "MX"}, TTL: 300, Values: []string{"10 mail", "20 backup.example.net."}}
	res := e.check(t, Request{Zone: "example.com", Host: "@", Type: "MX", Expected: s, Hash: "h"})
	if res.Summary.Match != 2 || !slices.Equal(res.Expected.Values, []string{"10 mail.example.com.", "20 backup.example.net."}) {
		t.Errorf("mx: %+v %+v", res.Expected, res.Answers)
	}
}

func TestCheckCNAMEChain(t *testing.T) {
	e := newEnv(t, 2, nil)
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 90 IN CNAME edge.example.net.", "edge.example.net. 30 IN CNAME edge2.example.net.", "edge2.example.net. 60 IN A 192.0.2.1"))
	e.resolvers[1].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 300 IN A 192.0.2.1"))
	res := e.check(t, aRequest("192.0.2.1"))
	a := byName(res)["r0"]
	if a.Status != StatusStale || !slices.Equal(a.CNAMEs, []string{"edge.example.net.", "edge2.example.net."}) || *a.TTLLeft != 30 || a.Values[0] != "192.0.2.1" {
		t.Errorf("chain: %+v", a)
	}

	e.auth.handle("app.example.com.", mdns.TypeCNAME, answer(t, true, "app.example.com. 300 IN CNAME Target.Example.NET."))
	e.resolvers[0].handle("app.example.com.", mdns.TypeCNAME, answer(t, false, "app.example.com. 300 IN CNAME target.example.net."))
	e.resolvers[1].handle("app.example.com.", mdns.TypeCNAME, answer(t, false, "app.example.com. 300 IN CNAME old.example.net."))
	s := &dns.RRset{Key: dns.Key{Host: "app", Type: "CNAME"}, TTL: 300, Values: []string{"target.example.net."}}
	got := byName(e.check(t, Request{Zone: "example.com", Host: "app", Type: "CNAME", Expected: s, Hash: "c"}))
	if got["ns1.dns.test"].Status != StatusMatch || got["r0"].Status != StatusMatch || got["r1"].Status != StatusStale {
		t.Errorf("cname: %+v", got)
	}
}

func TestCheckAlias(t *testing.T) {
	e := newEnv(t, 4, func(o *Options) {
		l := o.Lookup.(fakeLookup)
		l.addrs["d111.cloudfront.net"] = []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("2001:db8::1")}
		l.addrs["lb.example.net"] = []netip.Addr{netip.MustParseAddr("198.51.100.4")}
	})
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 60 IN A 198.51.100.1", "www.example.com. 60 IN A 198.51.100.2"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 60 IN A 203.0.113.7"))
	e.resolvers[0].handle("d111.cloudfront.net.", mdns.TypeA, answer(t, false, "d111.cloudfront.net. 60 IN A 203.0.113.7", "d111.cloudfront.net. 60 IN A 203.0.113.8"))
	e.resolvers[1].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 60 IN A 192.0.2.50"))
	e.resolvers[1].handle("d111.cloudfront.net.", mdns.TypeA, answer(t, false, "d111.cloudfront.net. 60 IN A 203.0.113.9"))
	e.resolvers[2].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 60 IN A 198.51.100.2"))
	e.resolvers[3].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 60 IN A 203.0.113.7", "www.example.com. 60 IN A 192.0.2.66"))
	e.resolvers[3].handle("d111.cloudfront.net.", mdns.TypeA, answer(t, false, "d111.cloudfront.net. 60 IN A 203.0.113.7"))
	s := &dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, Alias: &dns.Alias{Target: "D111.cloudfront.net", HostedZoneID: "Z2FDTNDATAQYW2"}}
	res := e.check(t, Request{Zone: "example.com", Host: "www", Type: "A", Expected: s, Hash: dns.ContentHash(*s)})
	got := byName(res)
	if res.Expected.AliasTarget != "d111.cloudfront.net." || got["ns1.dns.test"].Status != StatusMatch || got["r0"].Status != StatusMatch ||
		got["r1"].Status != StatusIndeterminate || got["r2"].Status != StatusIndeterminate || got["r3"].Status != StatusIndeterminate {
		t.Errorf("alias: %+v %+v", res.Expected, got)
	}
	if res.Summary.Indeterminate != 3 || res.Summary.Converged {
		t.Errorf("alias summary: %+v", res.Summary)
	}

	apex := &dns.RRset{Key: dns.Key{Host: "@", Type: "APEX"}, TTL: 600, Values: []string{"lb.example.net."}}
	e.auth.handle("example.com.", mdns.TypeA, answer(t, true, "example.com. 600 IN A 198.51.100.3"))
	for _, r := range e.resolvers {
		r.handle("example.com.", mdns.TypeA, answer(t, false, "example.com. 600 IN A 198.51.100.3"))
		r.handle("lb.example.net.", mdns.TypeA, answer(t, false, "lb.example.net. 600 IN A 198.51.100.3"))
	}
	res = e.check(t, Request{Zone: "example.com", Host: "@", Type: "APEX", Expected: apex, Hash: "x"})
	if a := byName(res)["ns1.dns.test"]; a.Status != StatusIndeterminate || res.Summary.Converged {
		t.Errorf("authoritative answer outside the resolved target: %+v %+v", a, res.Summary)
	}
	e.checker.opt.Lookup.(fakeLookup).addrs["lb.example.net"] = []netip.Addr{netip.MustParseAddr("198.51.100.3")}
	res = e.check(t, Request{Zone: "example.com", Host: "@", Type: "APEX", Expected: apex, Hash: "y"})
	if res.QueryType != "A" || res.Expected.AliasTarget != "lb.example.net." || !res.Summary.Converged {
		t.Errorf("apex: %+v", res)
	}
}

func TestCheckDeleted(t *testing.T) {
	e := newEnv(t, 2, nil)
	e.auth.handle("old.example.com.", mdns.TypeA, negative(t, mdns.RcodeNameError, true))
	e.resolvers[0].handle("old.example.com.", mdns.TypeA, negative(t, mdns.RcodeSuccess, false))
	e.resolvers[1].handle("old.example.com.", mdns.TypeA, answer(t, false, "old.example.com. 40 IN A 192.0.2.1"))
	res := e.check(t, Request{Zone: "example.com", Host: "old", Type: "A"})
	got := byName(res)
	if res.Expected.Exists || got["ns1.dns.test"].Status != StatusMatch || got["r0"].Status != StatusMatch || got["r1"].Status != StatusStale || res.Summary.MaxTTLLeft != 40 {
		t.Errorf("deleted: %+v", got)
	}
}

func TestCheckCacheAndRateLimit(t *testing.T) {
	e := newEnv(t, 1, func(o *Options) { o.RequestsPerMinute = 6 })
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 300 IN A 192.0.2.1"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 300 IN A 192.0.2.1"))
	req := aRequest("192.0.2.1")
	first := e.check(t, req)
	n := e.resolvers[0].queries.Load()
	second := e.check(t, req)
	if first.Cached || !second.Cached || e.resolvers[0].queries.Load() != n {
		t.Fatalf("cache: %v %v %d->%d", first.Cached, second.Cached, n, e.resolvers[0].queries.Load())
	}
	other := req
	other.Hash = "other"
	if r := e.check(t, other); r.Cached {
		t.Error("another content served from the cache")
	}
	e.now = e.now.Add(11 * time.Second)
	if r := e.check(t, req); r.Cached {
		t.Error("expired entry served")
	}
	var limited bool
	for i := range 10 {
		r := req
		r.Hash = strconv.Itoa(i)
		if _, err := e.checker.Check(context.Background(), "tester", r); errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("never rate limited")
	}
	if _, err := e.checker.Check(context.Background(), "tester", req); err != nil {
		t.Errorf("cached result refused: %v", err)
	}
	if _, err := e.checker.Check(context.Background(), "other", other); err != nil {
		t.Errorf("other subject: %v", err)
	}
}

func TestQueryType(t *testing.T) {
	for typ, want := range map[string]uint16{"a": mdns.TypeA, "APEX": mdns.TypeA, "TXT": mdns.TypeTXT, "HTTPS": mdns.TypeHTTPS} {
		if got, err := QueryType(typ); err != nil || got != want {
			t.Errorf("%s: %d %v", typ, got, err)
		}
	}
	for _, typ := range []string{"ANY", "AXFR", "NOPE", ""} {
		if _, err := QueryType(typ); !errors.Is(err, ErrUnsupportedType) {
			t.Errorf("%s accepted", typ)
		}
	}
	e := newEnv(t, 1, nil)
	if _, err := e.checker.Check(context.Background(), "s", Request{Zone: "example.com", Host: "@", Type: "AXFR"}); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("AXFR: %v", err)
	}
}

func TestCanonicalValue(t *testing.T) {
	for _, c := range []struct {
		typ   uint16
		value string
		rr    string
	}{
		{mdns.TypeAAAA, "2001:DB8:0:0::1", "x. 1 IN AAAA 2001:db8::1"},
		{mdns.TypeCAA, `0 ISSUE "letsencrypt.org"`, `x. 1 IN CAA 0 issue "letsencrypt.org"`},
		{mdns.TypeDS, "12345 13 2 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "x. 1 IN DS 12345 13 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"},
		{mdns.TypeTLSA, "3 1 1 ABCDEF", "x. 1 IN TLSA 3 1 1 abcdef"},
		{mdns.TypeSRV, "10 5 443 sip", "x. 1 IN SRV 10 5 443 SIP.example.com."},
		{mdns.TypeCNAME, "@", "x. 1 IN CNAME example.com."},
		{mdns.TypeHTTPS, `1 . alpn="h2,h3"`, `x. 1 IN HTTPS 1 . alpn="h2,h3"`},
	} {
		if got, want := canonicalValue("example.com", c.typ, c.value), canonicalRR(rr(t, c.rr)); got != want {
			t.Errorf("%s %q: %q, want %q", mdns.TypeToString[c.typ], c.value, got, want)
		}
	}
	if got := canonicalValue("example.com", mdns.TypeA, "not an address"); got != "not an address" {
		t.Errorf("invalid value: %q", got)
	}
}

func TestCheckTTL(t *testing.T) {
	e := newEnv(t, 2, nil)
	e.auth.handle("www.example.com.", mdns.TypeA, answer(t, true, "www.example.com. 3600 IN A 192.0.2.1"))
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 3000 IN A 192.0.2.1"))
	e.resolvers[1].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 200 IN A 192.0.2.1"))
	s := &dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}}
	res := e.check(t, Request{Zone: "example.com", Host: "www", Type: "A", Expected: s, Hash: dns.ContentHash(*s)})
	got := byName(res)
	if got["ns1.dns.test"].Status != StatusStale || got["r0"].Status != StatusStale || got["r1"].Status != StatusMatch || res.Summary.Converged {
		t.Errorf("TTL-only change: %+v", got)
	}
}

func TestCheckUnusableAnswers(t *testing.T) {
	e := newEnv(t, 3, func(o *Options) { o.Resolvers[2].Filtering = true })
	e.auth.handle("old.example.com.", mdns.TypeA, negative(t, mdns.RcodeNameError, true))
	e.resolvers[0].handle("old.example.com.", mdns.TypeA, answer(t, false, "other.example.net. 60 IN A 192.0.2.1"))
	e.resolvers[1].handle("old.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, _ bool) {
		resp.Answer = []mdns.RR{rr(t, "old.example.com. 60 IN A 0.0.0.0")}
		resp.SetEdns0(1232, false)
		resp.IsEdns0().Option = append(resp.IsEdns0().Option, &mdns.EDNS0_EDE{InfoCode: mdns.ExtendedErrorCodeBlocked})
	})
	e.resolvers[2].handle("old.example.com.", mdns.TypeA, negative(t, mdns.RcodeSuccess, false))
	res := e.check(t, Request{Zone: "example.com", Host: "old", Type: "A"})
	got := byName(res)
	if a := got["r0"]; a.Status != StatusError || !strings.Contains(a.Error, "records") {
		t.Errorf("records of another name: %+v", a)
	}
	if a := got["r1"]; a.Status != StatusError || !strings.Contains(a.Error, "blocked") {
		t.Errorf("blocked answer: %+v", a)
	}
	if a := got["r2"]; a.Status != StatusMatch || !a.Filtering {
		t.Errorf("negative answer of a filtering resolver: %+v", a)
	}

	e.auth.handle("old.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, _ bool) { resp.Rcode = mdns.RcodeServerFailure })
	e.resolvers[0].handle("old.example.com.", mdns.TypeA, negative(t, mdns.RcodeNameError, false))
	e.now = e.now.Add(time.Minute)
	res = e.check(t, Request{Zone: "example.com", Host: "old", Type: "A"})
	if res.Summary.Converged || res.Summary.Match == 0 {
		t.Errorf("converged without an authoritative answer: %+v", res.Summary)
	}
}

func TestCheckCapsAnswers(t *testing.T) {
	e := newEnv(t, 1, nil)
	var rrs []string
	for i := range 100 {
		rrs = append(rrs, "big.example.com. 300 IN TXT \"v"+strconv.Itoa(i)+strings.Repeat("x", 250)+"\" \""+strings.Repeat("y", 250)+"\"")
	}
	big := func(aa bool) func(req, resp *mdns.Msg, tcp bool) {
		return func(req, resp *mdns.Msg, tcp bool) {
			resp.Authoritative = aa
			if !tcp {
				resp.Truncated = true
				return
			}
			answer(t, aa, rrs...)(req, resp, tcp)
		}
	}
	e.auth.handle("big.example.com.", mdns.TypeTXT, big(true))
	e.resolvers[0].handle("big.example.com.", mdns.TypeTXT, big(false))
	s := &dns.RRset{Key: dns.Key{Host: "big", Type: "TXT"}, TTL: 300, Values: []string{"v"}}
	res := e.check(t, Request{Zone: "example.com", Host: "big", Type: "TXT", Expected: s, Hash: "h"})
	for _, a := range res.Answers {
		if len(a.Values) > MaxValues || !a.Truncated {
			t.Errorf("%s: %d values, truncated %v", a.Name, len(a.Values), a.Truncated)
		}
		for _, v := range a.Values {
			if len(v) > MaxValueBytes+len("…") {
				t.Errorf("value of %d bytes", len(v))
			}
		}
	}
}

func TestCheckInFlightCap(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, 1, func(o *Options) { o.MaxInFlight = 1; o.Timeout = 3 * time.Second; o.QueryTimeout = 2 * time.Second })
	e.auth.handle("www.example.com.", mdns.TypeA, func(req, resp *mdns.Msg, _ bool) {
		<-release
		resp.Authoritative = true
	})
	e.resolvers[0].handle("www.example.com.", mdns.TypeA, answer(t, false, "www.example.com. 300 IN A 192.0.2.1"))
	done := make(chan error, 1)
	go func() {
		_, err := e.checker.Check(context.Background(), "a", aRequest("192.0.2.1"))
		done <- err
	}()
	for e.auth.queries.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	other := aRequest("192.0.2.1")
	other.Hash = "other"
	if _, err := e.checker.Check(context.Background(), "b", other); !errors.Is(err, ErrBusy) {
		t.Errorf("second check while one runs: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := e.checker.Check(context.Background(), "b", other); err != nil {
		t.Errorf("after the first check: %v", err)
	}
}

func TestSubjectBucketsBounded(t *testing.T) {
	c := New(Options{MaxSubjects: 8, Resolvers: []Resolver{{Name: "x", Address: "192.0.2.53"}}})
	for i := range 100 {
		c.allow("s" + strconv.Itoa(i))
	}
	if n := c.subjects.Len(); n > 8 {
		t.Fatalf("%d buckets kept", n)
	}
}

func TestPublicAddr(t *testing.T) {
	for _, a := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.0.0.8", "192.0.2.1", "192.88.99.1",
		"192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::1", "2002:a00:1::1", "2002:7f00:1::",
		"2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:db8::1", "3fff::1", "fec0::1", "fe80::1", "fc00::1", "fd00::1", "100::1", "ff02::1",
	} {
		if PublicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s is public", a)
		}
	}
	for _, a := range []string{"205.251.192.1", "1.1.1.1", "2600:9000:5300::1", "64:ff9b::808:808", "2002:808:808::1", "::ffff:8.8.8.8"} {
		if !PublicAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s refused", a)
		}
	}
}
