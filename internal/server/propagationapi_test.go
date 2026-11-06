package server

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/propagation"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

type fakePropagator struct {
	mu   sync.Mutex
	reqs []propagation.Request
	subj []string
	err  error
}

func (f *fakePropagator) Check(_ context.Context, subject string, req propagation.Request) (*propagation.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.reqs, f.subj = append(f.reqs, req), append(f.subj, subject)
	return &propagation.Result{Zone: req.Zone, Host: req.Host, Type: req.Type, Answers: []propagation.Answer{}, Summary: propagation.Summary{Total: 1, Match: 1, Converged: true}}, nil
}

func (f *fakePropagator) last(t *testing.T) propagation.Request {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		t.Fatal("no check")
	}
	return f.reqs[len(f.reqs)-1]
}

type nsEngine struct{ *fakeEngine }

func (n nsEngine) RRset(ctx context.Context, s *identity.Subject, zone string, key dns.Key) (*uiapi.RRset, error) {
	if key == (dns.Key{Host: dns.Apex, Type: "NS"}) {
		return &uiapi.RRset{Host: dns.Apex, Type: "NS", TTL: 172800, Values: []string{"ns1.dns.test.", "ns2.dns.test."}, Status: uiapi.StatusForeign}, nil
	}
	return n.fakeEngine.RRset(ctx, s, zone, key)
}

func propagationEnv(t *testing.T) (*env, *fakePropagator) {
	t.Helper()
	e := mcpEnv(t, false)
	if e.server.cfg.Propagation == nil {
		t.Fatal("propagation not enabled by default")
	}
	f := &fakePropagator{}
	e.server.cfg.Propagation = f
	e.server.cfg.Engine = nsEngine{e.engine}
	return e, f
}

func TestPropagationAPI(t *testing.T) {
	e, f := propagationEnv(t)
	tok := e.token("writer")
	events := len(e.audit.events)
	r := e.do(t, "GET", "/api/v1/zones/Example.com/rrsets/WWW/a/propagation", tok, "", nil)
	res := decode[propagation.Result](t, r)
	hash := dns.ContentHash(dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 600, Values: []string{"192.0.2.1"}})
	req := f.last(t)
	if r.StatusCode != 200 || !res.Summary.Converged || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("check: %d %+v", r.StatusCode, res)
	}
	if req.Zone != "example.com" || req.Host != "www" || req.Type != "A" || req.Expected == nil || req.Expected.Values[0] != "192.0.2.1" ||
		req.Hash != hash || strings.Join(req.NameServers, ",") != "ns1.dns.test.,ns2.dns.test." || !strings.HasSuffix(f.subj[0], ":writer") {
		t.Fatalf("request: %+v %v", req, f.subj)
	}

	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/gone/A/propagation?expect=absent", tok, "", nil); r.StatusCode != 200 || f.last(t).Expected != nil || f.last(t).Host != "gone" {
		t.Fatalf("deleted RRset: %d %+v", r.StatusCode, f.last(t))
	}
	for query, status := range map[string]int{
		"?expect=" + hash:            200,
		"?expect=%22" + hash + "%22": 200,
		"?expect=0123":               412,
		"?expect=absent":             412,
	} {
		if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/www/A/propagation"+query, tok, "", nil); r.StatusCode != status {
			t.Errorf("%s: %d, want %d", query, r.StatusCode, status)
		}
	}
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/gone/A/propagation?expect="+hash, tok, "", nil); r.StatusCode != 412 {
		t.Errorf("expect on a missing RRset: %d", r.StatusCode)
	}

	for path, status := range map[string]int{
		"/api/v1/zones/example.org/rrsets/www/A/propagation":    403,
		"/api/v1/zones/example.net/rrsets/www/A/propagation":    404,
		"/api/v1/zones/example.com/rrsets/www/AXFR/propagation": 400,
		"/api/v1/zones/example.com/rrsets/a.*/A/propagation":    400,
		"/api/v1/zones/not_a_zone/rrsets/www/A/propagation":     400,
	} {
		if r := e.do(t, "GET", path, tok, "", nil); r.StatusCode != status {
			t.Errorf("GET %s: %d, want %d", path, r.StatusCode, status)
		}
	}
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/www/A/propagation", e.token("admin"), "", nil); r.StatusCode != 403 {
		t.Errorf("without dns.read: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/api/v1/zones/example.com/rrsets/www/A/propagation", tok, "{}", nil); r.StatusCode != 405 {
		t.Errorf("POST: %d", r.StatusCode)
	}
	if len(e.audit.events) != events {
		t.Errorf("checks audited: %+v", e.audit.events[events:])
	}

	f.err = propagation.ErrRateLimited
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/www/A/propagation", tok, "", nil); r.StatusCode != 429 || r.Header.Get("Retry-After") == "" {
		t.Errorf("rate limited: %d", r.StatusCode)
	}
	e.server.cfg.Propagation = nil
	if r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/www/A/propagation", tok, "", nil); r.StatusCode != 501 {
		t.Errorf("disabled: %d", r.StatusCode)
	}
}

func TestPropagationDisabled(t *testing.T) {
	off := false
	e := newEnvWith(t, func(c *config.Config) { c.Propagation.Enabled = &off })
	if e.server.cfg.Propagation != nil {
		t.Fatal("checker built while disabled")
	}
}

func TestMCPCheckPropagation(t *testing.T) {
	e, f := propagationEnv(t)
	cs := connect(t, e, e.token("writer"))
	tool := toolNames(t, cs)["check_propagation"]
	if tool == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
		t.Fatalf("tool: %+v", tool)
	}
	events := len(e.audit.events)
	var out propagation.Result
	if res := call(t, cs, "check_propagation", map[string]any{"zone": "example.com.", "host": "www", "type": "a"}, &out); res.IsError || !out.Summary.Converged || f.last(t).Hash == "" {
		t.Fatalf("check: %s %+v", errText(res), out)
	}
	if res := call(t, cs, "check_propagation", map[string]any{"zone": "example.org", "host": "www", "type": "A"}, nil); !res.IsError || !strings.Contains(errText(res), "dns.read") {
		t.Fatalf("unreadable zone: %s", errText(res))
	}
	if res := call(t, cs, "check_propagation", map[string]any{"zone": "example.com", "host": "www", "type": "A", "expect": "absent"}, nil); !res.IsError {
		t.Fatal("expect absent accepted")
	}
	for _, ev := range e.audit.events[events:] {
		if strings.Contains(ev.Action, "propagation") {
			t.Errorf("audited: %+v", ev)
		}
	}
}

// TestPropagationEndToEnd runs a real checker against an in-process name
// server answering as authoritative and as resolver.
func TestPropagationEndToEnd(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Authoritative = !req.RecursionDesired
		if q := req.Question[0]; q.Name == "www.example.com." && q.Qtype == mdns.TypeA {
			rr, _ := mdns.NewRR("www.example.com. 600 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })

	e, _ := propagationEnv(t)
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	e.server.cfg.Propagation = propagation.New(propagation.Options{
		Resolvers:    []propagation.Resolver{{Name: "local", Address: pc.LocalAddr().String(), Location: "Paris", Country: "FR", Region: propagation.RegionEurope}},
		QueryTimeout: time.Second, NameServerPort: port, AllowPrivateNameServers: true,
		Lookup: staticLookup{"ns1.dns.test": netip.MustParseAddr("127.0.0.1")},
	})
	r := e.do(t, "GET", "/api/v1/zones/example.com/rrsets/www/A/propagation", e.token("writer"), "", nil)
	res := decode[propagation.Result](t, r)
	if r.StatusCode != 200 || res.Summary.Total != 3 || res.Summary.Match != 2 || res.Summary.Error != 1 || !res.Summary.Converged || res.Name != "www.example.com." {
		t.Fatalf("check: %d %+v", r.StatusCode, res)
	}
}

type staticLookup map[string]netip.Addr

func (s staticLookup) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, nil }

func (s staticLookup) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := s[strings.TrimSuffix(host, ".")]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
