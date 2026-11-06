//go:build live

package propagation

import (
	"context"
	"net"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
)

// TestLiveDefaultResolvers asks the real default resolvers and the
// authoritative servers of example.com for its NS RRset, as the system
// resolver reads it:
//
//	go test -tags live -run TestLive -v ./internal/propagation/
func TestLiveDefaultResolvers(t *testing.T) {
	ns, err := net.DefaultResolver.LookupNS(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	s := &dns.RRset{Key: dns.Key{Host: dns.Apex, Type: "NS"}, TTL: 86400}
	for _, n := range ns {
		s.Values = append(s.Values, n.Host)
	}
	res, err := New(Options{}).Check(context.Background(), "live", Request{Zone: "example.com", Host: dns.Apex, Type: "NS", Expected: s, Hash: dns.ContentHash(*s)})
	if err != nil {
		t.Fatal(err)
	}
	auth := 0
	for _, a := range res.Answers {
		ttl := -1
		if a.TTLLeft != nil {
			ttl = *a.TTLLeft
		}
		t.Logf("%-14s %-32s %-16s %-8s ttl=%-6d %4dms %s %v", a.Kind, a.Name, a.Address, a.Status, ttl, a.LatencyMS, a.Error, a.Values)
		if a.Kind == KindAuthoritative {
			auth++
			if a.Status != StatusMatch {
				t.Errorf("authoritative %s: %s %s", a.Name, a.Status, a.Error)
			}
		}
	}
	t.Logf("summary %+v", res.Summary)
	if auth == 0 {
		t.Error("no authoritative server asked")
	}
	if res.Summary.Match < res.Summary.Total/2 || res.Summary.Stale+res.Summary.Missing > 0 {
		t.Errorf("summary: %+v", res.Summary)
	}
}
