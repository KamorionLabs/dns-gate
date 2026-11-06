package eurodns

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	api "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

func id(n int64) *int64 { return &n }

func sample() *api.Zone {
	locked := true
	return &api.Zone{
		Name: "example.com",
		Records: []api.Record{
			{ID: id(1), Type: "SOA", Host: "@", TTL: 86400, Locked: &locked, RData: "ns1.example.net. hostmaster.example.com. 1 2 3 4 5"},
			{ID: id(2), Type: "NS", Host: "@", TTL: 86400, Locked: &locked, RData: "ns1.example.net."},
			{ID: id(3), Type: "a", Host: "WWW.example.com.", TTL: 600, RData: "192.0.2.2"},
			{ID: id(4), Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"},
			{ID: id(5), Type: "TXT", Host: "", TTL: 3600, RData: "\"v=spf1 -all\""},
			{ID: id(6), Type: "MX", Host: "@", TTL: 3600, RData: "10 mx.example.net."},
			{ID: id(7), Type: "CNAME", Host: "rel", TTL: 3600, RData: "internal"},
		},
		URLForwards: []json.RawMessage{json.RawMessage(`{"id":9,"host":"go","forwardType":"HTTP302","url":"https://example.net/x"}`)},
	}
}

// The ownership entries written before the provider-neutral model hold
// rrset.ContentHash of the user records grouped by eurodns-go: the adapter's
// RRsets must hash the same.
func TestContentHashMatchesLegacyEngine(t *testing.T) {
	native := sample()
	z := FromNative("eurodns", "Example.com.", native)
	var user []api.Record
	for _, r := range native.Records {
		if !rrset.ServerManaged(r) {
			user = append(user, r)
		}
	}
	legacy := rrset.Group("example.com", user)
	n := 0
	for _, s := range z.RRsets {
		if s.ReadOnly == ReadOnlyServerManaged || s.Key.IsForward() {
			continue
		}
		n++
		old, ok := legacy[rrset.Key{Host: s.Key.Host, Type: s.Key.Type}]
		if !ok {
			t.Fatalf("%s missing from the legacy grouping", s.Key)
		}
		if got, want := dns.ContentHash(s), rrset.ContentHash(old); got != want {
			t.Fatalf("%s: hash %s, legacy %s", s.Key, got, want)
		}
	}
	if n != len(legacy) || n != 4 {
		t.Fatalf("%d user RRsets, legacy %d", n, len(legacy))
	}
	if z.Provider != "eurodns" || z.Name != "example.com" || z.RRsets[0].Key != (dns.Key{Host: "@", Type: "MX"}) {
		t.Fatalf("zone %+v", z)
	}
	for _, s := range z.RRsets {
		if (s.Key.Type == "SOA" || s.Key.Type == "NS") != (s.ReadOnly == ReadOnlyServerManaged) {
			t.Fatalf("read-only flag on %s: %q", s.Key, s.ReadOnly)
		}
		if (s.Key.Host == "rel") != (s.ReadOnly == CodeRelativeTarget) {
			t.Fatalf("relative target flag on %s: %q", s.Key, s.ReadOnly)
		}
	}
}

func TestNormalize(t *testing.T) {
	p := &Provider{id: "eurodns"}
	s, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "WWW.example.com.", Type: "a"}, TTL: 600, Values: []string{"192.0.2.2", "192.0.2.1"}})
	if err != nil || s.Key != (dns.Key{Host: "www", Type: "A"}) || s.Values[0] != "192.0.2.1" {
		t.Fatalf("%+v %v", s, err)
	}
	var ie *provider.InvalidError
	if _, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}}); !errors.As(err, &ie) || !strings.Contains(err.Error(), "TTL 300") {
		t.Fatalf("ttl: %v", err)
	}
	if _, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "m", Type: "MX"}, TTL: 600, Values: []string{"10 mail"}}); !errors.As(err, &ie) || ie.Code != CodeRelativeTarget {
		t.Fatalf("single label: %v", err)
	}
	for typ, in := range map[string][2]string{
		"MX":    {"10 mx.example.net", "10 mx.example.net."},
		"SRV":   {"10 5 5060 sip.example.net", "10 5 5060 sip.example.net."},
		"CNAME": {" target.example.net ", "target.example.net."},
		"TXT":   {"no.dot here", "no.dot here"},
	} {
		recs := []api.Record{{Type: typ, Host: "x", TTL: 600, RData: in[0]}}
		s, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "x", Type: typ}, TTL: 600, Values: []string{in[0]}, Native: recs})
		if err != nil || s.Values[0] != in[1] || Records(&s)[0].RData != in[1] || recs[0].RData != in[0] {
			t.Fatalf("%s %q: %+v %v", typ, in[0], s, err)
		}
	}
	if _, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "a", Type: "A"}, TTL: 600, Alias: &dns.Alias{Target: "x."}}); !errors.As(err, &ie) {
		t.Fatalf("alias: %v", err)
	}
}

func TestDesiredKeepsForwardsAndServerManaged(t *testing.T) {
	native := sample()
	z := FromNative("eurodns", "example.com", native)
	www, _ := z.Set(dns.Key{Host: "www", Type: "A"})
	desired, err := Desired("example.com", z, []dns.Change{
		{Op: dns.OpUpdate, Key: www.Key, Old: &www, New: &dns.RRset{Key: www.Key, TTL: 600, Values: []string{"192.0.2.1"}}},
		{Op: dns.OpCreate, Key: dns.Key{Host: "api", Type: "A"}, New: &dns.RRset{Key: dns.Key{Host: "api", Type: "A"}, TTL: 600, Values: []string{"192.0.2.9"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.URLForwards) != 1 || desired.Records[0].Type != "SOA" || len(desired.Records) != 7 {
		t.Fatalf("desired %+v", desired)
	}
	got := rrset.Group("example.com", desired.Records)
	if w := got[rrset.Key{Host: "www", Type: "A"}]; len(w.Records) != 1 || *w.Records[0].ID != 4 {
		t.Fatalf("update must keep the id of the kept value: %+v", w)
	}
	if _, err := Desired("example.com", &dns.Zone{Name: "example.com"}, nil); err == nil {
		t.Fatal("a zone without native content must be refused")
	}
}

func TestProblems(t *testing.T) {
	f := false
	rep := &api.ValidationReport{IsValid: &f, RecordErrors: []json.RawMessage{
		json.RawMessage(`{"messages":["shadowed"],"record":{"type":"A","host":"www.example.com.","ttl":600,"rdata":"x"},"severity":"WARNING"}`),
		json.RawMessage(`{"messages":["other"],"record":{"type":"A","host":"api","ttl":600,"rdata":"x"},"severity":"WARNING"}`),
	}}
	ps := Problems("example.com", rep, map[dns.Key]bool{{Host: "www", Type: "A"}: true})
	if len(ps) != 2 || !ps[0].Blocking || ps[1].Blocking || ps[0].Key == nil || ps[0].Key.Host != "www" {
		t.Fatalf("problems %+v", ps)
	}
	ps = Problems("example.com", rep, nil)
	if len(ps) != 3 || !ps[2].Blocking {
		t.Fatalf("invalid zone without a blocking problem must block: %+v", ps)
	}
}

func TestWrap(t *testing.T) {
	nf := wrap("get zone", &api.APIError{StatusCode: http.StatusNotFound})
	if !errors.Is(nf, provider.ErrZoneNotFound) {
		t.Fatalf("404: %v", nf)
	}
	var re *provider.RejectedError
	if bad := wrap("save zone", &api.APIError{StatusCode: http.StatusBadRequest, Report: &api.ValidationReport{}}); !errors.As(bad, &re) || re.Details == nil || !errors.Is(bad, provider.ErrNotApplied) {
		t.Fatalf("400: %v", bad)
	}
	if f := wrap("save zone", &api.APIError{StatusCode: http.StatusForbidden}); !errors.Is(f, provider.ErrNotApplied) {
		t.Fatalf("403: %v", f)
	}
	if s := wrap("save zone", &api.APIError{StatusCode: http.StatusBadGateway}); errors.Is(s, provider.ErrNotApplied) {
		t.Fatalf("5xx is not definite: %v", s)
	}
}
