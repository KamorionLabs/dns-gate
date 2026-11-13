package scaleway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

type fakeScw struct {
	mu      sync.Mutex
	srv     *httptest.Server
	next    int
	records []record
	patches []patch
	reject  bool
}

func newFake(t *testing.T) *fakeScw {
	f := &fakeScw{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeScw) add(r record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	r.ID = "id-" + strconv.Itoa(f.next)
	f.records = append(f.records, r)
}

func (f *fakeScw) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		out = append(out, fmt.Sprintf("%s %s %d %d %s", r.Name, r.Type, r.TTL, r.Priority, r.Data))
	}
	slices.Sort(out)
	return out
}

func page[T any](r *http.Request, all []T) []T {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	n, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	n = min(n, 2) // small pages, to exercise the paging
	start := min((p-1)*n, len(all))
	return all[start:min(start+n, len(all))]
}

func (f *fakeScw) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Auth-Token") != "secret" {
		http.Error(w, `{"message":"denied"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/domain/v2beta1/dns-zones":
		if r.URL.Query().Get("project_id") != "proj" {
			http.Error(w, `{"message":"project"}`, http.StatusBadRequest)
			return
		}
		zones := []dnsZone{{Domain: "example.com"}, {Domain: "example.com", Subdomain: "dev"}, {Domain: "other.net"}}
		json.NewEncoder(w).Encode(map[string]any{"total_count": len(zones), "dns_zones": page(r, zones)})
	case r.URL.Path != "/domain/v2beta1/dns-zones/example.com/records":
		http.Error(w, `{"message":"zone not found"}`, http.StatusNotFound)
	case r.Method == http.MethodGet:
		q := r.URL.Query()
		var sel []record
		for _, rec := range f.records {
			if (q.Has("name") && rec.Name != q.Get("name")) || (q.Has("type") && rec.Type != q.Get("type")) {
				continue
			}
			sel = append(sel, rec)
		}
		json.NewEncoder(w).Encode(map[string]any{"total_count": len(sel), "records": page(r, sel)})
	case r.Method == http.MethodPatch:
		var in patch
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || f.reject {
			http.Error(w, `{"message":"invalid argument"}`, http.StatusBadRequest)
			return
		}
		f.patches = append(f.patches, in)
		for _, c := range in.Changes {
			switch {
			case c.Delete != nil:
				f.records = slices.DeleteFunc(f.records, func(rec record) bool { return rec.ID == c.Delete.ID })
			case c.Set != nil:
				for i := range f.records {
					if f.records[i].ID == c.Set.ID {
						n := c.Set.Records[0]
						n.ID = c.Set.ID
						f.records[i] = n
					}
				}
			case c.Add != nil:
				for _, n := range c.Add.Records {
					f.next++
					n.ID = "id-" + strconv.Itoa(f.next)
					f.records = append(f.records, n)
				}
			}
		}
		fmt.Fprint(w, `{"records":[]}`)
	}
}

func newTestProvider(t *testing.T) (*Provider, *fakeScw) {
	t.Helper()
	f := newFake(t)
	zero := 0
	p, err := New("scw", Config{SecretKey: "secret", ProjectID: "proj", BaseURL: f.srv.URL, MaxRetries: &zero})
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func rrset(host, typ string, ttl int, values ...string) *dns.RRset {
	return &dns.RRset{Key: dns.Key{Host: host, Type: typ}, TTL: ttl, Values: values}
}

func TestListAndReadZone(t *testing.T) {
	p, f := newTestProvider(t)
	f.add(record{Name: "", Type: "NS", Data: "ns0.dom.scw.cloud.", TTL: 1800})
	f.add(record{Name: "", Type: "MX", Data: "mx.example.net.", Priority: 10, TTL: 300})
	f.add(record{Name: "", Type: "TXT", Data: `"v=spf1 -all"`, TTL: 300})
	f.add(record{Name: "www", Type: "A", Data: "192.0.2.2", TTL: 300})
	f.add(record{Name: "www", Type: "A", Data: "192.0.2.1", TTL: 300})
	f.add(record{Name: "_sip._tcp", Type: "SRV", Data: "20 443 sip.example.net.", Priority: 5, TTL: 300})
	f.add(record{Name: "rel", Type: "CNAME", Data: "www", TTL: 300})
	f.add(record{Name: "geo", Type: "A", Data: "192.0.2.3", TTL: 300, GeoIP: json.RawMessage(`{"matches":[]}`)})
	f.add(record{Name: "", Type: "ALIAS", Data: "lb.example.net.", TTL: 300})
	ctx := context.Background()

	zones, err := p.ListZones(ctx)
	if err != nil || !reflect.DeepEqual(zones, []string{"dev.example.com", "example.com", "other.net"}) {
		t.Fatalf("zones = %v, %v", zones, err)
	}
	z, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range z.RRsets {
		got = append(got, fmt.Sprintf("%s %d %q %s", s.Key, s.TTL, s.Values, s.ReadOnly))
	}
	want := []string{
		`@/ALIAS 300 ["lb.example.net."] alias`,
		`@/MX 300 ["10 mx.example.net."] `,
		`@/NS 1800 ["ns0.dom.scw.cloud."] server_managed`,
		`@/TXT 300 ["v=spf1 -all"] `,
		`_sip._tcp/SRV 300 ["5 20 443 sip.example.net."] `,
		`geo/A 300 ["192.0.2.3"] routing_policy`,
		`rel/CNAME 300 ["www.example.com."] `,
		`www/A 300 ["192.0.2.1" "192.0.2.2"] `,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("zone:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := p.ReadZone(ctx, "missing.org"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Errorf("missing zone: %v", err)
	}
}

func TestApply(t *testing.T) {
	p, f := newTestProvider(t)
	f.add(record{Name: "www", Type: "A", Data: "192.0.2.1", TTL: 300})
	f.add(record{Name: "www", Type: "A", Data: "192.0.2.2", TTL: 300})
	f.add(record{Name: "old", Type: "TXT", Data: `"bye"`, TTL: 300})
	ctx := context.Background()
	err := p.Apply(ctx, "example.com", nil, []dns.Change{
		{Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 300, "192.0.2.1", "192.0.2.2"),
			New: rrset("www", "A", 600, "192.0.2.2", "192.0.2.3", "192.0.2.4")},
		{Op: dns.OpDelete, Key: dns.Key{Host: "old", Type: "TXT"}, Old: rrset("old", "TXT", 300, "bye")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "@", Type: "MX"}, New: rrset("@", "MX", 3600, "10 MX.example.net")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "_sip._tcp", Type: "SRV"}, New: rrset("_sip._tcp", "SRV", 3600, "5 20 443 sip.example.net.")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "t", Type: "TXT"}, New: rrset("t", "TXT", 3600, `say "hi"`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		" MX 3600 10 mx.example.net.",
		"_sip._tcp SRV 3600 5 20 443 sip.example.net.",
		`t TXT 3600 0 "say \"hi\""`,
		"www A 600 0 192.0.2.2",
		"www A 600 0 192.0.2.3",
		"www A 600 0 192.0.2.4",
	}
	if got := f.list(); !reflect.DeepEqual(got, want) {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(f.patches) != 1 || !f.patches[0].DisallowNewZoneCreation {
		t.Fatalf("patches = %+v", f.patches)
	}
	z, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*dns.RRset{rrset("t", "TXT", 3600, `say "hi"`), rrset("@", "MX", 3600, "10 mx.example.net.")} {
		s, _ := z.Set(d.Key)
		n, _ := p.Normalize("example.com", *d)
		if dns.ContentHash(s) != dns.ContentHash(n) {
			t.Errorf("%s read back %q differs from the desired RRset", d.Key, s.Values)
		}
	}
}

func TestApplyRefused(t *testing.T) {
	p, f := newTestProvider(t)
	f.add(record{Name: "www", Type: "A", Data: "192.0.2.1", TTL: 300})
	f.add(record{Name: "geo", Type: "A", Data: "192.0.2.3", TTL: 300, GeoIP: json.RawMessage(`{}`)})
	ctx := context.Background()
	for name, c := range map[string]dns.Change{
		"create exists": {Op: dns.OpCreate, Key: dns.Key{Host: "www", Type: "A"}, New: rrset("www", "A", 300, "192.0.2.7")},
		"update values": {Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 300, "192.0.2.5"),
			New: rrset("www", "A", 300, "192.0.2.7")},
		"update ttl": {Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 600, "192.0.2.1"),
			New: rrset("www", "A", 300, "192.0.2.7")},
		"delete gone": {Op: dns.OpDelete, Key: dns.Key{Host: "gone", Type: "A"}, Old: rrset("gone", "A", 300, "192.0.2.5")},
	} {
		if err := p.Apply(ctx, "example.com", nil, []dns.Change{c}); !errors.Is(err, provider.ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var ie *provider.InvalidError
	err := p.Apply(ctx, "example.com", nil, []dns.Change{{Op: dns.OpDelete, Key: dns.Key{Host: "geo", Type: "A"}, Old: rrset("geo", "A", 300, "192.0.2.3")}})
	if !errors.As(err, &ie) {
		t.Errorf("dynamic record: %v", err)
	}
	if _, err := p.Normalize("example.com", *rrset("www", "A", 30, "192.0.2.1")); !errors.As(err, &ie) {
		t.Errorf("TTL 30: %v", err)
	}
	f.reject = true
	err = p.Apply(ctx, "example.com", nil, []dns.Change{{Op: dns.OpCreate, Key: dns.Key{Host: "n", Type: "A"}, New: rrset("n", "A", 300, "192.0.2.7")}})
	if !errors.Is(err, provider.ErrNotApplied) {
		t.Errorf("rejected: %v", err)
	}
	if len(f.patches) != 0 {
		t.Errorf("patches = %+v", f.patches)
	}
}
