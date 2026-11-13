package infomaniak

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

type fakeIk struct {
	mu      sync.Mutex
	srv     *httptest.Server
	next    int64
	records []record
	writes  []string
	failOn  string
}

func newFake(t *testing.T) *fakeIk {
	f := &fakeIk{next: 10}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIk) add(source, typ, target string, ttl int, desc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	r := record{ID: f.next, Source: source, Type: typ, Target: target, TTL: ttl}
	if desc != "" {
		r.Description = json.RawMessage(desc)
	}
	f.records = append(f.records, r)
}

func (f *fakeIk) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		out = append(out, fmt.Sprintf("%s %s %d %s", r.Source, r.Type, r.TTL, r.Target))
	}
	slices.Sort(out)
	return out
}

func ok(w http.ResponseWriter, data any, pages int) {
	json.NewEncoder(w).Encode(map[string]any{"result": "success", "data": data, "pages": pages})
}

func (f *fakeIk) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer token" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"result":"error","error":{"code":"not_authorized"}}`)
		return
	}
	if f.failOn == r.Method {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	const records = "/2/zones/example.com/records"
	switch {
	case r.URL.Path == "/1/product":
		pages := [][]map[string]any{{{"customer_name": "example.com"}}, {{"customer_name": "Other.ch"}}}
		p, _ := strconv.Atoi(r.URL.Query().Get("page"))
		ok(w, pages[p-1], len(pages))
	case !strings.HasPrefix(r.URL.Path, records):
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"result":"error","error":{"code":"object_not_found"}}`)
	case r.URL.Path == records && r.Method == http.MethodGet:
		ok(w, f.records, 1)
	case r.URL.Path == records && r.Method == http.MethodPost:
		var in record
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Type == "A" && in.Target == "192.0.2.66" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, `{"result":"error","error":{"code":"validation_failed"}}`)
			return
		}
		f.next++
		in.ID = f.next
		f.records = append(f.records, in)
		f.writes = append(f.writes, "POST")
		ok(w, in, 0)
	default:
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, records+"/"), 10, 64)
		i := slices.IndexFunc(f.records, func(rec record) bool { return rec.ID == id })
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var in record
			_ = json.NewDecoder(r.Body).Decode(&in)
			in.ID = id
			f.records[i] = in
			f.writes = append(f.writes, "PUT")
			ok(w, in, 0)
		case http.MethodDelete:
			f.records = slices.Delete(f.records, i, i+1)
			f.writes = append(f.writes, "DELETE")
			ok(w, true, 0)
		}
	}
}

func newTestProvider(t *testing.T) (*Provider, *fakeIk) {
	t.Helper()
	f := newFake(t)
	zero := 0
	p, err := New("ik", Config{Token: "token", BaseURL: f.srv.URL, Every: -1, MaxRetries: &zero})
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
	f.add(".", "NS", "ns11.infomaniak.ch", 3600, "")
	f.add(".", "MX", "mta-gw.infomaniak.ch", 3600, `{"priority":{"value":5}}`)
	f.add("", "MX", "10 backup.example.net", 3600, `[]`)
	f.add("@", "TXT", `"v=spf1 include:spf.infomaniak.ch -all"`, 3600, "")
	f.add("raw", "TXT", "plain text", 300, "")
	f.add("www.example.com", "CNAME", "Example.com", 300, "")
	f.add("_sip._tcp", "SRV", "sip.example.net", 300, `{"priority":{"value":1},"weight":{"value":2},"port":{"value":"5060"}}`)
	f.add(".", "CAA", "letsencrypt.org", 300, `{"flags":{"value":0},"tag":{"value":"issue"}}`)
	ctx := context.Background()

	zones, err := p.ListZones(ctx)
	if err != nil || !reflect.DeepEqual(zones, []string{"example.com", "other.ch"}) {
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
		`@/CAA 300 ["0 issue \"letsencrypt.org\""] `,
		`@/MX 3600 ["10 backup.example.net." "5 mta-gw.infomaniak.ch."] `,
		`@/NS 3600 ["ns11.infomaniak.ch."] server_managed`,
		`@/TXT 3600 ["v=spf1 include:spf.infomaniak.ch -all"] `,
		`_sip._tcp/SRV 300 ["1 2 5060 sip.example.net."] `,
		`raw/TXT 300 ["plain text"] `,
		`www/CNAME 300 ["example.com."] `,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("zone:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := p.ReadZone(ctx, "missing.org"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Errorf("missing zone: %v", err)
	}

	pinned, _ := New("ik", Config{Token: "token", Zones: []string{"B.example.", "a.example"}})
	if zones, _ := pinned.ListZones(ctx); !reflect.DeepEqual(zones, []string{"a.example", "b.example"}) {
		t.Errorf("pinned zones = %v", zones)
	}
}

func TestApply(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("www", "A", "192.0.2.1", 300, "")
	f.add("www", "A", "192.0.2.2", 300, "")
	f.add("old", "TXT", `"bye"`, 300, "")
	ctx := context.Background()
	err := p.Apply(ctx, "example.com", nil, []dns.Change{
		{Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 300, "192.0.2.1", "192.0.2.2"),
			New: rrset("www", "A", 300, "192.0.2.2", "192.0.2.3")},
		{Op: dns.OpDelete, Key: dns.Key{Host: "old", Type: "TXT"}, Old: rrset("old", "TXT", 300, "bye")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "@", Type: "MX"}, New: rrset("@", "MX", 3600, "10 MX.example.net.")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "t", Type: "TXT"}, New: rrset("t", "TXT", 3600, `"quoted" "twice"`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		". MX 3600 10 mx.example.net",
		"t TXT 3600 quotedtwice",
		"www A 300 192.0.2.2",
		"www A 300 192.0.2.3",
	}
	if got := f.list(); !reflect.DeepEqual(got, want) {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := strings.Join(f.writes, " "); got != "DELETE PUT POST POST" {
		t.Errorf("writes = %s", got)
	}
	z, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	d := rrset("@", "MX", 3600, "10 mx.example.net.")
	s, _ := z.Set(d.Key)
	if n, _ := p.Normalize("example.com", *d); dns.ContentHash(s) != dns.ContentHash(n) {
		t.Errorf("read back %q differs from the desired RRset", s.Values)
	}
}

func TestApplyRefused(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("www", "A", "192.0.2.1", 300, "")
	ctx := context.Background()
	for name, c := range map[string]dns.Change{
		"create exists": {Op: dns.OpCreate, Key: dns.Key{Host: "www", Type: "A"}, New: rrset("www", "A", 300, "192.0.2.7")},
		"update values": {Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 300, "192.0.2.5"),
			New: rrset("www", "A", 300, "192.0.2.7")},
		"delete ttl": {Op: dns.OpDelete, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 600, "192.0.2.1")},
	} {
		if err := p.Apply(ctx, "example.com", nil, []dns.Change{c}); !errors.Is(err, provider.ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var re *provider.RejectedError
	err := p.Apply(ctx, "example.com", nil, []dns.Change{{Op: dns.OpCreate, Key: dns.Key{Host: "n", Type: "A"}, New: rrset("n", "A", 300, "192.0.2.66")}})
	if !errors.As(err, &re) || !errors.Is(err, provider.ErrNotApplied) {
		t.Errorf("rejected: %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
	f.failOn = http.MethodPost
	err = p.Apply(ctx, "example.com", nil, []dns.Change{
		{Op: dns.OpDelete, Key: dns.Key{Host: "www", Type: "A"}, Old: rrset("www", "A", 300, "192.0.2.1")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "n", Type: "A"}, New: rrset("n", "A", 300, "192.0.2.7")},
	})
	if err == nil || errors.Is(err, provider.ErrNotApplied) || !strings.Contains(err.Error(), "partially changed") {
		t.Errorf("partial: %v", err)
	}
}
