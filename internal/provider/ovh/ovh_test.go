package ovh

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

const (
	testAK = "app-key"
	testAS = "app-secret"
	testCK = "consumer-key"
)

type fakeOVH struct {
	t       *testing.T
	mu      sync.Mutex
	srv     *httptest.Server
	next    int64
	records map[int64]record
	export  string // served instead of the generated zone file when set
	refresh int
	writes  []string
	failOn  string // "METHOD path-suffix" answering 500
	oauth   bool
}

func newFake(t *testing.T) *fakeOVH {
	f := &fakeOVH{t: t, next: 100, records: map[int64]record{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOVH) add(sub, ft, target string, ttl int64) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	f.records[f.next] = record{ID: f.next, SubDomain: sub, FieldType: ft, Target: target, TTL: ttl}
	return f.next
}

func (f *fakeOVH) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		out = append(out, fmt.Sprintf("%s %s %d %s", r.SubDomain, r.FieldType, r.TTL, r.Target))
	}
	slices.Sort(out)
	return out
}

func (f *fakeOVH) zoneFile() string {
	if f.export != "" {
		return f.export
	}
	var b strings.Builder
	b.WriteString("$TTL 3600\n@\tIN SOA dns100.ovh.net. tech.ovh.net. (2024010100 86400 3600 3600000 300)\n")
	b.WriteString("        IN NS     dns100.ovh.net.\n")
	ids := make([]int64, 0, len(f.records))
	for id := range f.records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		r := f.records[id]
		sub := r.SubDomain
		if sub == "" {
			sub = "@"
		}
		ttl := ""
		if r.TTL != 0 {
			ttl = strconv.FormatInt(r.TTL, 10)
		}
		fmt.Fprintf(&b, "%s %s IN %s %s\n", sub, ttl, keyType(r.FieldType), r.Target)
	}
	return b.String()
}

func (f *fakeOVH) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/auth/time" {
		fmt.Fprint(w, time.Now().Unix())
		return
	}
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
		return
	}
	if f.oauth {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
	} else {
		h := sha1.New()
		fmt.Fprintf(h, "%s+%s+%s+%s+%s+%s", testAS, testCK, r.Method, f.srv.URL+r.URL.RequestURI(), body, r.Header.Get("X-Ovh-Timestamp"))
		if r.Header.Get("X-Ovh-Application") != testAK || r.Header.Get("X-Ovh-Consumer") != testCK ||
			r.Header.Get("X-Ovh-Signature") != "$1$"+hex.EncodeToString(h.Sum(nil)) {
			http.Error(w, `{"message":"Invalid signature"}`, http.StatusBadRequest)
			return
		}
	}
	if f.failOn != "" {
		m, suffix, _ := strings.Cut(f.failOn, " ")
		if r.Method == m && strings.HasSuffix(r.URL.Path, suffix) {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
			return
		}
	}
	const prefix = "/domain/zone"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case path == "":
		json.NewEncoder(w).Encode([]string{"Example.com", "other.net"})
	case !strings.HasPrefix(path, "/example.com"):
		http.Error(w, `{"message":"This service does not exist"}`, http.StatusNotFound)
	case path == "/example.com/export":
		json.NewEncoder(w).Encode(f.zoneFile())
	case path == "/example.com/soa":
		json.NewEncoder(w).Encode(map[string]any{"ttl": 3600})
	case path == "/example.com/refresh" && r.Method == http.MethodPost:
		f.refresh++
	case path == "/example.com/record" && r.Method == http.MethodGet:
		ids := []int64{}
		q := r.URL.Query()
		for id, rec := range f.records {
			if q.Has("fieldType") && rec.FieldType != q.Get("fieldType") {
				continue
			}
			// "ilike": a substring matches, as a pattern would.
			if q.Has("subDomain") && !strings.Contains(rec.SubDomain, q.Get("subDomain")) {
				continue
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		json.NewEncoder(w).Encode(ids)
	case path == "/example.com/record" && r.Method == http.MethodPost:
		var rec record
		if json.Unmarshal(body, &rec) != nil || rec.FieldType == "" || rec.Target == "" {
			http.Error(w, `{"message":"invalid"}`, http.StatusBadRequest)
			return
		}
		f.next++
		rec.ID = f.next
		f.records[rec.ID] = rec
		f.writes = append(f.writes, "POST")
		json.NewEncoder(w).Encode(rec)
	case strings.HasPrefix(path, "/example.com/record/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/example.com/record/"), 10, 64)
		rec, ok := f.records[id]
		if !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(rec)
		case http.MethodPut:
			var in record
			_ = json.Unmarshal(body, &in)
			rec.Target, rec.TTL, rec.SubDomain = in.Target, in.TTL, in.SubDomain
			f.records[id] = rec
			f.writes = append(f.writes, "PUT")
		case http.MethodDelete:
			delete(f.records, id)
			f.writes = append(f.writes, "DELETE")
		}
	default:
		http.Error(w, `{"message":"unexpected"}`, http.StatusTeapot)
	}
}

func newTestProvider(t *testing.T) (*Provider, *fakeOVH) {
	t.Helper()
	f := newFake(t)
	zero := 0
	p, err := New("ovh", Config{ApplicationKey: testAK, ApplicationSecret: testAS, ConsumerKey: testCK, BaseURL: f.srv.URL, MaxRetries: &zero})
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func set(host, typ string, ttl int, values ...string) *dns.RRset {
	return &dns.RRset{Key: dns.Key{Host: host, Type: typ}, TTL: ttl, Values: values}
}

func TestNewCredentials(t *testing.T) {
	for name, cfg := range map[string]Config{
		"none":     {},
		"partial":  {ApplicationKey: "a"},
		"both":     {ApplicationKey: "a", ApplicationSecret: "b", ConsumerKey: "c", ClientID: "d", ClientSecret: "e"},
		"endpoint": {Endpoint: "ovh-xx", ClientID: "d", ClientSecret: "e"},
	} {
		if _, err := New("ovh", cfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestListAndReadZone(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("", "A", "192.0.2.1", 0)
	f.add("www", "CNAME", "example.com.", 600)
	f.add("rel", "CNAME", "www", 0)
	f.add("", "MX", "10 mx1.mail.ovh.net.", 0)
	f.add("", "SPF", `"v=spf1 include:mx.ovh.com ~all"`, 0)
	f.add("", "TXT", `"hello world"`, 0)
	f.add("_dmarc", "DMARC", `"v=DMARC1; p=none"`, 0)
	ctx := context.Background()

	zones, err := p.ListZones(ctx)
	if err != nil || !reflect.DeepEqual(zones, []string{"example.com", "other.net"}) {
		t.Fatalf("zones = %v, %v", zones, err)
	}
	z, err := p.ReadZone(ctx, "Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := map[dns.Key]dns.RRset{
		{Host: "@", Type: "A"}:        {TTL: 3600, Values: []string{"192.0.2.1"}},
		{Host: "@", Type: "MX"}:       {TTL: 3600, Values: []string{"10 mx1.mail.ovh.net."}},
		{Host: "@", Type: "NS"}:       {TTL: 3600, Values: []string{"dns100.ovh.net."}, ReadOnly: "server_managed"},
		{Host: "@", Type: "TXT"}:      {TTL: 3600, Values: []string{"hello world", "v=spf1 include:mx.ovh.com ~all"}},
		{Host: "_dmarc", Type: "TXT"}: {TTL: 3600, Values: []string{"v=DMARC1; p=none"}},
		{Host: "rel", Type: "CNAME"}:  {TTL: 3600, Values: []string{"www.example.com."}},
		{Host: "www", Type: "CNAME"}:  {TTL: 600, Values: []string{"example.com."}},
	}
	got := 0
	for _, s := range z.RRsets {
		if s.Key.Type == "SOA" {
			if s.ReadOnly != "server_managed" {
				t.Errorf("SOA is writable")
			}
			continue
		}
		w, ok := want[s.Key]
		if !ok {
			t.Errorf("unexpected %s", s.Key)
			continue
		}
		got++
		if s.TTL != w.TTL || !reflect.DeepEqual(s.Values, w.Values) || s.ReadOnly != w.ReadOnly {
			t.Errorf("%s = %d %q %q, want %d %q %q", s.Key, s.TTL, s.Values, s.ReadOnly, w.TTL, w.Values, w.ReadOnly)
		}
	}
	if got != len(want) {
		t.Errorf("%d RRsets, want %d", got, len(want))
	}
	if !slices.IsSortedFunc(z.RRsets, func(a, b dns.RRset) int {
		if a.Key.Less(b.Key) {
			return -1
		}
		return 1
	}) {
		t.Error("RRsets are not sorted")
	}

	if _, err := p.ReadZone(ctx, "missing.org"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Errorf("missing zone: %v", err)
	}
}

func TestReadZoneFallback(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("www", "A", "192.0.2.1", 0)
	f.add("www", "A", "192.0.2.2", 300)
	f.export = "www IN A not-an-address\n"
	z, err := p.ReadZone(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(z.RRsets) != 1 || z.RRsets[0].TTL != 300 || !reflect.DeepEqual(z.RRsets[0].Values, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("zone = %+v", z.RRsets)
	}
}

func TestApply(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("www", "A", "192.0.2.1", 0)
	f.add("www", "A", "192.0.2.2", 300)
	f.add("wwwx", "A", "192.0.2.9", 300) // matched by the listing pattern, another RRset
	f.add("old", "TXT", `"bye"`, 300)
	f.add("", "SPF", `"v=spf1 -all"`, 300)
	ctx := context.Background()

	long := strings.Repeat("a", 300)
	err := p.Apply(ctx, "example.com", nil, []dns.Change{
		{Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: set("www", "A", 300, "192.0.2.1", "192.0.2.2"),
			New: set("www", "A", 300, "192.0.2.2", "192.0.2.3", "192.0.2.4")},
		{Op: dns.OpDelete, Key: dns.Key{Host: "old", Type: "TXT"}, Old: set("old", "TXT", 300, "bye")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "mail", Type: "MX"}, New: set("mail", "MX", 3600, "10 MX.example.net")},
		{Op: dns.OpUpdate, Key: dns.Key{Host: "@", Type: "TXT"}, Old: set("@", "TXT", 300, "v=spf1 -all"),
			New: set("@", "TXT", 300, "v=spf1 ~all", long)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		" SPF 300 \"" + long[:255] + "\" \"" + long[255:] + "\"",
		" TXT 300 \"v=spf1 ~all\"",
		"mail MX 3600 10 mx.example.net.",
		"www A 300 192.0.2.2",
		"www A 300 192.0.2.3",
		"www A 300 192.0.2.4",
		"wwwx A 300 192.0.2.9",
	}
	if got := f.list(); !reflect.DeepEqual(got, want) {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// www/A: one record kept, one rewritten, one created; old/TXT deleted;
	// mail/MX created; @/TXT: the SPF record rewritten, one TXT created.
	if got := strings.Join(f.writes, " "); got != "DELETE PUT PUT POST POST POST" {
		t.Errorf("writes = %s", got)
	}
	if f.refresh != 1 {
		t.Errorf("refresh = %d", f.refresh)
	}
	z, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := z.Set(dns.Key{Host: "@", Type: "TXT"})
	n, _ := p.Normalize("example.com", *set("@", "TXT", 300, "v=spf1 ~all", long))
	if dns.ContentHash(s) != dns.ContentHash(n) {
		t.Errorf("read back %q differs from the desired RRset", s.Values)
	}
}

func TestApplyConflicts(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("www", "A", "192.0.2.1", 300)
	ctx := context.Background()
	for name, c := range map[string]dns.Change{
		"create exists": {Op: dns.OpCreate, Key: dns.Key{Host: "www", Type: "A"}, New: set("www", "A", 300, "192.0.2.7")},
		"update stale": {Op: dns.OpUpdate, Key: dns.Key{Host: "www", Type: "A"}, Old: set("www", "A", 300, "192.0.2.5"),
			New: set("www", "A", 300, "192.0.2.7")},
		"delete gone": {Op: dns.OpDelete, Key: dns.Key{Host: "gone", Type: "A"}, Old: set("gone", "A", 300, "192.0.2.5")},
	} {
		// The conflict is found before the valid first change is written.
		err := p.Apply(ctx, "example.com", nil, []dns.Change{
			{Op: dns.OpCreate, Key: dns.Key{Host: "new", Type: "A"}, New: set("new", "A", 300, "192.0.2.8")}, c})
		if !errors.Is(err, provider.ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.writes) != 0 || f.refresh != 0 {
		t.Errorf("writes = %v, refresh = %d", f.writes, f.refresh)
	}
	var ie *provider.InvalidError
	err := p.Apply(ctx, "example.com", nil, []dns.Change{{Op: dns.OpCreate, Key: dns.Key{Host: "@", Type: "NS"}, New: set("@", "NS", 300, "ns.example.net.")}})
	if !errors.As(err, &ie) {
		t.Errorf("apex NS: %v", err)
	}
}

func TestApplyPartial(t *testing.T) {
	p, f := newTestProvider(t)
	f.add("old", "A", "192.0.2.1", 300)
	f.failOn = "POST /record"
	err := p.Apply(context.Background(), "example.com", nil, []dns.Change{
		{Op: dns.OpDelete, Key: dns.Key{Host: "old", Type: "A"}, Old: set("old", "A", 300, "192.0.2.1")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "new", Type: "A"}, New: set("new", "A", 300, "192.0.2.8")},
	})
	if err == nil || errors.Is(err, provider.ErrNotApplied) || !strings.Contains(err.Error(), "partially changed") {
		t.Fatalf("err = %v", err)
	}
	if f.refresh != 1 {
		t.Errorf("refresh = %d", f.refresh)
	}
}

func TestServiceAccount(t *testing.T) {
	f := newFake(t)
	f.oauth = true
	p, err := New("ovh", Config{ClientID: "id", ClientSecret: "secret", BaseURL: f.srv.URL, TokenURL: f.srv.URL + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	if zones, err := p.ListZones(context.Background()); err != nil || len(zones) != 2 {
		t.Fatalf("zones = %v, %v", zones, err)
	}
}
