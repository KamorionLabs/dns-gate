package eurodns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	api "github.com/KamorionLabs/eurodns-go"
)

func forwardZone() *api.Zone {
	return &api.Zone{
		Name: "example.com",
		Records: []api.Record{
			{ID: id(1), Type: "A", Host: "www", TTL: 600, RData: "192.0.2.1"},
			{ID: id(2), Type: "URL", Host: "go", TTL: 600, RData: "192.0.2.80"},
		},
		URLForwards: []json.RawMessage{
			json.RawMessage(`{"id":7,"forwardType":"HTTP301","host":"go","url":"https://example.net/","title":null,"x-extra":{"a":1},"updated":false}`),
			json.RawMessage(`{"id":8,"forwardType":"FRAME","host":"Shop.example.com.","url":"https://shop.example.net/","title":"Shop","keywords":"a b","description":"d"}`),
			json.RawMessage(`{"id":9,"forwardType":"MAGIC","host":"odd","url":"https://example.net/"}`),
			json.RawMessage(`{"id":10,"forwardType":"HTTP302","host":"dup","url":"https://a.example.net/"}`),
			json.RawMessage(`{"id":11,"forwardType":"HTTP302","host":"dup","url":"https://b.example.net/"}`),
		},
		MailForwards: []json.RawMessage{json.RawMessage(`{"id":3,"source":"info","destination":"x@example.net"}`)},
	}
}

func TestForwardsFromNative(t *testing.T) {
	z := FromNative("eurodns", "example.com", forwardZone())
	want := map[string]struct{ mode, ro string }{
		"go": {"301", ""}, "shop": {"frame", ""}, "odd": {"magic", ReadOnlyUnsupportedForward}, "dup": {"302", ReadOnlyDuplicateForward},
	}
	n := 0
	for i, s := range z.RRsets {
		if i > 0 && !z.RRsets[i-1].Key.Less(s.Key) {
			t.Fatalf("RRsets not sorted at %s", s.Key)
		}
		if s.Key.Type == "URL" && s.ReadOnly != ReadOnlyForwardRecord {
			t.Fatalf("URL pseudo record not read-only: %+v", s)
		}
		if !s.Key.IsForward() {
			continue
		}
		n++
		w, ok := want[s.Key.Host]
		if !ok || s.Forward == nil || s.Forward.Mode != w.mode || s.ReadOnly != w.ro || s.TTL != 0 || len(s.Values) != 0 {
			t.Fatalf("forward %+v %+v", s, s.Forward)
		}
	}
	if n != 4 {
		t.Fatalf("%d forwards", n)
	}
	shop, _ := z.Set(dns.ForwardKey("shop"))
	if f := shop.Forward; f.Title != "Shop" || f.Keywords != "a b" || f.Description != "d" || f.URL != "https://shop.example.net/" {
		t.Fatalf("frame %+v", f)
	}
}

func TestForwardHashIsStable(t *testing.T) {
	f := dns.RRset{Key: dns.ForwardKey("go"), Forward: &dns.Forward{Mode: "301", URL: "https://example.net/"}}
	g := f
	g.Forward = &dns.Forward{Mode: "301", URL: "https://example.net/", Title: "x"}
	h := f
	h.Forward = &dns.Forward{Mode: "302", URL: "https://example.net/"}
	if dns.ContentHash(f) == dns.ContentHash(g) || dns.ContentHash(f) == dns.ContentHash(h) {
		t.Fatal("forward hash ignores a field")
	}
	read, _ := FromNative("eurodns", "example.com", forwardZone()).Set(dns.ForwardKey("go"))
	norm, err := (&Provider{}).Normalize("example.com", dns.RRset{Key: dns.Key{Host: "GO", Type: "urlfwd"}, Forward: &dns.Forward{Mode: "301", URL: "https://example.net/"}})
	if err != nil || dns.ContentHash(norm) != dns.ContentHash(read) || norm.Key != dns.ForwardKey("go") {
		t.Fatalf("normalized %+v %v: hash differs from the forward read back", norm, err)
	}
}

func TestNormalizeForward(t *testing.T) {
	p := &Provider{}
	k := dns.ForwardKey("go")
	bad := []dns.RRset{
		{Key: k},
		{Key: k, Forward: &dns.Forward{Mode: "307", URL: "https://example.net/"}},
		{Key: k, Forward: &dns.Forward{Mode: "301", URL: "example.net"}},
		{Key: k, Forward: &dns.Forward{Mode: "301", URL: "ftp://example.net/"}},
		{Key: k, Forward: &dns.Forward{Mode: "301", URL: "https://example.net/a b"}},
		{Key: k, Forward: &dns.Forward{Mode: "302", URL: "https://example.net/", Title: "t"}},
		{Key: k, Values: []string{"x"}, Forward: &dns.Forward{Mode: "301", URL: "https://example.net/"}},
		{Key: dns.Key{Host: "go", Type: "A"}, TTL: 600, Values: []string{"192.0.2.1"}, Forward: &dns.Forward{Mode: "301", URL: "https://example.net/"}},
	}
	for _, s := range bad {
		var ie *provider.InvalidError
		if _, err := p.Normalize("example.com", s); !errors.As(err, &ie) {
			t.Fatalf("%+v %+v: %v", s, s.Forward, err)
		}
	}
	s, err := p.Normalize("example.com", dns.RRset{Key: k, TTL: 3600, Forward: &dns.Forward{Mode: " FRAME ", URL: "http://example.net/x?y=1", Title: " T "}})
	if err != nil || s.TTL != 0 || s.Forward.Mode != "frame" || s.Forward.Title != "T" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestDesiredForwards(t *testing.T) {
	native := forwardZone()
	z := FromNative("eurodns", "example.com", native)
	goSet, _ := z.Set(dns.ForwardKey("go"))
	shop, _ := z.Set(dns.ForwardKey("shop"))
	desired, err := Desired("example.com", z, []dns.Change{
		{Op: dns.OpUpdate, Key: goSet.Key, Old: &goSet, New: &dns.RRset{Key: goSet.Key, Forward: &dns.Forward{Mode: "302", URL: "https://example.org/"}}},
		{Op: dns.OpDelete, Key: shop.Key, Old: &shop},
		{Op: dns.OpCreate, Key: dns.ForwardKey("@"), New: &dns.RRset{Key: dns.ForwardKey("@"), Forward: &dns.Forward{Mode: "frame", URL: "https://example.org/", Title: "Home"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.Records) != 2 || string(desired.MailForwards[0]) != string(native.MailForwards[0]) {
		t.Fatalf("records or mail forwards changed: %+v", desired)
	}
	if len(desired.URLForwards) != 5 {
		t.Fatalf("forwards %s", desired.URLForwards)
	}
	var updated map[string]any
	_ = json.Unmarshal(desired.URLForwards[0], &updated)
	if updated["id"] != float64(7) || updated["forwardType"] != "HTTP302" || updated["url"] != "https://example.org/" || updated["x-extra"] == nil ||
		updated["host"] != "go" {
		t.Fatalf("updated entry %v", updated)
	}
	if _, ok := updated["updated"]; ok {
		t.Fatal("read-only field updated sent back")
	}
	for i, j := range map[int]int{1: 2, 2: 3, 3: 4} {
		if string(desired.URLForwards[i]) != string(native.URLForwards[j]) {
			t.Fatalf("entry %d rewritten: %s", j, desired.URLForwards[i])
		}
	}
	if s := string(desired.URLForwards[4]); !strings.Contains(s, `"forwardType":"FRAME"`) || !strings.Contains(s, `"host":"@"`) || strings.Contains(s, `"id"`) {
		t.Fatalf("created entry %s", s)
	}
	if string(native.URLForwards[0]) == string(desired.URLForwards[0]) {
		t.Fatal("the current zone was modified")
	}
}

func TestForwardProblems(t *testing.T) {
	rep := &api.ValidationReport{URLForwardErrors: []json.RawMessage{
		json.RawMessage(`{"messages":["bad url"],"urlForward":{"host":"go","forwardType":"HTTP301","url":"x"},"severity":"ERROR"}`),
		json.RawMessage(`{"messages":["slow"],"urlForward":{"host":"shop.example.com.","forwardType":"FRAME","url":"x"},"severity":"WARNING"}`),
		json.RawMessage(`{"messages":["meh"],"urlForward":{"host":"old","forwardType":"FRAME","url":"x"},"severity":"WARNING"}`),
	}}
	ps := Problems("example.com", rep, map[dns.Key]bool{dns.ForwardKey("shop"): true})
	if len(ps) != 3 || !ps[0].Blocking || *ps[0].Key != dns.ForwardKey("go") || !ps[1].Blocking || ps[2].Blocking {
		t.Fatalf("problems %+v", ps)
	}
}

func TestHTTPSRedirect(t *testing.T) {
	var subs, details atomic.Int32
	var listing, ssl atomic.Value
	listing.Store(`[]`)
	ssl.Store(`ACTIVE`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/subscriptions":
			subs.Add(1)
			if r.URL.Query().Get("subscription-types") != "HTTPS_REDIRECT" || r.URL.Query().Get("domain-name") == "" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			if r.URL.Query().Get("domain-name") == "denied.example" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(listing.Load().(string)))
		case r.URL.Path == "/https-redirect-subscriptions/12":
			details.Add(1)
			_, _ = w.Write([]byte(`{"id":12,"subscriptionType":"HTTPS_REDIRECT","active":true,"domainName":"example.com","sslStatus":"` + ssl.Load().(string) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	newP := func() *Provider { return &Provider{id: "eurodns", baseURL: srv.URL, transport: http.DefaultTransport} }
	ctx := context.Background()

	p := newP()
	if st, _ := p.HTTPSRedirect(ctx, "example.com"); st.Status != provider.HTTPSInactive {
		t.Fatalf("no subscription: %+v", st)
	}
	listing.Store(`[{"id":11,"subscriptionType":"HTTPS_REDIRECT","active":false,"subscriptionStatus":"TO_DELETE","domainName":"example.com"},` +
		`{"id":12,"subscriptionType":"HTTPS_REDIRECT","active":true,"subscriptionStatus":"ACTIVE","domainName":"example.com","expirationDate":"2027-01-01T00:00:00Z"},` +
		`{"id":13,"subscriptionType":"HTTPS_REDIRECT","active":true,"domainName":"other.example"}]`)
	if st, _ := p.HTTPSRedirect(ctx, "example.com"); st.Status != provider.HTTPSInactive || subs.Load() != 1 {
		t.Fatalf("cache not used: %+v, %d listings", st, subs.Load())
	}
	for sslStatus, want := range map[string]string{"ACTIVE": provider.HTTPSActive, "PENDING": provider.HTTPSPending, "NO_FORWARD": provider.HTTPSNoForward} {
		ssl.Store(sslStatus)
		st, err := newP().HTTPSRedirect(ctx, "Example.com.")
		if err != nil || st.Status != want || st.Subscription != "12" || st.ExpiresAt != "2027-01-01T00:00:00Z" {
			t.Fatalf("%s: %+v %v", sslStatus, st, err)
		}
	}
	if st, err := newP().HTTPSRedirect(ctx, "denied.example"); err != nil || st.Status != provider.HTTPSUnknown || !strings.Contains(st.Message, "403") {
		t.Fatalf("denied: %+v %v", st, err)
	}
}
