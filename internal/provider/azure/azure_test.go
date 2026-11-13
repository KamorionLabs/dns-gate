package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

const (
	sub    = "00000000-0000-0000-0000-000000000001"
	zoneID = "/subscriptions/" + sub + "/resourceGroups/dns/providers/Microsoft.Network/dnszones/example.com"
)

type fakeAzure struct {
	mu     sync.Mutex
	srv    *httptest.Server
	sets   map[string]*recordSet // "TYPE/name"
	etag   int
	tokens []string // grants seen by the token endpoint
	writes []string
	failOn string
	other  bool // a second zone named example.com in another group
}

func newFake(t *testing.T) *fakeAzure {
	f := &fakeAzure{sets: map[string]*recordSet{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAzure) put(typ, name string, pr properties) *recordSet {
	f.etag++
	rs := &recordSet{Name: name, Type: "Microsoft.Network/dnszones/" + typ, Etag: fmt.Sprintf("etag-%d", f.etag), Properties: pr}
	f.sets[typ+"/"+name] = rs
	return rs
}

func (f *fakeAzure) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		_ = r.ParseForm()
		grant := "secret:" + r.Form.Get("client_secret")
		if a := r.Form.Get("client_assertion"); a != "" {
			grant = "assertion:" + a
		}
		f.tokens = append(f.tokens, r.URL.Path+" "+grant+" "+r.Form.Get("scope"))
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
		return
	}
	if r.URL.Path == "/metadata/identity/oauth2/token" {
		f.tokens = append(f.tokens, "imds "+r.Header.Get("Metadata")+" "+r.URL.Query().Get("client_id"))
		fmt.Fprint(w, `{"access_token":"tok","expires_in":"3600"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("api-version") != apiVersion {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	zones := "/subscriptions/" + sub + "/providers/Microsoft.Network/dnszones"
	switch {
	case r.URL.Path == zones && r.URL.Query().Get("page") == "":
		json.NewEncoder(w).Encode(map[string]any{
			"value":    []map[string]any{{"id": zoneID, "name": "example.com", "properties": map[string]any{"zoneType": "Public"}}},
			"nextLink": f.srv.URL + zones + "?api-version=" + apiVersion + "&page=2",
		})
	case r.URL.Path == zones:
		value := []map[string]any{
			{"id": "/subscriptions/" + sub + "/resourceGroups/dns/providers/Microsoft.Network/dnszones/other.net", "name": "Other.net"},
			{"id": "/x/private", "name": "private.example", "properties": map[string]any{"zoneType": "Private"}},
		}
		if f.other {
			value = append(value, map[string]any{"id": strings.Replace(zoneID, "/dns/", "/dns2/", 1), "name": "example.com"})
		}
		json.NewEncoder(w).Encode(map[string]any{"value": value})
	case r.URL.Path == zoneID+"/recordsets":
		var value []recordSet
		for _, rs := range f.sets {
			value = append(value, *rs)
		}
		json.NewEncoder(w).Encode(map[string]any{"value": value})
	case strings.HasPrefix(r.URL.Path, zoneID+"/"):
		k := strings.TrimPrefix(r.URL.Path, zoneID+"/")
		cur := f.sets[k]
		if f.failOn == r.Method+" "+k {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		im, inm := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
		switch r.Method {
		case http.MethodGet:
			if cur == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(cur)
		case http.MethodPut:
			if (inm == "*" && cur != nil) || (im != "" && (cur == nil || cur.Etag != im)) || (im == "" && inm == "") {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			var in recordSet
			_ = json.NewDecoder(r.Body).Decode(&in)
			typ, name, _ := strings.Cut(k, "/")
			f.put(typ, name, in.Properties)
			f.writes = append(f.writes, "PUT "+k)
		case http.MethodDelete:
			if cur == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if cur.Etag != im {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			delete(f.sets, k)
			f.writes = append(f.writes, "DELETE "+k)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestProvider(t *testing.T) (*Provider, *fakeAzure) {
	t.Helper()
	f := newFake(t)
	zero := 0
	p, err := New("az", Config{SubscriptionID: sub, TenantID: "tenant", ClientID: "client", ClientSecret: "s3cret",
		BaseURL: f.srv.URL, AuthorityURL: f.srv.URL, MaxRetries: &zero})
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func rrset(host, typ string, ttl int, values ...string) *dns.RRset {
	return &dns.RRset{Key: dns.Key{Host: host, Type: typ}, TTL: ttl, Values: values}
}

func TestIdentity(t *testing.T) {
	if _, err := New("az", Config{SubscriptionID: sub}); err == nil {
		t.Error("no identity accepted")
	}
	if _, err := New("az", Config{SubscriptionID: sub, ClientSecret: "x"}); err == nil {
		t.Error("secret without tenant accepted")
	}
	f := newFake(t)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fed, _ := New("az", Config{SubscriptionID: sub, TenantID: "tenant", ClientID: "client", FederatedTokenFile: file, BaseURL: f.srv.URL, AuthorityURL: f.srv.URL})
	if _, err := fed.ListZones(ctx); err != nil {
		t.Fatal(err)
	}
	mi, _ := New("az", Config{SubscriptionID: sub, ClientID: "uami", ManagedIdentity: true, BaseURL: f.srv.URL, IMDSURL: f.srv.URL})
	if _, err := mi.ListZones(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"/tenant/oauth2/v2.0/token assertion:jwt " + f.srv.URL + "/.default", "imds true uami"}
	if !reflect.DeepEqual(f.tokens, want) {
		t.Errorf("tokens = %q", f.tokens)
	}
}

func TestListAndReadZone(t *testing.T) {
	p, f := newTestProvider(t)
	f.put("SOA", "@", properties{TTL: 3600, SOA: &soaRecord{Host: "ns1-01.azure-dns.com.", Email: "azuredns-hostmaster.microsoft.com", SerialNumber: 1, RefreshTime: 3600, RetryTime: 300, ExpireTime: 2419200, MinimumTTL: 300}})
	f.put("NS", "@", properties{TTL: 172800, NS: []nsRecord{{NSDName: "ns1-01.azure-dns.com."}}})
	f.put("A", "www", properties{TTL: 300, A: []aRecord{{"192.0.2.2"}, {"192.0.2.1"}}})
	f.put("MX", "@", properties{TTL: 300, MX: []mxRecord{{10, "MX.example.net"}}})
	f.put("TXT", "@", properties{TTL: 300, TXT: []txtRecord{{Value: []string{"v=spf1 ", "-all"}}}})
	f.put("CAA", "@", properties{TTL: 300, CAA: []caaRecord{{0, "issue", "letsencrypt.org"}}})
	f.put("SRV", "_sip._tcp", properties{TTL: 300, SRV: []srvRecord{{1, 2, 5060, "sip.example.net"}}})
	f.put("CNAME", "app", properties{TTL: 300, CNAME: &cnameRecord{"app.azurewebsites.net"}})
	f.put("A", "alias", properties{TTL: 60, TargetResource: &struct {
		ID string `json:"id"`
	}{ID: "/subscriptions/x/publicIPAddresses/ip"}})
	f.put("A", "empty", properties{TTL: 60})
	ctx := context.Background()

	zones, err := p.ListZones(ctx)
	if err != nil || !reflect.DeepEqual(zones, []string{"example.com", "other.net"}) {
		t.Fatalf("zones = %v, %v", zones, err)
	}
	if len(f.tokens) != 1 || f.tokens[0] != "/tenant/oauth2/v2.0/token secret:s3cret "+f.srv.URL+"/.default" {
		t.Errorf("tokens = %q", f.tokens)
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
		`@/MX 300 ["10 mx.example.net."] `,
		`@/NS 172800 ["ns1-01.azure-dns.com."] server_managed`,
		`@/SOA 3600 ["ns1-01.azure-dns.com. azuredns-hostmaster.microsoft.com. 1 3600 300 2419200 300"] server_managed`,
		`@/TXT 300 ["v=spf1 -all"] `,
		`_sip._tcp/SRV 300 ["1 2 5060 sip.example.net."] `,
		`alias/A 60 ["/subscriptions/x/publicIPAddresses/ip"] alias`,
		`app/CNAME 300 ["app.azurewebsites.net."] `,
		`www/A 300 ["192.0.2.1" "192.0.2.2"] `,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("zone:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := p.ReadZone(ctx, "missing.org"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Errorf("missing zone: %v", err)
	}
	f.other = true
	if _, err := p.ListZones(ctx); err == nil || !strings.Contains(err.Error(), "resource_group") {
		t.Errorf("duplicate zone: %v", err)
	}
}

func TestApply(t *testing.T) {
	p, f := newTestProvider(t)
	f.put("A", "www", properties{TTL: 300, Metadata: map[string]string{"owner": "web"}, A: []aRecord{{"192.0.2.1"}}})
	f.put("TXT", "old", properties{TTL: 300, TXT: []txtRecord{{Value: []string{"bye"}}}})
	f.put("A", "empty", properties{TTL: 60})
	ctx := context.Background()
	z, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	www, _ := z.Set(dns.Key{Host: "www", Type: "A"})
	long := strings.Repeat("a", 300)
	err = p.Apply(ctx, "example.com", z, []dns.Change{
		{Op: dns.OpCreate, Key: dns.Key{Host: "@", Type: "MX"}, New: rrset("@", "MX", 3600, "10 mx.example.net.")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "empty", Type: "A"}, New: rrset("empty", "A", 60, "192.0.2.9")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "t", Type: "TXT"}, New: rrset("t", "TXT", 60, long)},
		{Op: dns.OpCreate, Key: dns.Key{Host: "@", Type: "CAA"}, New: rrset("@", "CAA", 60, `0 issue "letsencrypt.org"`)},
		{Op: dns.OpUpdate, Key: www.Key, Old: &www, New: rrset("www", "A", 600, "192.0.2.2", "192.0.2.3")},
		// Old without Native: the etag comes from the zone read.
		{Op: dns.OpDelete, Key: dns.Key{Host: "old", Type: "TXT"}, Old: rrset("old", "TXT", 300, "bye")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.writes, ", "); got != "DELETE TXT/old, PUT A/www, PUT MX/@, PUT A/empty, PUT TXT/t, PUT CAA/@" {
		t.Errorf("writes = %s", got)
	}
	w := f.sets["A/www"].Properties
	if w.TTL != 600 || len(w.A) != 2 || w.Metadata["owner"] != "web" {
		t.Errorf("www = %+v", w)
	}
	if mx := f.sets["MX/@"].Properties.MX; len(mx) != 1 || mx[0] != (mxRecord{10, "mx.example.net"}) {
		t.Errorf("mx = %+v", mx)
	}
	if txt := f.sets["TXT/t"].Properties.TXT; len(txt) != 1 || len(txt[0].Value) != 2 || len(txt[0].Value[0]) != 255 {
		t.Errorf("txt = %+v", txt)
	}
	if caa := f.sets["CAA/@"].Properties.CAA; len(caa) != 1 || caa[0] != (caaRecord{0, "issue", "letsencrypt.org"}) {
		t.Errorf("caa = %+v", caa)
	}
	after, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*dns.RRset{rrset("t", "TXT", 60, long), rrset("@", "CAA", 60, `0 issue "letsencrypt.org"`), rrset("www", "A", 600, "192.0.2.2", "192.0.2.3")} {
		s, _ := after.Set(d.Key)
		if n, _ := p.Normalize("example.com", *d); dns.ContentHash(s) != dns.ContentHash(n) {
			t.Errorf("%s read back %q differs from the desired RRset", d.Key, s.Values)
		}
	}
}

func TestApplyConflicts(t *testing.T) {
	p, f := newTestProvider(t)
	f.put("A", "www", properties{TTL: 300, A: []aRecord{{"192.0.2.1"}}})
	f.put("A", "alias", properties{TTL: 60, TargetResource: &struct {
		ID string `json:"id"`
	}{ID: "/x"}})
	ctx := context.Background()
	z, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	www, _ := z.Set(dns.Key{Host: "www", Type: "A"})
	alias, _ := z.Set(dns.Key{Host: "alias", Type: "A"})

	f.mu.Lock()
	f.put("A", "www", properties{TTL: 300, A: []aRecord{{"192.0.2.50"}}}) // changed upstream: new etag
	f.mu.Unlock()
	for name, c := range map[string]dns.Change{
		"stale etag":    {Op: dns.OpUpdate, Key: www.Key, Old: &www, New: rrset("www", "A", 300, "192.0.2.7")},
		"stale delete":  {Op: dns.OpDelete, Key: www.Key, Old: &www},
		"create exists": {Op: dns.OpCreate, Key: www.Key, New: rrset("www", "A", 300, "192.0.2.7")},
		"stale content": {Op: dns.OpDelete, Key: www.Key, Old: rrset("www", "A", 300, "192.0.2.1")},
		"gone":          {Op: dns.OpDelete, Key: dns.Key{Host: "gone", Type: "A"}, Old: rrset("gone", "A", 300, "192.0.2.1")},
	} {
		cur := z
		if name == "stale content" || name == "gone" {
			cur = nil // the record set is read again
		}
		if err := p.Apply(ctx, "example.com", cur, []dns.Change{c}); !errors.Is(err, provider.ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var ie *provider.InvalidError
	if err := p.Apply(ctx, "example.com", z, []dns.Change{{Op: dns.OpDelete, Key: alias.Key, Old: &alias}}); !errors.As(err, &ie) {
		t.Errorf("alias: %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}

	// Read again with the current content: the delete goes through.
	if err := p.Apply(ctx, "example.com", nil, []dns.Change{{Op: dns.OpDelete, Key: www.Key, Old: rrset("www", "A", 300, "192.0.2.50")}}); err != nil {
		t.Fatal(err)
	}
	f.failOn = "PUT A/b"
	err = p.Apply(ctx, "example.com", nil, []dns.Change{
		{Op: dns.OpCreate, Key: dns.Key{Host: "a", Type: "A"}, New: rrset("a", "A", 300, "192.0.2.7")},
		{Op: dns.OpCreate, Key: dns.Key{Host: "b", Type: "A"}, New: rrset("b", "A", 300, "192.0.2.7")},
	})
	if err == nil || errors.Is(err, provider.ErrNotApplied) || !strings.Contains(err.Error(), "partially changed") {
		t.Errorf("partial: %v", err)
	}
	if !slices.Contains(f.writes, "PUT A/a") {
		t.Errorf("writes = %v", f.writes)
	}
}
