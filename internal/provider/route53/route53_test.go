package route53

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

const zoneID = "Z1EXAMPLE"

func rrs(name string, typ types.RRType, ttl int64, values ...string) types.ResourceRecordSet {
	s := types.ResourceRecordSet{Name: aws.String(name), Type: typ, TTL: aws.Int64(ttl)}
	for _, v := range values {
		s.ResourceRecords = append(s.ResourceRecords, types.ResourceRecord{Value: aws.String(v)})
	}
	return s
}

func baseSets() []types.ResourceRecordSet {
	return []types.ResourceRecordSet{
		rrs("example.com.", types.RRTypeSoa, 900, "ns-1.awsdns-01.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"),
		rrs("example.com.", types.RRTypeNs, 172800, "ns-1.awsdns-01.org.", "ns-2.awsdns-02.com."),
	}
}

func newTestProvider(t *testing.T, sets ...types.ResourceRecordSet) (*Provider, *fakeR53) {
	t.Helper()
	f := newFake(2)
	f.addZone(zoneID, "example.com", false, append(baseSets(), sets...)...)
	p, err := New(context.Background(), "r53", Config{}, WithClient(f))
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func readSet(t *testing.T, p *Provider, k dns.Key) (dns.RRset, bool) {
	t.Helper()
	z, err := p.ReadZone(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	return z.Set(k)
}

func sameContent(a, b dns.RRset) bool {
	return a.Key == b.Key && a.TTL == b.TTL && reflect.DeepEqual(a.Values, b.Values) && reflect.DeepEqual(a.Alias, b.Alias) &&
		dns.ContentHash(a) == dns.ContentHash(b)
}

func apply(t *testing.T, p *Provider, changes ...dns.Change) error {
	t.Helper()
	cur, err := p.ReadZone(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range changes {
		if c.Op != dns.OpCreate {
			old, ok := cur.Set(c.Key)
			if !ok {
				t.Fatalf("%s missing", c.Key)
			}
			changes[i].Old = &old
		}
	}
	return p.Apply(context.Background(), "example.com", cur, changes)
}

func TestRoundTrip(t *testing.T) {
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 20)
	cases := []struct {
		in, upd dns.RRset
		want    []string
	}{
		{in: dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 300, Values: []string{"192.0.2.2", "192.0.2.1", "192.0.2.1"}},
			upd: dns.RRset{TTL: 60, Values: []string{"192.0.2.3"}}, want: []string{"192.0.2.1", "192.0.2.2"}},
		{in: dns.RRset{Key: dns.Key{Host: "WWW.Example.com.", Type: "aaaa"}, TTL: 300, Values: []string{"2001:DB8:0:0::1"}},
			upd: dns.RRset{TTL: 300, Values: []string{"2001:db8::2"}}, want: []string{"2001:db8::1"}},
		{in: dns.RRset{Key: dns.Key{Host: "app", Type: "CNAME"}, TTL: 300, Values: []string{"Target.Example.NET"}},
			upd: dns.RRset{TTL: 300, Values: []string{"other.example.net."}}, want: []string{"target.example.net."}},
		{in: dns.RRset{Key: dns.Key{Host: "@", Type: "MX"}, TTL: 3600, Values: []string{"10 Mail.example.com", "20 mx2.example.com."}},
			upd: dns.RRset{TTL: 3600, Values: []string{"0 ."}}, want: []string{"10 mail.example.com.", "20 mx2.example.com."}},
		{in: dns.RRset{Key: dns.Key{Host: "_sip._tcp", Type: "SRV"}, TTL: 300, Values: []string{"10 5 5060 SIP.example.com"}},
			upd: dns.RRset{TTL: 300, Values: []string{"0 0 0 ."}}, want: []string{"10 5 5060 sip.example.com."}},
		{in: dns.RRset{Key: dns.Key{Host: "@", Type: "TXT"}, TTL: 300, Values: []string{"v=spf1 include:_spf.example.net ~all", "google-site-verification=abc"}},
			upd: dns.RRset{TTL: 300, Values: []string{`say "hi" \ back`}}, want: []string{"google-site-verification=abc", "v=spf1 include:_spf.example.net ~all"}},
		{in: dns.RRset{Key: dns.Key{Host: "s1._domainkey", Type: "TXT"}, TTL: 300, Values: []string{dkim}},
			upd: dns.RRset{TTL: 300, Values: []string{dkim + "IDAQAB"}}, want: []string{dkim}},
		{in: dns.RRset{Key: dns.Key{Host: "quoted", Type: "TXT"}, TTL: 300, Values: []string{`"part one " "part two"`}},
			upd: dns.RRset{TTL: 300, Values: []string{"café \t tab"}}, want: []string{"part one part two"}},
		{in: dns.RRset{Key: dns.Key{Host: "empty", Type: "TXT"}, TTL: 300, Values: []string{""}},
			upd: dns.RRset{TTL: 300, Values: []string{"x"}}, want: []string{""}},
		{in: dns.RRset{Key: dns.Key{Host: "@", Type: "SPF"}, TTL: 300, Values: []string{"v=spf1 -all"}},
			upd: dns.RRset{TTL: 600, Values: []string{"v=spf1 ~all"}}, want: []string{"v=spf1 -all"}},
		{in: dns.RRset{Key: dns.Key{Host: "@", Type: "CAA"}, TTL: 300, Values: []string{`0 Issue "letsencrypt.org"`, "128 iodef mailto:sec@example.com"}},
			upd: dns.RRset{TTL: 300, Values: []string{`0 issue ";"`}}, want: []string{`0 issue "letsencrypt.org"`, `128 iodef "mailto:sec@example.com"`}},
		{in: dns.RRset{Key: dns.Key{Host: "sub", Type: "NS"}, TTL: 172800, Values: []string{"NS1.example.net", "ns2.example.net."}},
			upd: dns.RRset{TTL: 3600, Values: []string{"ns3.example.net."}}, want: []string{"ns1.example.net.", "ns2.example.net."}},
		{in: dns.RRset{Key: dns.Key{Host: "sub", Type: "DS"}, TTL: 3600, Values: []string{"12345 13 2 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}},
			upd:  dns.RRset{TTL: 3600, Values: []string{"54321 8 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"}},
			want: []string{"12345 13 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"}},
		{in: dns.RRset{Key: dns.Key{Host: "1.2", Type: "PTR"}, TTL: 300, Values: []string{"Host.Example.com"}},
			upd: dns.RRset{TTL: 300, Values: []string{"other.example.com."}}, want: []string{"host.example.com."}},
		{in: dns.RRset{Key: dns.Key{Host: "*.dev", Type: "A"}, TTL: 300, Values: []string{"192.0.2.10"}},
			upd: dns.RRset{TTL: 300, Values: []string{"192.0.2.11"}}, want: []string{"192.0.2.10"}},
		{in: dns.RRset{Key: dns.Key{Host: "@", Type: "A"}, TTL: 300, Alias: &dns.Alias{Target: "D111.CloudFront.net", HostedZoneID: "/hostedzone/z2fdtndataqyw2"}},
			upd: dns.RRset{Alias: &dns.Alias{Target: "dualstack.lb-1.eu-west-3.elb.amazonaws.com.", HostedZoneID: "Z3Q77PNBQS71R4", EvaluateTargetHealth: true}}},
		{in: dns.RRset{Key: dns.Key{Host: "cdn", Type: "AAAA"}, TTL: 300, Alias: &dns.Alias{Target: "www.example.com", HostedZoneID: zoneID}},
			upd: dns.RRset{Values: []string{"2001:db8::7"}, TTL: 120}},
	}
	for _, c := range cases {
		t.Run(c.in.Key.String(), func(t *testing.T) {
			p, f := newTestProvider(t)
			n, err := p.Normalize("example.com", c.in)
			if err != nil {
				t.Fatal(err)
			}
			if c.want != nil && !reflect.DeepEqual(n.Values, c.want) {
				t.Fatalf("normalized values %q, want %q", n.Values, c.want)
			}
			if n.Alias != nil && (n.TTL != 0 || n.Values != nil) {
				t.Fatalf("alias not canonical: %+v", n)
			}
			again, err := p.Normalize("example.com", n)
			if err != nil || !sameContent(again, n) {
				t.Fatalf("normalize not idempotent: %+v %v", again, err)
			}
			if err := apply(t, p, dns.Change{Op: dns.OpCreate, Key: n.Key, New: &n}); err != nil {
				t.Fatal(err)
			}
			got, ok := readSet(t, p, n.Key)
			if !ok || !sameContent(got, n) || got.ReadOnly != "" {
				t.Fatalf("read back %+v, want %+v", got, n)
			}
			upd := c.upd
			upd.Key = n.Key
			u, err := p.Normalize("example.com", upd)
			if err != nil {
				t.Fatal(err)
			}
			if err := apply(t, p, dns.Change{Op: dns.OpUpdate, Key: n.Key, New: &u}); err != nil {
				t.Fatal(err)
			}
			if got, ok := readSet(t, p, n.Key); !ok || !sameContent(got, u) {
				t.Fatalf("read back %+v, want %+v", got, u)
			}
			if err := apply(t, p, dns.Change{Op: dns.OpDelete, Key: n.Key}); err != nil {
				t.Fatal(err)
			}
			if got, ok := readSet(t, p, n.Key); ok {
				t.Fatalf("still there: %+v", got)
			}
			if len(f.records(zoneID)) != len(baseSets()) {
				t.Fatalf("leftovers: %+v", f.records(zoneID))
			}
		})
	}
}

func TestLongTXTChunking(t *testing.T) {
	p, f := newTestProvider(t)
	content := strings.Repeat("a", 254) + `"` + strings.Repeat("b", 300)
	n, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "long", Type: "TXT"}, TTL: 300, Values: []string{content}})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(t, p, dns.Change{Op: dns.OpCreate, Key: n.Key, New: &n}); err != nil {
		t.Fatal(err)
	}
	var raw string
	for _, s := range f.records(zoneID) {
		if aws.ToString(s.Name) == "long.example.com." {
			raw = aws.ToString(s.ResourceRecords[0].Value)
		}
	}
	want := `"` + strings.Repeat("a", 254) + `\"" "` + strings.Repeat("b", 255) + `" "` + strings.Repeat("b", 45) + `"`
	if raw != want {
		t.Fatalf("upstream value\n%s\nwant\n%s", raw, want)
	}
	got, _ := readSet(t, p, n.Key)
	if got.Values[0] != content {
		t.Fatalf("read back %q", got.Values[0])
	}
}

func TestReadZone(t *testing.T) {
	weighted := func(id string, w int64, v string) types.ResourceRecordSet {
		s := rrs("api.example.com.", types.RRTypeA, 60, v)
		s.SetIdentifier, s.Weight = aws.String(id), aws.Int64(w)
		return s
	}
	alias := types.ResourceRecordSet{Name: aws.String("example.com."), Type: types.RRTypeAaaa,
		AliasTarget: &types.AliasTarget{DNSName: aws.String("D111.cloudfront.net."), HostedZoneId: aws.String("Z2FDTNDATAQYW2")}}
	checked := rrs("hc.example.com.", types.RRTypeA, 60, "192.0.2.9")
	checked.HealthCheckId = aws.String("hc-1")
	p, f := newTestProvider(t,
		rrs("*.example.com.", types.RRTypeA, 300, "192.0.2.1"),
		rrs("s1._domainkey.example.com.", types.RRTypeTxt, 300, `"v=DKIM1; k=rsa; " "p=MIIB"`),
		rrs("odd.example.com.", types.RRTypeTxt, 300, `"caf\303\251"`),
		rrs("www.example.com.", types.RRTypeCname, 300, "Target.Example.net"),
		weighted("blue", 10, "192.0.2.1"), weighted("green", 90, "192.0.2.2"),
		alias, checked,
	)
	z, err := p.ReadZone(context.Background(), "Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if z.Name != "example.com" || z.Provider != "r53" || f.count("ListResourceRecordSets") < 2 {
		t.Fatalf("zone %s %s, %d pages", z.Name, z.Provider, f.count("ListResourceRecordSets"))
	}
	for i := 1; i < len(z.RRsets); i++ {
		if !z.RRsets[i-1].Key.Less(z.RRsets[i].Key) {
			t.Fatalf("not sorted: %v then %v", z.RRsets[i-1].Key, z.RRsets[i].Key)
		}
	}
	want := map[dns.Key]dns.RRset{
		{Host: "*", Type: "A"}:               {TTL: 300, Values: []string{"192.0.2.1"}},
		{Host: "s1._domainkey", Type: "TXT"}: {TTL: 300, Values: []string{"v=DKIM1; k=rsa; p=MIIB"}},
		{Host: "odd", Type: "TXT"}:           {TTL: 300, Values: []string{"café"}},
		{Host: "www", Type: "CNAME"}:         {TTL: 300, Values: []string{"target.example.net."}},
		{Host: "api", Type: "A"}:             {TTL: 60, Values: []string{"192.0.2.1", "192.0.2.2"}, ReadOnly: "routing_policy"},
		{Host: "hc", Type: "A"}:              {TTL: 60, Values: []string{"192.0.2.9"}, ReadOnly: "routing_policy"},
		{Host: "@", Type: "AAAA"}:            {Alias: &dns.Alias{Target: "d111.cloudfront.net.", HostedZoneID: "Z2FDTNDATAQYW2"}},
		{Host: "@", Type: "NS"}:              {TTL: 172800, Values: []string{"ns-1.awsdns-01.org.", "ns-2.awsdns-02.com."}, ReadOnly: "server_managed"},
	}
	if len(z.RRsets) != len(want)+1 {
		t.Fatalf("%d RRsets: %+v", len(z.RRsets), z.RRsets)
	}
	for k, w := range want {
		got, ok := z.Set(k)
		w.Key = k
		if !ok || !sameContent(got, w) || got.ReadOnly != w.ReadOnly {
			t.Errorf("%s: got %+v, want %+v", k, got, w)
		}
	}
	if soa, _ := z.Set(dns.Key{Host: "@", Type: "SOA"}); soa.ReadOnly != "server_managed" {
		t.Errorf("SOA not server managed: %+v", soa)
	}
	if api, _ := z.Set(dns.Key{Host: "api", Type: "A"}); len(api.Native.([]types.ResourceRecordSet)) != 2 {
		t.Errorf("routing policy native: %+v", api.Native)
	}
}

func TestUpdateDeletesExactNative(t *testing.T) {
	p, f := newTestProvider(t, rrs("s1._domainkey.example.com.", types.RRTypeTxt, 300, `"v=DKIM1; " "k=rsa; " "p=MIIB"`))
	k := dns.Key{Host: "s1._domainkey", Type: "TXT"}
	n, err := p.Normalize("example.com", dns.RRset{Key: k, TTL: 300, Values: []string{"v=DKIM1; k=rsa; p=NEW"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(t, p, dns.Change{Op: dns.OpUpdate, Key: k, New: &n}); err != nil {
		t.Fatal(err)
	}
	b := f.batches[0]
	if len(b) != 2 || b[0].Action != types.ChangeActionDelete || aws.ToString(b[0].ResourceRecordSet.ResourceRecords[0].Value) != `"v=DKIM1; " "k=rsa; " "p=MIIB"` ||
		b[1].Action != types.ChangeActionCreate || aws.ToString(b[1].ResourceRecordSet.ResourceRecords[0].Value) != `"v=DKIM1; k=rsa; p=NEW"` {
		t.Fatalf("batch %+v", b)
	}
}

func TestOldWithoutNative(t *testing.T) {
	p, f := newTestProvider(t, rrs("www.example.com.", types.RRTypeA, 300, "192.0.2.1"))
	k := dns.Key{Host: "www", Type: "A"}
	cur, err := p.ReadZone(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	stale := dns.RRset{Key: k, TTL: 300, Values: []string{"192.0.2.99"}}
	err = p.Apply(context.Background(), "example.com", cur, []dns.Change{{Op: dns.OpDelete, Key: k, Old: &stale}})
	if !errors.Is(err, provider.ErrConflict) || f.count("ChangeResourceRecordSets") != 0 {
		t.Fatalf("stale old: %v, %d calls", err, f.count("ChangeResourceRecordSets"))
	}
	old := dns.RRset{Key: k, TTL: 300, Values: []string{"192.0.2.1"}}
	if err := p.Apply(context.Background(), "example.com", cur, []dns.Change{{Op: dns.OpDelete, Key: k, Old: &old}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), "example.com", nil, []dns.Change{{Op: dns.OpDelete, Key: k, Old: &old}}); !errors.Is(err, provider.ErrConflict) {
		t.Fatalf("delete of a missing set: %v", err)
	}
}

func TestConflicts(t *testing.T) {
	ctx := context.Background()
	p, f := newTestProvider(t, rrs("www.example.com.", types.RRTypeA, 300, "192.0.2.1"), rrs("old.example.com.", types.RRTypeA, 300, "192.0.2.5"))
	www := dns.Key{Host: "www", Type: "A"}
	cur, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.mutate(zoneID, func(sets []types.ResourceRecordSet) []types.ResourceRecordSet {
		for i := range sets {
			if aws.ToString(sets[i].Name) == "www.example.com." {
				sets[i].TTL = aws.Int64(60)
			}
		}
		return sets
	})
	before := f.records(zoneID)
	old, _ := cur.Set(www)
	oldDel, _ := cur.Set(dns.Key{Host: "old", Type: "A"})
	nw := dns.RRset{Key: www, TTL: 300, Values: []string{"192.0.2.2"}}
	created := dns.RRset{Key: dns.Key{Host: "new", Type: "A"}, TTL: 300, Values: []string{"192.0.2.3"}}
	err = p.Apply(ctx, "example.com", cur, []dns.Change{
		{Op: dns.OpCreate, Key: created.Key, New: &created},
		{Op: dns.OpDelete, Key: oldDel.Key, Old: &oldDel},
		{Op: dns.OpUpdate, Key: www, Old: &old, New: &nw},
	})
	if !errors.Is(err, provider.ErrConflict) || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("stale update: %v", err)
	}
	if !reflect.DeepEqual(f.records(zoneID), before) {
		t.Fatal("a rejected batch changed the zone")
	}
	dup := dns.RRset{Key: dns.Key{Host: "old", Type: "A"}, TTL: 300, Values: []string{"192.0.2.7"}}
	if err := p.Apply(ctx, "example.com", cur, []dns.Change{{Op: dns.OpCreate, Key: dup.Key, New: &dup}}); !errors.Is(err, provider.ErrConflict) {
		t.Fatalf("create over an existing set: %v", err)
	}
	cname := dns.RRset{Key: dns.Key{Host: "www", Type: "CNAME"}, TTL: 300, Values: []string{"x.example.net."}}
	if err := p.Apply(ctx, "example.com", cur, []dns.Change{{Op: dns.OpCreate, Key: cname.Key, New: &cname}}); !errors.Is(err, provider.ErrConflict) {
		t.Fatalf("CNAME next to an A: %v", err)
	}
}

func TestApplyRefusals(t *testing.T) {
	ctx := context.Background()
	w := func(id string, wt int64) types.ResourceRecordSet {
		s := rrs("api.example.com.", types.RRTypeA, 60, "192.0.2.1")
		s.SetIdentifier, s.Weight = aws.String(id), aws.Int64(wt)
		return s
	}
	p, f := newTestProvider(t, w("a", 1), w("b", 2))
	cur, err := p.ReadZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	api, _ := cur.Set(dns.Key{Host: "api", Type: "A"})
	ns, _ := cur.Set(dns.Key{Host: "@", Type: "NS"})
	var inv *provider.InvalidError
	for _, old := range []dns.RRset{api, ns} {
		if err := p.Apply(ctx, "example.com", cur, []dns.Change{{Op: dns.OpDelete, Key: old.Key, Old: &old}}); !errors.As(err, &inv) {
			t.Fatalf("delete of read-only %s: %v", old.Key, err)
		}
	}
	api.ReadOnly = ""
	if err := p.Apply(ctx, "example.com", cur, []dns.Change{{Op: dns.OpDelete, Key: api.Key, Old: &api}}); !errors.As(err, &inv) {
		t.Fatalf("delete of a routing policy native: %v", err)
	}
	many := dns.RRset{Key: dns.Key{Host: "many", Type: "A"}, TTL: 300}
	for i := 0; i < 1001; i++ {
		many.Values = append(many.Values, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if err := p.Apply(ctx, "example.com", cur, []dns.Change{{Op: dns.OpCreate, Key: many.Key, New: &many}}); !errors.As(err, &inv) || !strings.Contains(inv.Message, "not split") {
		t.Fatalf("over 1000 records: %v", err)
	}
	var changes []dns.Change
	for i := 0; i < 9; i++ {
		s := dns.RRset{Key: dns.Key{Host: fmt.Sprintf("t%d", i), Type: "TXT"}, TTL: 300, Values: []string{strings.Repeat("x", 3800)}}
		changes = append(changes, dns.Change{Op: dns.OpCreate, Key: s.Key, New: &s})
	}
	if err := p.Apply(ctx, "example.com", cur, changes); !errors.As(err, &inv) {
		t.Fatalf("over 32000 characters: %v", err)
	}
	bad := dns.RRset{Key: dns.Key{Host: "x", Type: "A"}, TTL: 300, Values: []string{"nope"}}
	if err := p.Apply(ctx, "example.com", cur, []dns.Change{{Op: dns.OpCreate, Key: bad.Key, New: &bad}}); !errors.As(err, &inv) {
		t.Fatalf("invalid new: %v", err)
	}
	if n := f.count("ChangeResourceRecordSets"); n != 0 {
		t.Fatalf("%d upstream writes", n)
	}
	if err := p.Apply(ctx, "example.com", cur, nil); err != nil {
		t.Fatal(err)
	}
}

func TestApplyErrorMapping(t *testing.T) {
	ctx := context.Background()
	p, f := newTestProvider(t)
	s := dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}}
	ch := []dns.Change{{Op: dns.OpCreate, Key: s.Key, New: &s}}
	f.changeErrs = []error{
		&types.InvalidChangeBatch{Messages: []string{"RRSet with DNS name www.example.com. is not permitted in zone example.com. [name='www.example.com.', type='A']"}},
		&types.InvalidInput{Message: aws.String("Invalid XML")},
		&types.NoSuchHostedZone{Message: aws.String("gone")},
		errors.New("boom"),
	}
	var inv *provider.InvalidError
	if err := p.Apply(ctx, "example.com", nil, ch); !errors.As(err, &inv) || inv.Key != s.Key {
		t.Fatalf("invalid change batch: %v", err)
	}
	if err := p.Apply(ctx, "example.com", nil, ch); !errors.As(err, &inv) {
		t.Fatalf("invalid input: %v", err)
	}
	if err := p.Apply(ctx, "example.com", nil, ch); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Fatalf("no such hosted zone: %v", err)
	}
	if err := p.Apply(ctx, "example.com", nil, ch); err == nil || errors.Is(err, provider.ErrConflict) || errors.As(err, &inv) {
		t.Fatalf("other error: %v", err)
	}
}

func TestNormalizeRefusals(t *testing.T) {
	p, _ := newTestProvider(t)
	cases := []dns.RRset{
		{Key: dns.Key{Host: "@", Type: "SOA"}, TTL: 300, Values: []string{"a. b. 1 2 3 4 5"}},
		{Key: dns.Key{Host: "@", Type: "NS"}, TTL: 300, Values: []string{"ns.example.net."}},
		{Key: dns.Key{Host: "@", Type: "CNAME"}, TTL: 300, Values: []string{"x.example.net."}},
		{Key: dns.Key{Host: "@", Type: "DS"}, TTL: 300, Values: []string{"1 13 2 ABCD"}},
		{Key: dns.Key{Host: "*.x", Type: "NS"}, TTL: 300, Values: []string{"ns.example.net."}},
		{Key: dns.Key{Host: "x", Type: "HINFO"}, TTL: 300, Values: []string{`"a" "b"`}},
		{Key: dns.Key{Host: "x", Type: "A"}, TTL: 300, Values: []string{"2001:db8::1"}},
		{Key: dns.Key{Host: "x", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1 192.0.2.2"}},
		{Key: dns.Key{Host: "x", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1\nx. 0 IN A 192.0.2.2"}},
		{Key: dns.Key{Host: "x", Type: "AAAA"}, TTL: 300, Values: []string{"192.0.2.1"}},
		{Key: dns.Key{Host: "x", Type: "A"}, TTL: -1, Values: []string{"192.0.2.1"}},
		{Key: dns.Key{Host: "x", Type: "A"}, TTL: 300},
		{Key: dns.Key{Host: "x", Type: "CNAME"}, TTL: 300, Values: []string{"a.example.net.", "b.example.net."}},
		{Key: dns.Key{Host: "x", Type: "CNAME"}, TTL: 300, Values: []string{"a..b"}},
		{Key: dns.Key{Host: "x", Type: "MX"}, TTL: 300, Values: []string{"70000 mx.example.net."}},
		{Key: dns.Key{Host: "x", Type: "SRV"}, TTL: 300, Values: []string{"1 2 mx.example.net."}},
		{Key: dns.Key{Host: "x", Type: "CAA"}, TTL: 300, Values: []string{"300 issue x"}},
		{Key: dns.Key{Host: "x", Type: "TXT"}, TTL: 300, Values: []string{strings.Repeat("x", 3990)}},
		{Key: dns.Key{Host: "a.*", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}},
		{Key: dns.Key{Host: "a*", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}},
		{Key: dns.Key{Host: strings.Repeat("a", 64), Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}},
		{Key: dns.Key{Host: "x", Type: "CNAME"}, Alias: &dns.Alias{Target: "a.example.net", HostedZoneID: "Z1"}},
		{Key: dns.Key{Host: "x", Type: "A"}, Values: []string{"192.0.2.1"}, Alias: &dns.Alias{Target: "a.example.net", HostedZoneID: "Z1"}},
		{Key: dns.Key{Host: "x", Type: "A"}, Alias: &dns.Alias{Target: "", HostedZoneID: "Z1"}},
		{Key: dns.Key{Host: "x", Type: "A"}, Alias: &dns.Alias{Target: "a.example.net", HostedZoneID: "bad id"}},
	}
	for _, c := range cases {
		_, err := p.Normalize("example.com", c)
		var inv *provider.InvalidError
		if !errors.As(err, &inv) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	got, err := p.Normalize("example.com", dns.RRset{Key: dns.Key{Host: "x", Type: "A"}, TTL: 300, Alias: &dns.Alias{Target: "a.example.net", HostedZoneID: "Z1"}})
	if err != nil || got.TTL != 0 {
		t.Fatalf("alias TTL: %+v %v", got, err)
	}
	if c := p.Capabilities(); !c.AtomicBatch || !c.ConditionalWrite || !c.Alias || c.FullZoneWrite || c.MaxTTL != 2147483647 || len(c.Types) != len(writable) {
		t.Fatalf("capabilities %+v", c)
	}
}

func TestListZones(t *testing.T) {
	ctx := context.Background()
	f := newFake(2)
	f.addZone("Z1", "example.com", false, baseSets()...)
	f.addZone("Z2", "example.com", true)
	f.addZone("Z3", "other.org", false)
	f.addZone("Z4", "internal.lan", true)
	f.addZone("Z5", "dup.net", false)
	f.addZone("Z6", "dup.net", false)

	p, _ := New(ctx, "r53", Config{}, WithClient(f))
	if _, err := p.ListZones(ctx); err == nil || !strings.Contains(err.Error(), "dup.net") {
		t.Fatalf("duplicate public zones: %v", err)
	}
	if _, err := p.ReadZone(ctx, "dup.net"); err == nil || !strings.Contains(err.Error(), "Z5") {
		t.Fatalf("lookup of a duplicate zone: %v", err)
	}
	if _, err := p.ReadZone(ctx, "missing.com"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Fatalf("missing zone: %v", err)
	}
	if _, err := p.ReadZone(ctx, "internal.lan"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Fatalf("private zone visible: %v", err)
	}
	if z, err := p.ReadZone(ctx, "example.com"); err != nil || len(z.RRsets) != 2 {
		t.Fatalf("public example.com: %+v %v", z, err)
	}

	p, _ = New(ctx, "r53", Config{HostedZones: map[string]string{"Dup.net.": "/hostedzone/z6"}}, WithClient(f))
	names, err := p.ListZones(ctx)
	if err != nil || !reflect.DeepEqual(names, []string{"dup.net", "example.com", "other.org"}) {
		t.Fatalf("zones %v %v", names, err)
	}
	if id, _ := p.zoneID(ctx, "example.com"); id != "Z1" {
		t.Fatalf("example.com resolved to %s", id)
	}
	if id, _ := p.zoneID(ctx, "dup.net"); id != "Z6" {
		t.Fatalf("dup.net resolved to %s", id)
	}

	p, _ = New(ctx, "r53", Config{IncludePrivate: true, HostedZones: map[string]string{"dup.net": "Z5"}}, WithClient(f))
	if _, err := p.ListZones(ctx); err == nil || !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "private") {
		t.Fatalf("public and private zones with the same name: %v", err)
	}
	p, _ = New(ctx, "r53", Config{IncludePrivate: true, HostedZones: map[string]string{"dup.net": "Z5", "example.com": "Z2"}}, WithClient(f))
	names, err = p.ListZones(ctx)
	if err != nil || !reflect.DeepEqual(names, []string{"dup.net", "example.com", "internal.lan", "other.org"}) {
		t.Fatalf("zones %v %v", names, err)
	}
	if z, err := p.ReadZone(ctx, "example.com"); err != nil || len(z.RRsets) != 0 {
		t.Fatalf("private example.com: %+v %v", z, err)
	}
	if f.count("ListHostedZones") < 3 {
		t.Fatalf("hosted zones not paginated: %d calls", f.count("ListHostedZones"))
	}
}

func TestZoneNotFoundForgetsCache(t *testing.T) {
	ctx := context.Background()
	p, f := newTestProvider(t)
	if _, err := p.ListZones(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.zones[0].id = "ZNEW"
	f.mu.Unlock()
	if _, err := p.ReadZone(ctx, "example.com"); !errors.Is(err, provider.ErrZoneNotFound) {
		t.Fatalf("deleted zone: %v", err)
	}
	if _, err := p.ReadZone(ctx, "example.com"); err != nil {
		t.Fatalf("recreated zone: %v", err)
	}
}

func TestNewConfig(t *testing.T) {
	ctx := context.Background()
	if _, err := New(ctx, "", Config{}); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := New(ctx, "r53", Config{ExternalID: "x"}); err == nil {
		t.Fatal("external id without role accepted")
	}
	if _, err := New(ctx, "r53", Config{HostedZones: map[string]string{"example.com": ""}}); err == nil {
		t.Fatal("empty pinned id accepted")
	}
	if _, err := New(ctx, "r53", Config{HostedZones: map[string]string{"example.com": "Z1", "Example.com.": "Z2"}}); err == nil {
		t.Fatal("zone pinned twice accepted")
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	p, err := New(ctx, "prod account", Config{AssumeRoleARN: "arn:aws:iam::123456789012:role/dns-gate", ExternalID: "ext"})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := p.api.(*awsr53.Client)
	if !ok {
		t.Fatalf("client %T", p.api)
	}
	o := c.Options()
	if o.Region != defaultRegion || o.Retryer.MaxAttempts() != retryMaxAttempts {
		t.Fatalf("region %q, %d attempts", o.Region, o.Retryer.MaxAttempts())
	}
	if p.Kind() != "route53" || p.ID() != "prod account" || sessionName(p.ID()) != "dns-gate-prod-account" {
		t.Fatalf("kind %s id %s session %s", p.Kind(), p.ID(), sessionName(p.ID()))
	}
}

const r53ns = `xmlns="https://route53.amazonaws.com/doc/2013-04-01/"`

func TestSDKRetriesThrottlingAndMapsConflicts(t *testing.T) {
	var hits atomic.Int32
	responses := []struct {
		code int
		body string
	}{
		{400, `<?xml version="1.0"?><ErrorResponse ` + r53ns + `><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>r1</RequestId></ErrorResponse>`},
		{200, `<?xml version="1.0"?><ChangeResourceRecordSetsResponse ` + r53ns + `><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2026-11-05T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`},
		{400, `<?xml version="1.0"?><InvalidChangeBatch ` + r53ns + `><Messages><Message>Tried to delete resource record set [name='www.example.com.', type='A'] but the values provided do not match the current values</Message></Messages><RequestId>r3</RequestId></InvalidChangeBatch>`},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(hits.Add(1)) - 1
		if i >= len(responses) || r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/hostedzone/"+zoneID+"/rrset") {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(responses[i].code)
		_, _ = w.Write([]byte(responses[i].body))
	}))
	defer srv.Close()
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		Retryer:     func() aws.Retryer { return retry.AddWithMaxBackoffDelay(newRetryer(), time.Millisecond) },
	}
	api := awsr53.NewFromConfig(cfg, func(o *awsr53.Options) { o.BaseEndpoint = aws.String(srv.URL) })
	p, err := New(context.Background(), "r53", Config{HostedZones: map[string]string{"example.com": zoneID}}, WithClient(api))
	if err != nil {
		t.Fatal(err)
	}
	s := dns.RRset{Key: dns.Key{Host: "www", Type: "A"}, TTL: 300, Values: []string{"192.0.2.1"}}
	ch := []dns.Change{{Op: dns.OpCreate, Key: s.Key, New: &s}}
	if err := p.Apply(context.Background(), "example.com", nil, ch); err != nil {
		t.Fatalf("throttled write: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d requests", hits.Load())
	}
	old := s
	del := []dns.Change{{Op: dns.OpDelete, Key: s.Key, Old: &old}}
	if err := p.Apply(context.Background(), "example.com", nil, del); !errors.Is(err, provider.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
}
