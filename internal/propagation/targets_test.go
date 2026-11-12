package propagation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func resolve(t *testing.T, e *env, names ...string) map[string]Target {
	t.Helper()
	out, err := e.checker.ResolveTargets(context.Background(), "tester", names)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestResolveTargetsStatuses(t *testing.T) {
	e := newEnv(t, 1, nil)
	r := e.resolvers[0]
	// live through a CNAME chain
	r.handle("app.example.net.", mdns.TypeA, answer(t, false,
		"app.example.net. 300 IN CNAME d111.cloudfront.net.",
		"d111.cloudfront.net. 60 IN A 192.0.2.10",
		"d111.cloudfront.net. 60 IN A 192.0.2.11"))
	// dangling CNAME towards a deleted distribution
	r.handle("old.example.net.", mdns.TypeA, func(req, resp *mdns.Msg, tcp bool) {
		answer(t, false, "old.example.net. 300 IN CNAME dgone.cloudfront.net.")(req, resp, tcp)
		resp.Rcode = mdns.RcodeNameError
	})
	r.handle("old.example.net.", mdns.TypeAAAA, negative(t, mdns.RcodeNameError, false))
	// a name of the zone's own that does not exist: no takeover service
	r.handle("nope.example.net.", mdns.TypeA, negative(t, mdns.RcodeNameError, false))
	// exists without addresses
	r.handle("txt.example.net.", mdns.TypeA, negative(t, mdns.RcodeSuccess, false))
	r.handle("txt.example.net.", mdns.TypeAAAA, negative(t, mdns.RcodeSuccess, false))
	// IPv6 only
	r.handle("v6.example.net.", mdns.TypeA, negative(t, mdns.RcodeSuccess, false))
	r.handle("v6.example.net.", mdns.TypeAAAA, answer(t, false, "v6.example.net. 60 IN AAAA 2001:db8::1"))
	// broken delegation
	r.handle("broken.example.net.", mdns.TypeA, negative(t, mdns.RcodeServerFailure, false))

	got := resolve(t, e, "App.Example.Net", "old.example.net.", "nope.example.net", "txt.example.net", "v6.example.net", "broken.example.net", "", "not a name")
	if len(got) != 6 {
		t.Fatalf("got %d targets: %v", len(got), got)
	}
	live := got["app.example.net."]
	if live.Status != TargetLive || !slices.Equal(live.Chain, []string{"d111.cloudfront.net."}) ||
		!slices.Equal(live.Addresses, []string{"192.0.2.10", "192.0.2.11"}) || live.TakeoverRisk != "" || live.Resolver != "r0" {
		t.Fatalf("live: %+v", live)
	}
	old := got["old.example.net."]
	if old.Status != TargetNXDomain || !slices.Equal(old.Chain, []string{"dgone.cloudfront.net."}) || old.TakeoverRisk != "AWS CloudFront" {
		t.Fatalf("dangling: %+v", old)
	}
	if n := got["nope.example.net."]; n.Status != TargetNXDomain || n.TakeoverRisk != "" {
		t.Fatalf("nxdomain: %+v", n)
	}
	if n := got["txt.example.net."]; n.Status != TargetNoData {
		t.Fatalf("nodata: %+v", n)
	}
	if n := got["v6.example.net."]; n.Status != TargetLive || !slices.Equal(n.Addresses, []string{"2001:db8::1"}) {
		t.Fatalf("v6: %+v", n)
	}
	if n := got["broken.example.net."]; n.Status != TargetServFail || n.Error != "servfail" {
		t.Fatalf("servfail: %+v", n)
	}
}

func TestResolveTargetsFallbackAndFiltering(t *testing.T) {
	e := newEnv(t, 3, nil)
	// r0 is filtering: asked last. r1 fails, r2 answers.
	e.checker.opt.Resolvers[0].Filtering = true
	e.resolvers[0].handle("app.example.net.", mdns.TypeA, answer(t, false, "app.example.net. 60 IN A 192.0.2.99"))
	e.resolvers[1].handle("app.example.net.", mdns.TypeA, negative(t, mdns.RcodeServerFailure, false))
	e.resolvers[2].handle("app.example.net.", mdns.TypeA, answer(t, false, "app.example.net. 60 IN A 192.0.2.1"))
	got := resolve(t, e, "app.example.net")["app.example.net."]
	if got.Status != TargetLive || got.Resolver != "r2" || !slices.Equal(got.Addresses, []string{"192.0.2.1"}) {
		t.Fatalf("fallback: %+v", got)
	}
	if e.resolvers[0].queries.Load() != 0 {
		t.Fatal("the filtering resolver was asked although two others were available")
	}
}

func TestResolveTargetsTimeout(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	e := newEnv(t, 0, func(o *Options) {
		o.QueryTimeout = 100 * time.Millisecond
		o.Resolvers = []Resolver{{Name: "silent", Address: pc.LocalAddr().String()}}
	})
	got := resolve(t, e, "app.example.net")["app.example.net."]
	if got.Status != TargetTimeout || got.Error != "timeout" {
		t.Fatalf("timeout: %+v", got)
	}
}

func TestResolveTargetsCacheAndRateLimit(t *testing.T) {
	e := newEnv(t, 1, func(o *Options) { o.RequestsPerMinute = 1 })
	r := e.resolvers[0]
	for i := range 6 {
		n := fmt.Sprintf("h%d.example.net.", i)
		r.handle(n, mdns.TypeA, answer(t, false, n+" 60 IN A 192.0.2.1"))
	}
	if got := resolve(t, e, "h0.example.net", "h1.example.net"); got["h0.example.net."].Cached || len(got) != 2 {
		t.Fatalf("first call: %+v", got)
	}
	asked := r.queries.Load()
	// served from the cache: no query, no token
	for range 10 {
		got := resolve(t, e, "h0.example.net", "h1.example.net")
		if !got["h0.example.net."].Cached || !got["h1.example.net."].Cached {
			t.Fatalf("not cached: %+v", got)
		}
	}
	if r.queries.Load() != asked {
		t.Fatal("cached targets were asked again")
	}
	// burst of 5 calls that ask something, then the limit
	for i := 2; i < 6; i++ {
		resolve(t, e, fmt.Sprintf("h%d.example.net", i))
	}
	if _, err := e.checker.ResolveTargets(context.Background(), "tester", []string{"other.example.net"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	// another subject has its own budget
	if _, err := e.checker.ResolveTargets(context.Background(), "someone-else", []string{"h2.example.net"}); err != nil {
		t.Fatal(err)
	}
	// after the cache TTL, the target is asked again
	e.now = e.now.Add(DefaultTargetCacheTTL + time.Second)
	if _, err := e.checker.ResolveTargets(context.Background(), "someone-else", []string{"h0.example.net"}); err != nil {
		t.Fatal(err)
	}
	if r.queries.Load() == asked {
		t.Fatal("an expired target was not asked again")
	}
}

func TestResolveTargetsBounds(t *testing.T) {
	e := newEnv(t, 1, nil)
	names := make([]string, 0, MaxTargets+10)
	for i := range MaxTargets + 10 {
		n := fmt.Sprintf("h%d.example.net.", i)
		e.resolvers[0].handle(n, mdns.TypeA, answer(t, false, n+" 60 IN A 192.0.2.1"))
		names = append(names, n, n) // duplicates count once
	}
	got := resolve(t, e, names...)
	skipped := 0
	for _, tg := range got {
		if tg.Status == TargetSkipped {
			skipped++
		}
	}
	if len(got) != MaxTargets+10 || skipped != 10 {
		t.Fatalf("got %d targets, %d skipped", len(got), skipped)
	}
}

func TestTakeoverService(t *testing.T) {
	for name, want := range map[string]string{
		"d1.cloudfront.net.":                   "AWS CloudFront",
		"bucket.s3.amazonaws.com":              "AWS S3",
		"x.s3-website-eu-west-1.amazonaws.com": "AWS",
		"app.azurewebsites.net":                "Azure App Service",
		"foo.herokuapp.com":                    "Heroku",
		"cloudfront.net":                       "AWS CloudFront",
		"notcloudfront.net":                    "",
		"www.example.com":                      "",
		"contoso.mail.protection.outlook.com":  "",
		"Site.GitHub.IO.":                      "GitHub Pages",
		"myaccount.blob.core.windows.net":      "Azure Blob Storage",
		"something.trafficmanager.net":         "Azure Traffic Manager",
	} {
		if got := TakeoverService(name); got != want {
			t.Errorf("TakeoverService(%q) = %q, want %q", name, got, want)
		}
	}
}
