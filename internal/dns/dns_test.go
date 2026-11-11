package dns

import (
	"strings"
	"testing"

	"github.com/KamorionLabs/eurodns-go/rrset"
)

func TestContentHashMatchesEuroDNSGo(t *testing.T) {
	cases := []RRset{
		{TTL: 600, Values: []string{"192.0.2.2", "192.0.2.1"}},
		{TTL: 3600, Values: []string{"10 mx.example.com."}},
		{TTL: 300, Values: []string{"v=spf1 -all", "ab", "c"}},
		{TTL: 0},
	}
	for _, c := range cases {
		if got, want := ContentHash(c), rrset.ContentHash(rrset.Set{TTL: c.TTL, Values: c.Values}); got != want {
			t.Fatalf("hash of %+v = %s, eurodns-go %s", c, got, want)
		}
	}
	a := RRset{TTL: 0, Alias: &Alias{Target: "d1.cloudfront.net.", HostedZoneID: "Z2FDTNDATAQYW2"}}
	b := RRset{TTL: 0, Alias: &Alias{Target: "D1.cloudfront.net", HostedZoneID: "z2fdtndataqyw2"}}
	if ContentHash(a) != ContentHash(b) {
		t.Fatal("alias hash must ignore case and trailing dot")
	}
	b.Alias.EvaluateTargetHealth = true
	if ContentHash(a) == ContentHash(b) {
		t.Fatal("alias hash must depend on evaluate_target_health")
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"", "example.com"}: "@", {"example.com.", "example.com"}: "@",
		{"WWW.example.com.", "Example.COM"}: "www", {"a.b", "example.com"}: "a.b",
	} {
		if got := NormalizeHost(in[0], in[1]); got != want {
			t.Errorf("NormalizeHost(%q,%q)=%q want %q", in[0], in[1], got, want)
		}
	}
}

func TestHostProblem(t *testing.T) {
	const zone = "example.com"
	for _, h := range []string{"@", "www", "a.b", "_acme-challenge.www", "*", "*.wild", "com", "example", "xexample.com", "example.com.x"} {
		if msg := HostProblem(h, zone); msg != "" {
			t.Errorf("HostProblem(%q) = %q, want none", h, msg)
		}
	}
	for _, h := range []string{
		"", "example.com", "www.example.com", "a.example.com.example.com", "WWW", "www.", `\119ww`, `a\.b`,
		"a b", "a\tb", "a\nb", ".a", "a..b", strings.Repeat("a.", 127),
	} {
		if msg := HostProblem(h, zone); msg == "" {
			t.Errorf("HostProblem(%q) accepted", h)
		}
	}
	// Whatever the input, a normalized host that passes is stable.
	for _, in := range []string{"example.com.example.com", "www.example.com.example.com.", "Example.COM.", "a.example.com"} {
		h := NormalizeHost(in, zone)
		if HostProblem(h, zone) == "" && NormalizeHost(h, zone) != h {
			t.Errorf("%q normalizes to %q, accepted but not stable", in, h)
		}
	}
}

func TestForwardContentHash(t *testing.T) {
	f := RRset{Key: ForwardKey("go"), Forward: &Forward{Mode: ForwardPermanent, URL: "https://example.net/"}}
	if got := ContentHash(f); got != "a5df29b0fe2e36e66de490cd3dd44e3997fa76fa19194790e245bbd9eac2a796" {
		t.Fatalf("forward hash changed: %s", got)
	}
	g := f
	g.Forward = &Forward{Mode: ForwardPermanent, URL: "https://example.net/", Title: "t"}
	if ContentHash(g) == ContentHash(f) {
		t.Fatal("title ignored")
	}
	g.Forward = &Forward{Mode: ForwardPermanent, URL: "https://example.net/ 0:"}
	if ContentHash(g) == ContentHash(f) {
		t.Fatal("field boundaries ambiguous")
	}
	if !ForwardKey("x").IsForward() || (Key{Host: "x", Type: "urlfwd"}).IsForward() != true || (Key{Host: "x", Type: "URL"}).IsForward() {
		t.Fatal("IsForward")
	}
}
