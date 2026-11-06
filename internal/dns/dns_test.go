package dns

import (
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
