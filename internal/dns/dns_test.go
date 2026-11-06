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
