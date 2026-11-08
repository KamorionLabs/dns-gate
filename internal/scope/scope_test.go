package scope

import (
	"slices"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/identity"
)

func TestGrants(t *testing.T) {
	cases := []struct {
		scopes []string
		intent identity.Intent
		action string
		want   bool
	}{
		{[]string{DNSRead}, "", "dns.read", true},
		{[]string{DNSRead}, "", "ui.read", true},
		{[]string{DNSRead}, "", "dns.record.write", false},
		{[]string{DNSPlan}, "", "dns.record.write", false},
		{[]string{DNSPlan}, identity.IntentPlan, "dns.record.write", true},
		{[]string{DNSPlan}, identity.IntentPlan, "dns.record.adopt", true},
		{[]string{DNSPlan}, identity.IntentTransfer, "dns.record.write", false},
		{[]string{DNSTransfer}, identity.IntentTransfer, "dns.record.write", true},
		{[]string{DNSTransfer}, "", "dns.record.write", false},
		{[]string{DNSTransfer}, "", "dns.ownership.approve", true},
		{[]string{DNSWrite}, "", "dns.forward.write", true},
		{[]string{DNSAdopt}, "", "dns.record.adopt", true},
		{[]string{PolicyRead}, "", "policy.read", true},
	}
	for _, c := range cases {
		if got := Grants(c.scopes, c.intent, c.action); got != c.want {
			t.Errorf("%v %q %s: %v", c.scopes, c.intent, c.action, got)
		}
	}
	for _, a := range NeverDelegable {
		for _, i := range []identity.Intent{"", identity.IntentPlan, identity.IntentTransfer} {
			if Grants(All, i, a) {
				t.Errorf("%s granted under %q", a, i)
			}
		}
	}
}

func TestPermits(t *testing.T) {
	if !Permits(&identity.Subject{}, "dns.zone.admin", "example.com") || !Permits(nil, "dns.zone.admin", "") {
		t.Fatal("subjects without client are not capped")
	}
	s := &identity.Subject{Client: &identity.Client{ID: "c", Zones: []string{"*.example.com", "example.org"}}, Scopes: []string{DNSRead}}
	for zone, want := range map[string]bool{"a.example.com": true, "example.org": true, "Example.ORG.": true, "example.com": false, "example.net": false, "": true} {
		if got := Permits(s, "dns.read", zone); got != want {
			t.Errorf("%q: %v", zone, got)
		}
	}
	if Permits(s, "dns.record.write", "example.org") {
		t.Fatal("action outside the scopes")
	}
}

func TestClipZones(t *testing.T) {
	for _, c := range []struct {
		zones, client, want []string
	}{
		{[]string{"*"}, nil, []string{"*"}},
		{[]string{"*"}, []string{"*.example.com"}, []string{"*.example.com"}},
		{[]string{"a.example.com", "example.net"}, []string{"*.example.com"}, []string{"a.example.com"}},
		{[]string{"*.example.com"}, []string{"example.org"}, []string{}},
	} {
		if got := ClipZones(c.zones, c.client); !slices.Equal(got, c.want) {
			t.Errorf("%v %v: %v", c.zones, c.client, got)
		}
	}
}

func TestAny(t *testing.T) {
	s := &identity.Subject{Client: &identity.Client{ID: "c"}, Scopes: []string{DNSPlan}}
	if !Any(s, nil) || !Any(s, []string{DNSPlan, DNSWrite}) || Any(s, []string{DNSWrite}) {
		t.Fatal("Any")
	}
	if !slices.Equal(Actions([]string{DNSRead, DNSPlan}), []string{"dns.read", "domain.read", "ui.read"}) {
		t.Fatalf("Actions: %v", Actions([]string{DNSRead, DNSPlan}))
	}
}
