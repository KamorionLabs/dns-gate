package routes

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestMappingReferencesGeneratedOperations(t *testing.T) {
	ids := map[string]bool{}
	for _, op := range Operations() {
		ids[op.ID] = true
	}
	for id := range mapping {
		if !ids[id] {
			t.Errorf("mapping references unknown operation %q", id)
		}
	}
	if len(Operations()) < 90 {
		t.Fatalf("generated table too small: %d", len(Operations()))
	}
}

func TestResolve(t *testing.T) {
	tb := New([]string{"example.com"})
	cases := []struct {
		method, target string
		id             string
		kind           Kind
		err            error
	}{
		{"GET", "/dns-zones/example.com", "getDnsZone", Engine, nil},
		{"GET", "/dns-zones/EXAMPLE.com", "getDnsZone", Engine, nil},
		{"PUT", "/dns-zones/example.com", "saveDnsZone", Engine, nil},
		{"POST", "/dns-zones/example.com/check", "checkDnsZone", Engine, nil},
		{"POST", "/dns-zones/example.com/dns-records", "addDnsRecords", Engine, nil},
		{"DELETE", "/dns-zones/example.com/dns-records/42", "deleteDnsRecord", Engine, nil},
		{"GET", "/dns-zones/example.com/snapshots/7", "getSnapShot", Passthrough, nil},
		{"GET", "/domains/example.com", "getDomain", Passthrough, nil},
		{"POST", "/dns-zones/example.com/unsign", "unsignZone", Deny, ErrDenied},
		{"PUT", "/contact-profiles/12", "updateContactProfile", Deny, ErrDenied},
		{"PUT", "/nameserver-profiles/3", "updateNameserverProfile", Deny, ErrDenied},
		{"POST", "/domains/search", "searchDomains", Deny, ErrDenied},
		{"GET", "/zone-profiles", "listZoneProfiles", Account, nil},
		{"POST", "/zone-profiles", "createZoneProfile", Account, nil},
		{"POST", "/zone-profiles/check", "checkZoneProfile", Account, nil},
		{"GET", "/zone-profiles/12", "getProfile", Account, nil},
		{"PUT", "/zone-profiles/12", "updateUserAPiZoneProfile", Account, nil},
		{"DELETE", "/zone-profiles/12", "deleteZoneProfile", Account, nil},
		{"GET", "/zone-profiles/abc", "", 0, ErrBadParam},
		{"GET", "/zone-profiles?name=x", "", 0, ErrQuery},
		{"GET", "/dns-zones/other.com", "getDnsZone", Engine, ErrZoneUnknown},
		{"PATCH", "/dns-zones/example.com", "", 0, ErrMethod},
		{"GET", "/nope", "", 0, ErrNotFound},
		{"GET", "/dns-zones/example.com?x=1", "", 0, ErrQuery},
		{"GET", "/dns-zones/example.com/", "", 0, ErrBadPath},
		{"GET", "/dns-zones//example.com", "", 0, ErrBadPath},
		{"GET", "/dns-zones/../accounts/prepaid-balance", "", 0, ErrBadPath},
		{"GET", "/dns-zones/example.com%2Fsnapshots", "", 0, ErrBadPath},
		{"GET", "/dns-zones/ex%61mple.com", "", 0, ErrBadPath},
		{"DELETE", "/dns-zones/example.com/dns-records/abc", "", 0, ErrBadParam},
		{"GET", "/dns-zones/exa_mple.com", "", 0, ErrBadParam},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://gate"+c.target, nil)
		m, err := tb.Resolve(r)
		if !errors.Is(err, c.err) {
			t.Errorf("%s %s: err %v, want %v", c.method, c.target, err, c.err)
			continue
		}
		if c.id != "" && (m == nil || m.Operation.ID != c.id || m.Rule.Kind != c.kind) {
			t.Errorf("%s %s: got %+v", c.method, c.target, m)
		}
	}
}

func TestResolveRebuildsPath(t *testing.T) {
	tb := New([]string{"example.com"})
	m, err := tb.Resolve(httptest.NewRequest("GET", "http://gate/dns-zones/Example.COM/snapshots", nil))
	if err != nil {
		t.Fatal(err)
	}
	if m.Path != "/dns-zones/example.com/snapshots" || m.Zone != "example.com" {
		t.Fatalf("got %q %q", m.Path, m.Zone)
	}
}
