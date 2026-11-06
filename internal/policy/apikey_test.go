package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

func TestKeyRoleProblem(t *testing.T) {
	acme := &config.RecordScope{Hosts: []string{"_acme-challenge", "_acme-challenge.**"}, Types: []string{"TXT"}}
	c := &config.Config{
		Zones: []string{"example.com", "example.org"},
		Roles: map[string]config.Role{
			"keys-com": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionAPIKeyManage, ActionDNSRead, ActionRecordWrite}}}},
			"keys-acme": {Rules: []config.Rule{
				{Zones: []string{"example.com"}, Actions: []string{ActionAPIKeyManage, ActionDNSRead}},
				{Zones: []string{"example.com"}, Actions: []string{ActionRecordWrite}, Records: acme},
			}},
			"keys-all":  {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionAPIKeyManage, ActionDNSRead, ActionRecordWrite}}}},
			"acme-com":  {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionRecordWrite}, Records: acme}}},
			"write-com": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionRecordWrite}}}},
			"acme-all":  {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionRecordWrite}, Records: acme}}},
			"adopt-com": {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionRecordAdopt}}}},
			"meta":      {Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read"}}}},
		},
	}
	s := FromConfig(c).Holder().Current()
	for _, tc := range []struct {
		holder, role, want string
	}{
		{"keys-com", "acme-com", ""},
		{"keys-com", "write-com", ""},
		{"keys-acme", "acme-com", ""},
		{"keys-acme", "write-com", "beyond the caller's own rights"},
		{"keys-com", "acme-all", "not granted on zones"},
		{"keys-all", "acme-all", ""},
		{"keys-com", "adopt-com", "beyond the caller's own rights"},
		{"keys-all", "meta", "which API keys cannot hold"},
		{"keys-all", "keys-com", "which API keys cannot hold"},
		{"keys-com", "nope", "unknown role"},
		{"acme-com", "acme-com", "not granted on zones"},
	} {
		got := s.KeyRoleProblem([]string{tc.holder}, tc.role)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s gives %s: %q, want %q", tc.holder, tc.role, got, tc.want)
		}
	}
	if !s.GrantsPattern([]string{"keys-all"}, ActionAPIKeyManage, "*") || s.GrantsPattern([]string{"keys-com"}, ActionAPIKeyManage, "*") {
		t.Error("GrantsPattern on *")
	}
	if !s.GrantsAnywhere([]string{"keys-com"}, ActionAPIKeyManage) || s.GrantsAnywhere([]string{"acme-com"}, ActionAPIKeyManage) {
		t.Error("GrantsAnywhere")
	}
	if !s.RoleReserved("meta") || !s.RoleReserved("keys-com") || s.RoleReserved("acme-com") || s.RoleReserved("nope") {
		t.Error("RoleReserved")
	}
	if z := s.RoleZones("keys-acme"); len(z) != 2 || s.RoleZones("nope") != nil {
		t.Errorf("RoleZones %v", z)
	}
}

// A caller whose write rights are ephemeral or capped cannot issue a key
// whose role is permanent, longer-lived or less capped.
func TestKeyRoleProblemEphemeralAndCap(t *testing.T) {
	w := []string{ActionDNSRead, ActionRecordWrite}
	rule := []config.Rule{{Zones: []string{"example.com"}, Actions: w}}
	c := &config.Config{
		Zones:  []string{"example.com"},
		Limits: config.Limits{MaxChangesPerRequest: 20},
		Roles: map[string]config.Role{
			"keys": {EphemeralTTL: config.Duration(time.Hour), MaxChangesPerRequest: 5,
				Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: append([]string{ActionAPIKeyManage}, w...)}}},
			"keys-free": {MaxChangesPerRequest: -1, Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: append([]string{ActionAPIKeyManage}, w...)}}},
			"permanent": {MaxChangesPerRequest: 3, Rules: rule},
			"eph-2h":    {EphemeralTTL: config.Duration(2 * time.Hour), MaxChangesPerRequest: 3, Rules: rule},
			"eph-30m":   {EphemeralTTL: config.Duration(30 * time.Minute), MaxChangesPerRequest: 3, Rules: rule},
			"default":   {EphemeralTTL: config.Duration(30 * time.Minute), Rules: rule},
			"unlimited": {EphemeralTTL: config.Duration(30 * time.Minute), MaxChangesPerRequest: -1, Rules: rule},
			"reader":    {Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead}}}},
		},
	}
	s := FromConfig(c).Holder().Current()
	for _, tc := range []struct {
		holder, role, want string
	}{
		{"keys", "eph-30m", ""},
		{"keys", "permanent", "ephemeral"},
		{"keys", "eph-2h", "ephemeral"},
		{"keys", "default", "max_changes_per_request"},
		{"keys", "unlimited", "max_changes_per_request"},
		{"keys", "reader", ""},
		{"keys-free", "permanent", ""},
		{"keys-free", "unlimited", ""},
	} {
		got := s.KeyRoleProblem([]string{tc.holder}, tc.role)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s gives %s: %q, want %q", tc.holder, tc.role, got, tc.want)
		}
	}
}

// The grant recorded with a key holds the role's declared rules and
// limits: raising the global change limit or the bounds of the managed
// layer does not count as a widened role.
func TestRoleGrantDeclared(t *testing.T) {
	rule := []config.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionRecordWrite}}}
	cfg := func(maxChanges int, bounds []string) *config.Config {
		return &config.Config{
			Zones:  []string{"example.com"},
			Limits: config.Limits{MaxChangesPerRequest: maxChanges},
			Roles:  map[string]config.Role{"inherit": {EphemeralTTL: config.Duration(time.Hour), Rules: rule}},
			Policy: config.Policy{Editable: true, Bounds: config.Bounds{Zones: []string{"example.com"}, Actions: bounds}},
		}
	}
	a, _ := FromConfig(cfg(20, []string{ActionDNSRead})).Holder().Current().RoleGrant("inherit")
	b, _ := FromConfig(cfg(50, []string{ActionDNSRead})).Holder().Current().RoleGrant("inherit")
	if !b.Within(a) {
		t.Errorf("a higher global limit widened the role: %+v vs %+v", b, a)
	}
	doc := uiapi.PolicyDocument{Roles: map[string]uiapi.Role{"managed": {EphemeralTTL: "1h",
		Rules: []uiapi.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionDNSRead, ActionRecordWrite}}}}}}
	grant := func(bounds []string) RoleGrant {
		h, err := NewHolder(cfg(20, bounds))
		if err != nil {
			t.Fatal(err)
		}
		g, ok := h.CompileUnchecked(&doc, "r1").RoleGrant("managed")
		if !ok {
			t.Fatal("managed role missing")
		}
		return g
	}
	if narrow, wide := grant([]string{ActionDNSRead}), grant([]string{ActionDNSRead, ActionRecordWrite}); !wide.Within(narrow) {
		t.Errorf("wider bounds widened the role: %+v vs %+v", wide, narrow)
	}
	explicit := RoleGrant{Rules: a.Rules, EphemeralTTL: a.EphemeralTTL, MaxChanges: 30}
	if explicit.Within(a) || !a.Within(a) {
		t.Error("declared limits not compared")
	}
}
