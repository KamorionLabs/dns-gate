package policy

import (
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
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
