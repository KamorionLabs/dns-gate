package policy

import (
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

func TestZoneProfileGrantedOnEveryZoneOnly(t *testing.T) {
	c := layeredConfig()
	c.Roles["profiles"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionZoneProfile}}}}
	c.Roles["org-profiles"] = config.Role{Rules: []config.Rule{{Zones: []string{"*.example.org", "example.com"}, Actions: []string{ActionZoneProfile}}}}
	c.Roles["scoped-profiles"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{ActionZoneProfile},
		Records: &config.RecordScope{Hosts: []string{"www"}}}}}
	h, err := NewHolder(c)
	if err != nil {
		t.Fatal(err)
	}
	snap := h.Current()
	for role, want := range map[string]bool{"profiles": true, "org-profiles": false, "scoped-profiles": false} {
		if got := snap.GrantsPattern([]string{role}, ActionZoneProfile, "*"); got != want {
			t.Errorf("%s: GrantsPattern(*) = %v, want %v", role, got, want)
		}
	}
}
