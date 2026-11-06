package policy

import (
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
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

func TestImpactWarnsOfIneffectiveManagedProfileGrant(t *testing.T) {
	c := layeredConfig()
	c.Policy.Bounds.Actions = append(c.Policy.Bounds.Actions, ActionZoneProfile)
	h, _ := NewHolder(c)
	old := goodDoc()
	oldSnap, _ := h.Compile(&old, "rev1")
	next := goodDoc()
	next.Roles["profiles"] = uiapi.Role{Rules: []uiapi.Rule{{Zones: []string{"example.com"}, Actions: []string{ActionZoneProfile}}}}
	next.Bindings = append(next.Bindings, uiapi.Binding{Role: "profiles", Team: "web", Groups: []string{"operators"}})
	newSnap, errs := h.Compile(&next, "rev2")
	if len(errs) > 0 {
		t.Fatal(paths(errs))
	}
	for _, it := range Impact(oldSnap, newSnap, nil) {
		if it.Kind == "warning" && it.Role == "profiles" && strings.Contains(it.Message, ActionZoneProfile) {
			return
		}
	}
	t.Fatalf("no warning: %+v", Impact(oldSnap, newSnap, nil))
}
