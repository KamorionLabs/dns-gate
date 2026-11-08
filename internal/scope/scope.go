// Package scope defines the scopes of delegated clients: named allowlists
// of RBAC actions that cap the rights of a user when an application acts
// for it. Effective rights are the RBAC of the user, intersected with the
// actions of the scopes and with the zones of the client.
package scope

import (
	"slices"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/identity"
)

// Scopes.
const (
	DNSRead     = "dns.read"
	DNSPlan     = "dns.plan"
	DNSWrite    = "dns.write"
	DNSAdopt    = "dns.adopt"
	DNSTransfer = "dns.transfer"
	PolicyRead  = "policy.read"
	// OfflineAccess asks the gate authorization server for a refresh
	// token; it grants no action.
	OfflineAccess = "offline_access"
)

// Surfaces a delegated client may use.
const (
	SurfaceAPI = "api"
	SurfaceMCP = "mcp"
)

const (
	actionUIRead           = "ui.read"
	actionDNSRead          = "dns.read"
	actionDomainRead       = "domain.read"
	actionRecordWrite      = "dns.record.write"
	actionForwardWrite     = "dns.forward.write"
	actionRecordAdopt      = "dns.record.adopt"
	actionOwnershipApprove = "dns.ownership.approve"
	actionPolicyRead       = "policy.read"
)

// All lists the scopes, in documentation order.
var All = []string{DNSRead, DNSPlan, DNSWrite, DNSAdopt, DNSTransfer, PolicyRead}

// Surfaces lists the surfaces.
var Surfaces = []string{SurfaceAPI, SurfaceMCP}

var actions = map[string][]string{
	DNSRead:     {actionUIRead, actionDNSRead, actionDomainRead},
	DNSWrite:    {actionRecordWrite, actionForwardWrite},
	DNSAdopt:    {actionRecordAdopt},
	DNSTransfer: {actionOwnershipApprove},
	PolicyRead:  {actionPolicyRead},
}

var intentActions = map[identity.Intent]map[string][]string{
	identity.IntentPlan:     {DNSPlan: {actionRecordWrite, actionForwardWrite, actionRecordAdopt}},
	identity.IntentTransfer: {DNSTransfer: {actionRecordWrite, actionForwardWrite}},
}

// NeverDelegable lists the actions no scope grants, whatever the
// configuration: policy writes, API keys, zone administration and zone
// profiles, OAuth grants.
var NeverDelegable = []string{"policy.propose", "policy.approve", "gate.apikey.manage", "gate.oauth.manage", "dns.zone.admin", "dns.zone.profile"}

// Label is the description of a scope shown on the consent page.
func Label(name string) string {
	switch name {
	case DNSRead:
		return "Read the zones, records, teams, transfers and audit you can read"
	case DNSPlan:
		return "Prepare changes (plans) on the records you can change, without applying them"
	case DNSWrite:
		return "Change and delete the records and forwards you can change"
	case DNSAdopt:
		return "Adopt existing records for your teams"
	case DNSTransfer:
		return "Propose, approve and reject ownership transfers"
	case PolicyRead:
		return "Read the policy and explain who can do what"
	}
	return name
}

// Valid reports whether name is a scope.
func Valid(name string) bool { return slices.Contains(All, name) }

// ValidSurface reports whether name is a surface.
func ValidSurface(name string) bool { return slices.Contains(Surfaces, name) }

// Actions returns the actions the scopes grant, sorted. dns.plan grants
// nothing outside of a plan.
func Actions(scopes []string) []string {
	var out []string
	for _, sc := range scopes {
		for _, a := range actions[sc] {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Grants reports whether the scopes grant action for a request of intent:
// write actions count under dns.plan for a plan and under dns.transfer for
// the ownership checks of a transfer.
func Grants(scopes []string, intent identity.Intent, action string) bool {
	for _, sc := range scopes {
		if slices.Contains(actions[sc], action) || slices.Contains(intentActions[intent][sc], action) {
			return true
		}
	}
	return false
}

// Delegated reports whether s acts through a delegated client: its rights
// are then capped by its scopes and the zones of the client.
func Delegated(s *identity.Subject) bool { return s != nil && s.Client != nil }

// Permits reports whether the scopes and the client zones of s allow
// action on zone (zone is empty for zone-less actions). Subjects that are
// not delegated are not capped.
func Permits(s *identity.Subject, action, zone string) bool {
	if !Delegated(s) {
		return true
	}
	if !Grants(s.Scopes, s.Intent, action) {
		return false
	}
	return zone == "" || ZoneAllowed(s.Client.Zones, zone)
}

// ZoneAllowed reports whether zone matches the client zone globs; no globs
// allow every zone.
func ZoneAllowed(zones []string, zone string) bool {
	if len(zones) == 0 {
		return true
	}
	return glob.Any(zones, strings.TrimSuffix(strings.ToLower(zone), "."))
}

// Any reports whether s holds one of the scopes. An empty list requires
// none.
func Any(s *identity.Subject, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, r := range required {
		if slices.Contains(s.Scopes, r) {
			return true
		}
	}
	return false
}

// Surface reports whether the client of s may use a surface.
func Surface(s *identity.Subject, surface string) bool {
	return !Delegated(s) || slices.Contains(s.Client.Surfaces, surface)
}

// ClipZones returns the zone globs of a permission limited to the client
// zones: a glob is kept when the client zones cover it, a client glob when
// the permission glob covers it. Without client zones the globs are
// returned as is.
func ClipZones(zones, client []string) []string {
	if len(client) == 0 {
		return zones
	}
	out := []string{}
	add := func(z string) {
		if !slices.Contains(out, z) {
			out = append(out, z)
		}
	}
	for _, z := range zones {
		if glob.Covered(client, z) {
			add(z)
			continue
		}
		for _, c := range client {
			if glob.Covered([]string{z}, c) {
				add(c)
			}
		}
	}
	return out
}
