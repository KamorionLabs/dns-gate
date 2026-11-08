package server

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/scope"
)

// delegableRoutes are the /api/v1 routes open to delegated clients, with
// the scopes one of which is required. A route missing here is refused to
// every delegated client (not_delegable).
var delegableRoutes = map[string][]string{
	http.MethodGet + " /api/v1/me":                          {},
	http.MethodGet + " /api/v1/zones":                       {scope.DNSRead},
	http.MethodGet + " " + routeZoneRRsets:                  {scope.DNSRead},
	http.MethodGet + " " + routeRRset:                       {scope.DNSRead},
	http.MethodPut + " " + routeRRset:                       {scope.DNSWrite},
	http.MethodDelete + " " + routeRRset:                    {scope.DNSWrite},
	http.MethodGet + " " + routeForwards:                    {scope.DNSRead},
	http.MethodGet + " " + routeForward:                     {scope.DNSRead},
	http.MethodPut + " " + routeForward:                     {scope.DNSWrite},
	http.MethodDelete + " " + routeForward:                  {scope.DNSWrite},
	http.MethodGet + " " + routePropagation:                 {scope.DNSRead},
	http.MethodPost + " " + routePlan:                       {scope.DNSPlan, scope.DNSWrite},
	http.MethodPost + " " + routeApply:                      {scope.DNSWrite},
	http.MethodPost + " /api/v1/zones/{zone}/adopt/preview": {scope.DNSPlan, scope.DNSAdopt},
	http.MethodPost + " /api/v1/zones/{zone}/adopt":         {scope.DNSAdopt},
	http.MethodGet + " /api/v1/zones/{zone}/terraform":      {scope.DNSRead},
	http.MethodPost + " " + routeZoneTransfers:              {scope.DNSTransfer},
	http.MethodGet + " " + routeTransfers:                   {scope.DNSRead},
	http.MethodGet + " " + routeTransfer:                    {scope.DNSRead},
	http.MethodPost + " " + routeTransferApprove:            {scope.DNSTransfer},
	http.MethodPost + " " + routeTransferReject:             {scope.DNSTransfer},
	http.MethodGet + " " + routeTeams:                       {scope.DNSRead},
	http.MethodGet + " " + routeTeam:                        {scope.DNSRead},
	http.MethodGet + " /api/v1/audit":                       {scope.DNSRead},
	http.MethodPost + " /api/v1/policy/explain":             {scope.PolicyRead},
	http.MethodGet + " /api/v1/policy/who-can":              {scope.PolicyRead},
}

// mcpToolScopes are the MCP tools open to delegated clients, with the
// scopes one of which is required. Other tools are hidden from them and
// refused.
var mcpToolScopes = map[string][]string{
	"list_zones":         {scope.DNSRead},
	"list_rrsets":        {scope.DNSRead},
	"get_rrset":          {scope.DNSRead},
	"search_audit":       {scope.DNSRead},
	"list_teams":         {scope.DNSRead},
	"get_team":           {scope.DNSRead},
	"transfer_list":      {scope.DNSRead},
	"check_propagation":  {scope.DNSRead},
	"explain":            {scope.PolicyRead},
	"who_can":            {scope.PolicyRead},
	"plan_rrset_change":  {scope.DNSPlan, scope.DNSWrite},
	"apply_rrset_change": {scope.DNSWrite},
	"adopt_preview":      {scope.DNSPlan, scope.DNSAdopt},
	"adopt_apply":        {scope.DNSAdopt},
	"transfer_propose":   {scope.DNSTransfer},
	"transfer_approve":   {scope.DNSTransfer},
	"transfer_reject":    {scope.DNSTransfer},
}

// delegationError is the refusal of a request of a delegated subject:
// not_delegable or scope_insufficient (with the scope to ask for).
type delegationError struct {
	reason   string
	message  string
	required string
}

// checkDelegated checks a delegated subject against the scopes a route or
// a tool requires; known is false for a route or tool closed to delegated
// clients. Subjects that are not delegated always pass.
func checkDelegated(subj *identity.Subject, required []string, known bool, what string) *delegationError {
	if !scope.Delegated(subj) {
		return nil
	}
	if !known {
		return &delegationError{reason: "not_delegable", message: what + " is not open to delegated clients (client " + subj.Client.ID + ")"}
	}
	if scope.Any(subj, required) {
		return nil
	}
	return &delegationError{reason: "scope_insufficient", required: required[0],
		message: what + " requires the scope " + strings.Join(required, " or ") + ", not granted to client " + subj.Client.ID}
}

// delegatedWriteAge refuses the writes of a subject delegated to a
// declared OAuth client with write_max_age (routes and tools requiring
// dns.write, dns.transfer or dns.adopt only) when its last sign-in at the
// gate is older:
// reauth_required, the client sends the user to /oauth/authorize with
// prompt=login.
func (s *Server) delegatedWriteAge(subj *identity.Subject, required []string) *delegationError {
	if !scope.Delegated(subj) || subj.Client.WriteMaxAge <= 0 || len(required) != 1 || !slices.Contains([]string{scope.DNSWrite, scope.DNSTransfer, scope.DNSAdopt}, required[0]) {
		return nil
	}
	at, _ := subj.Claims["auth_time"].(float64)
	if at > 0 && s.now().Sub(time.Unix(int64(at), 0)) <= subj.Client.WriteMaxAge {
		return nil
	}
	return &delegationError{reason: "reauth_required", required: required[0],
		message: "client " + subj.Client.ID + " needs a sign-in at the gate within " + subj.Client.WriteMaxAge.String() + " to write: authorize again with prompt=login"}
}

// delegatedRoute checks a delegated subject against an /api/v1 route.
func delegatedRoute(subj *identity.Subject, method, pattern string) *delegationError {
	required, known := delegableRoutes[method+" "+pattern]
	return checkDelegated(subj, required, known, method+" "+pattern)
}

// delegatedTool checks a delegated subject against an MCP tool.
func delegatedTool(subj *identity.Subject, tool string) *delegationError {
	required, known := mcpToolScopes[tool]
	return checkDelegated(subj, required, known, "tool "+tool)
}

// planIntent returns the subject a plan is computed for: a delegated
// subject is evaluated under the plan intent, where dns.plan counts.
func planIntent(subj *identity.Subject) *identity.Subject {
	if !scope.Delegated(subj) {
		return subj
	}
	return subj.WithIntent(identity.IntentPlan)
}

// planOwner is the owner key of a plan: the subject, and the delegated
// client it acted through. Subject strings start with an issuer name,
// never with "@", so the two forms never collide.
func planOwner(subj *identity.Subject) string {
	if !scope.Delegated(subj) {
		return subj.String()
	}
	return "@" + subj.Client.ID + "/" + subj.String()
}

func writeDelegationError(w http.ResponseWriter, e *delegationError) {
	writeJSON(w, http.StatusForbidden, errorBody{Reason: e.reason, Message: e.message, RequiredScope: e.required})
}

// delegatedPolicyQuery keeps the policy.read queries of a delegated subject
// on the active policy and on the zones of its client.
func delegatedPolicyQuery(subj *identity.Subject, zone, revision string) *policyError {
	if !scope.Delegated(subj) {
		return nil
	}
	if revision != "" {
		return perr(http.StatusForbidden, "not_delegable", "policy revisions are not open to delegated clients")
	}
	if zone != "" && !scope.ZoneAllowed(subj.Client.Zones, zone) {
		return perr(http.StatusForbidden, "forbidden", "zone "+zone+" is outside the zones of client "+subj.Client.ID)
	}
	return nil
}
