package server

import (
	"net/http"
	"strings"
)

// apiRoute is one route of the gate API under /api/v1. Pattern segments in
// braces match exactly one non-empty path segment. The table is the router
// of handleUIAPI and must stay in sync with api/dns-gate.openapi.yaml (see
// TestOpenAPICoversRoutes).
type apiRoute struct {
	Method  string
	Pattern string
}

const (
	routeZoneRRsets = "/api/v1/zones/{zone}/rrsets"
	routeRRset      = "/api/v1/zones/{zone}/rrsets/{host}/{type}"
	routePlan       = "/api/v1/zones/{zone}/plan"
	routeApply      = "/api/v1/zones/{zone}/apply"
	routeZoneOps    = "/api/v1/zones/{zone}/"
	routePolicy     = "/api/v1/policy"
	routeTokens     = "/api/v1/tokens"
)

var apiRoutes = []apiRoute{
	{http.MethodGet, "/api/v1/me"},
	{http.MethodGet, "/api/v1/connect"},
	{http.MethodGet, "/api/v1" + claudeDesktopExtensionPath},
	{http.MethodPost, routeTokens},
	{http.MethodGet, "/api/v1/zones"},
	{http.MethodGet, routeZoneRRsets},
	{http.MethodGet, routeRRset},
	{http.MethodPut, routeRRset},
	{http.MethodDelete, routeRRset},
	{http.MethodPost, routePlan},
	{http.MethodPost, routeApply},
	{http.MethodPost, "/api/v1/zones/{zone}/adopt/preview"},
	{http.MethodPost, "/api/v1/zones/{zone}/adopt"},
	{http.MethodGet, "/api/v1/zones/{zone}/terraform"},
	{http.MethodPost, routeZoneTransfers},
	{http.MethodGet, routeTransfers},
	{http.MethodGet, routeTransfer},
	{http.MethodPost, routeTransferApprove},
	{http.MethodPost, routeTransferReject},
	{http.MethodGet, routeTeams},
	{http.MethodGet, routeTeam},
	{http.MethodPost, routeTeamRename},
	{http.MethodGet, "/api/v1/audit"},
	{http.MethodGet, routePolicy},
	{http.MethodGet, "/api/v1/policy/revisions"},
	{http.MethodPost, "/api/v1/policy/revisions"},
	{http.MethodGet, "/api/v1/policy/revisions/{id}"},
	{http.MethodGet, "/api/v1/policy/revisions/{id}/export"},
	{http.MethodPost, "/api/v1/policy/revisions/{id}/approve"},
	{http.MethodPost, "/api/v1/policy/revisions/{id}/reject"},
	{http.MethodPost, "/api/v1/policy/revisions/{id}/activate"},
	{http.MethodPost, "/api/v1/policy/revisions/{id}/rollback"},
	{http.MethodPost, "/api/v1/policy/explain"},
	{http.MethodGet, "/api/v1/policy/who-can"},
	{http.MethodPost, "/api/v1/policy/virtual-keys/generate"},
	{http.MethodGet, routeAPIKeys},
	{http.MethodPost, routeAPIKeys},
	{http.MethodGet, routeAPIKey},
	{http.MethodPut, routeAPIKey},
	{http.MethodDelete, routeAPIKey},
	{http.MethodPost, routeAPIKeyRotate},
	{http.MethodGet, "/api/v1/policy/delegated"},
	{http.MethodGet, "/api/v1/policy/delegated/roles/{name}"},
	{http.MethodPut, "/api/v1/policy/delegated/roles/{name}"},
	{http.MethodDelete, "/api/v1/policy/delegated/roles/{name}"},
	{http.MethodGet, "/api/v1/policy/delegated/bindings/{name}"},
	{http.MethodPut, "/api/v1/policy/delegated/bindings/{name}"},
	{http.MethodDelete, "/api/v1/policy/delegated/bindings/{name}"},
	{http.MethodGet, routeProfiles},
	{http.MethodPost, routeProfiles},
	{http.MethodPost, routeProfileCheck},
	{http.MethodGet, routeProfile},
	{http.MethodPut, routeProfile},
	{http.MethodDelete, routeProfile},
}

// matchAPIRoute resolves a request path against apiRoutes. It returns the
// pattern and its parameters, or the status to answer: 404 when no pattern
// matches the path, 405 when one does but not with this method.
func matchAPIRoute(method, path string) (string, map[string]string, int) {
	segs := strings.Split(path, "/")
	status := http.StatusNotFound
	for _, rt := range apiRoutes {
		params, ok := matchPattern(rt.Pattern, segs)
		if !ok {
			continue
		}
		if rt.Method != method {
			status = http.StatusMethodNotAllowed
			continue
		}
		return rt.Pattern, params, http.StatusOK
	}
	return "", nil, status
}

func matchPattern(pattern string, segs []string) (map[string]string, bool) {
	ps := strings.Split(pattern, "/")
	if len(ps) != len(segs) {
		return nil, false
	}
	var params map[string]string
	for i, p := range ps {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			if segs[i] == "" {
				return nil, false
			}
			if params == nil {
				params = map[string]string{}
			}
			params[p[1:len(p)-1]] = segs[i]
			continue
		}
		if p != segs[i] {
			return nil, false
		}
	}
	return params, true
}
