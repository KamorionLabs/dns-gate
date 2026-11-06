package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/eurodnsapi"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/routes"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
	api "github.com/KamorionLabs/eurodns-go"
)

const (
	routeProfiles     = "/api/v1/providers/{provider}/zone-profiles"
	routeProfileCheck = routeProfiles + "/check"
	routeProfile      = routeProfiles + "/{id}"
)

// Zone profile operations.
const (
	profileList   = "list"
	profileGet    = "get"
	profileCheck  = "check"
	profileCreate = "create"
	profileUpdate = "update"
	profileDelete = "delete"
)

// maxProfileName bounds the name of a zone profile.
const maxProfileName = 255

// providerIDRe is the format of provider ids (providers[].id).
var providerIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

// reasonInvalidProfile refuses a profile the gate will not send to EuroDNS.
const reasonInvalidProfile zonewrite.Reason = "invalid"

// profileCall is one zone profile operation, whatever the channel (EuroDNS
// API, REST API, MCP).
type profileCall struct {
	Op       string
	Provider string // provider id, "" for the only EuroDNS provider
	ID       int64
	Profile  *eurodnsprov.ZoneProfile
	Page     eurodnsprov.ProfilePage
	// AllPages lists every page instead of Page.
	AllPages bool
}

type profileResult struct {
	Provider string
	List     []eurodnsprov.ZoneProfileSummary
	Header   http.Header
	Profile  *eurodnsprov.ZoneProfile
}

// profileAuditor records one zone profile decision of a channel.
type profileAuditor func(ctx context.Context, provider, decision, reason string, extra map[string]any)

// canManageProfiles reports whether subj holds dns.zone.profile on every
// zone: profiles are account-wide objects that name no domain and are
// applied to any domain of the account, so no narrower grant is enough.
func (s *Server) canManageProfiles(subj *identity.Subject) bool {
	return subj != nil && s.cfg.Policy.Current().GrantsPattern(subj.Roles, policy.ActionZoneProfile, "*")
}

func profileForbidden() *zonewrite.Error {
	return &zonewrite.Error{Reason: zonewrite.ReasonForbidden,
		Message: policy.ActionZoneProfile + ` is required on every zone ("*"): zone profiles are account-wide`}
}

// runProfile authorizes, runs and audits a zone profile operation. Gate
// refusals are *zonewrite.Error; EuroDNS refusals wrap *api.APIError.
func (s *Server) runProfile(ctx context.Context, subj *identity.Subject, c profileCall, rec profileAuditor) (*profileResult, error) {
	extra := map[string]any{}
	if c.ID != 0 {
		extra["profile_id"] = c.ID
	}
	if !s.canManageProfiles(subj) {
		rec(ctx, c.Provider, "deny", "forbidden", extra)
		return nil, profileForbidden()
	}
	if s.cfg.EuroDNS == nil {
		rec(ctx, c.Provider, "deny", "not_eurodns", extra)
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonNotFound, Message: "no EuroDNS provider: zone profiles exist only on EuroDNS providers"}
	}
	ep, err := s.cfg.EuroDNS.ProfileAccount(c.Provider)
	if err != nil {
		rec(ctx, c.Provider, "deny", profileErrorReason(err), extra)
		return nil, err
	}
	pid := ep.ID()
	if c.Op == profileCreate || c.Op == profileUpdate {
		if msg := checkProfile(c.Profile); msg != "" {
			rec(ctx, pid, "deny", string(reasonInvalidProfile), extra)
			return nil, &zonewrite.Error{Reason: reasonInvalidProfile, Message: msg}
		}
	}
	if c.Profile != nil && c.Op != profileCheck {
		extra["profile"] = c.Profile.Clean()
	}
	out := &profileResult{Provider: pid}
	switch c.Op {
	case profileList:
		if c.AllPages {
			out.List, err = ep.ListZoneProfiles(ctx)
		} else {
			out.List, out.Header, err = ep.ListZoneProfilesPage(ctx, c.Page)
		}
	case profileGet:
		out.Profile, err = ep.GetZoneProfile(ctx, c.ID)
	case profileCheck:
		out.Profile, err = ep.CheckZoneProfile(ctx, c.Profile)
		if err == nil && out.Profile.Report != nil && out.Profile.Report.IsValid != nil {
			extra["valid"] = *out.Profile.Report.IsValid
		}
	case profileCreate:
		out.Profile, err = ep.CreateZoneProfile(ctx, c.Profile)
		if err == nil && out.Profile.ID != nil {
			extra["profile_id"] = *out.Profile.ID
		}
	case profileUpdate:
		out.Profile, err = ep.UpdateZoneProfile(ctx, c.ID, c.Profile)
	case profileDelete:
		var cur *eurodnsprov.ZoneProfile
		cur, err = ep.GetZoneProfile(ctx, c.ID)
		if err == nil {
			extra["profile"] = cur.Clean()
			err = ep.DeleteZoneProfile(ctx, c.ID)
		}
	default:
		err = &zonewrite.Error{Reason: reasonInvalidProfile, Message: "unknown zone profile operation " + c.Op}
	}
	if err != nil {
		rec(ctx, pid, "error", profileErrorReason(err), extra)
		return nil, err
	}
	rec(ctx, pid, "allow", "", extra)
	return out, nil
}

// checkProfile validates what the gate requires of a profile to save; the
// content itself is validated by EuroDNS.
func checkProfile(p *eurodnsprov.ZoneProfile) string {
	switch {
	case p == nil:
		return "a zone profile is required"
	case strings.TrimSpace(p.Name) == "":
		return "the profile name is required"
	case len(p.Name) > maxProfileName:
		return fmt.Sprintf("the profile name is longer than %d characters", maxProfileName)
	}
	return ""
}

// profileErrorReason is the audit reason of a failed operation.
func profileErrorReason(err error) string {
	if ze, ok := zonewrite.AsError(err); ok {
		return string(ze.Reason)
	}
	var ae *api.APIError
	if errors.As(err, &ae) {
		switch {
		case ae.StatusCode == http.StatusNotFound:
			return "not_found"
		case ae.StatusCode == http.StatusBadRequest || ae.StatusCode == http.StatusUnprocessableEntity:
			return "rejected"
		}
		return "upstream_" + strconv.Itoa(ae.StatusCode)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "upstream"
}

// profileErrorBody maps an error of runProfile to the gate error format of
// the REST API and MCP.
func (s *Server) profileErrorBody(ctx context.Context, err error) (int, errorBody) {
	if ze, ok := zonewrite.AsError(err); ok {
		status := reasonStatus(ze.Reason)
		if ze.Reason == reasonInvalidProfile || ze.Reason == eurodnsapi.ReasonInvalidProvider {
			status = http.StatusBadRequest
		}
		return status, errorBody{Reason: string(ze.Reason), Message: ze.Message, Details: ze.Details}
	}
	var ae *api.APIError
	if errors.As(err, &ae) {
		switch {
		case ae.StatusCode == http.StatusNotFound:
			return http.StatusNotFound, errorBody{Reason: "not_found", Message: "zone profile not found"}
		case ae.StatusCode == http.StatusBadRequest || ae.StatusCode == http.StatusUnprocessableEntity:
			msg := "rejected by EuroDNS"
			if ae.Message != "" {
				msg += ": " + ae.Message
			}
			var details any
			if ae.Report != nil {
				details = ae.Report
			} else if len(ae.Errors) > 0 {
				details = ae.Errors
			}
			return http.StatusBadRequest, errorBody{Reason: "rejected", Message: msg, Details: details}
		case ae.StatusCode == http.StatusTooManyRequests:
			return http.StatusServiceUnavailable, errorBody{Reason: "upstream", Message: "EuroDNS rate limit reached, retry later"}
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, errorBody{Reason: "timeout", Message: "request timed out"}
	}
	s.log.Warn("zone profile upstream error", "request_id", requestid.From(ctx), "err", err)
	return http.StatusBadGateway, errorBody{Reason: "upstream", Message: "EuroDNS error"}
}

// profileEvent builds the audit event of a zone profile decision.
func (s *Server) profileEvent(ctx context.Context, subj *identity.Subject, action, provider, decision, reason string, extra map[string]any) audit.Event {
	e := audit.Event{
		Time: s.now().UTC(), RequestID: requestid.From(ctx), Action: action, Provider: provider,
		Decision: decision, Reason: reason, Extra: map[string]any{},
	}
	if e.RequestID == "" {
		e.RequestID = requestid.New()
	}
	if subj != nil {
		e.Subject, e.SubjectName, e.SubjectCategory, e.Teams = subj.String(), subj.Name, subj.Category, subj.Teams
	}
	for k, v := range extra {
		e.Extra[k] = v
	}
	return e
}

// serveEuroDNSProfile serves the zone profile operations of the
// EuroDNS-compatible API (routes.Account). The provider is the only
// EuroDNS provider, or the one named by the X-DNS-Gate-Provider header.
func (s *Server) serveEuroDNSProfile(w http.ResponseWriter, r *http.Request, subj *identity.Subject, m *routes.Match) {
	c := profileCall{Provider: strings.TrimSpace(r.Header.Get(eurodnsapi.ProviderHeader))}
	if c.Provider != "" && !providerIDRe.MatchString(c.Provider) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid "+eurodnsapi.ProviderHeader+" header")
		return
	}
	if id := m.Params["id"]; id != "" {
		n, err := strconv.ParseInt(id, 10, 32)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid zone profile id")
			return
		}
		c.ID = n
	}
	switch m.Operation.ID {
	case "listZoneProfiles":
		c.Op = profileList
		pg, msg := paginationOf(r.Header)
		if msg != "" {
			writeError(w, http.StatusBadRequest, "bad_request", msg)
			return
		}
		c.Page = pg
	case "getProfile":
		c.Op = profileGet
	case "checkZoneProfile", "createZoneProfile", "updateUserAPiZoneProfile":
		c.Op = map[string]string{"checkZoneProfile": profileCheck, "createZoneProfile": profileCreate, "updateUserAPiZoneProfile": profileUpdate}[m.Operation.ID]
		var p eurodnsprov.ZoneProfile
		if !decodeBody(w, r, &p) {
			return
		}
		c.Profile = &p
	case "deleteZoneProfile":
		c.Op = profileDelete
	default:
		writeError(w, http.StatusForbidden, "operation_denied", "operation not allowed by the gate")
		return
	}
	rec := func(ctx context.Context, provider, decision, reason string, extra map[string]any) {
		s.cfg.Audit.Log(ctx, s.profileEvent(ctx, subj, m.Operation.ID, provider, decision, reason, extra))
	}
	out, err := s.runProfile(r.Context(), subj, c, rec)
	if err != nil {
		var ae *api.APIError
		if errors.As(err, &ae) && passUpstreamStatus(ae.StatusCode) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ae.StatusCode)
			_, _ = w.Write(ae.Body)
			return
		}
		status, body := s.profileErrorBody(r.Context(), err)
		writeJSON(w, status, body)
		return
	}
	switch c.Op {
	case profileList:
		for k, v := range out.Header {
			w.Header()[k] = v
		}
		writeJSON(w, http.StatusOK, out.List)
	case profileCreate:
		writeJSON(w, http.StatusCreated, out.Profile)
	case profileDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, out.Profile)
	}
}

// passUpstreamStatus tells the EuroDNS refusals returned as is to EuroDNS
// clients; the others (credentials of the gate, server errors) become 502.
func passUpstreamStatus(code int) bool {
	switch code {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusTooManyRequests:
		return true
	}
	return false
}

// paginationOf reads the pagination-* request headers of a listing.
func paginationOf(h http.Header) (eurodnsprov.ProfilePage, string) {
	var pg eurodnsprov.ProfilePage
	for _, f := range []struct {
		name string
		dst  *int
		max  int
	}{{"pagination-page", &pg.Page, 1 << 20}, {"pagination-size", &pg.Size, 1000}} {
		v := h.Get(f.name)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > f.max {
			return pg, fmt.Sprintf("%s must be an integer between 1 and %d", f.name, f.max)
		}
		*f.dst = n
	}
	switch pg.SortField = h.Get("pagination-sortfield"); pg.SortField {
	case "", "id", "name":
	default:
		return pg, "pagination-sortfield must be id or name"
	}
	switch pg.SortOrder = h.Get("pagination-sortorder"); pg.SortOrder {
	case "", "asc", "desc":
	default:
		return pg, "pagination-sortorder must be asc or desc"
	}
	return pg, ""
}

// handleZoneProfilesAPI serves /api/v1/providers/{provider}/zone-profiles.
func (s *Server) handleZoneProfilesAPI(w http.ResponseWriter, r *http.Request, subj *identity.Subject, pattern string, params map[string]string) {
	c := profileCall{Provider: params["provider"]}
	if !providerIDRe.MatchString(c.Provider) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid provider")
		return
	}
	var action string
	switch {
	case pattern == routeProfiles && r.Method == http.MethodGet:
		c.Op, c.AllPages = profileList, true
	case pattern == routeProfiles:
		c.Op = profileCreate
	case pattern == routeProfileCheck:
		c.Op = profileCheck
	case r.Method == http.MethodGet:
		c.Op = profileGet
	case r.Method == http.MethodPut:
		c.Op = profileUpdate
	default:
		c.Op = profileDelete
	}
	action = "zone_profile." + c.Op
	if pattern == routeProfile {
		n, err := strconv.ParseInt(params["id"], 10, 32)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid zone profile id")
			return
		}
		c.ID = n
	}
	if c.Op == profileCreate || c.Op == profileUpdate || c.Op == profileCheck {
		var p eurodnsprov.ZoneProfile
		if !decodeBody(w, r, &p) {
			return
		}
		c.Profile = &p
	}
	rec := func(ctx context.Context, provider, decision, reason string, extra map[string]any) {
		e := s.profileEvent(ctx, subj, action, provider, decision, reason, extra)
		e.Extra["via"] = "api"
		s.cfg.Audit.Log(ctx, e)
	}
	out, err := s.runProfile(r.Context(), subj, c, rec)
	if err != nil {
		status, body := s.profileErrorBody(r.Context(), err)
		writeJSON(w, status, body)
		return
	}
	switch c.Op {
	case profileList:
		list := uiapi.ZoneProfileList{Provider: out.Provider, Profiles: make([]uiapi.ZoneProfileSummary, 0, len(out.List))}
		for _, p := range out.List {
			list.Profiles = append(list.Profiles, uiapi.ZoneProfileSummary{ID: p.ID, Name: p.Name})
		}
		writeJSON(w, http.StatusOK, list)
	case profileCreate:
		writeJSON(w, http.StatusCreated, out.Profile)
	case profileDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, out.Profile)
	}
}
