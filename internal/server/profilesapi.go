package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/eurodnsapi"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/routes"
	"github.com/KamorionLabs/dns-gate/internal/scope"
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

// Refusals of zone profile operations, besides the zonewrite reasons.
const (
	reasonInvalidProfile   zonewrite.Reason = "invalid"
	reasonProtectedProfile zonewrite.Reason = "protected"
	reasonReauth           zonewrite.Reason = "reauth_required"
	reasonProfileRate      zonewrite.Reason = "rate_limited"
)

// profileRequestsPerMinute is the zone profile operations allowed per
// subject and minute, all channels together: they share the EuroDNS rate
// limit of the account with every zone write.
const profileRequestsPerMinute = 60

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
	// Session is the UI session of the request, nil for bearer tokens.
	Session *session
	// KeepForwards keeps, on update, the URL and mail forwards of the
	// current profile when the new one leaves them out (null).
	KeepForwards bool
}

type profileResult struct {
	Provider string
	List     []eurodnsprov.ZoneProfileSummary
	Header   http.Header
	Profile  *eurodnsprov.ZoneProfile
}

// profileAuditor records one zone profile decision of a channel.
type profileAuditor func(ctx context.Context, provider, decision, reason string, extra map[string]any, changes []uiapi.Change)

// canManageProfiles reports whether subj holds dns.zone.profile on every
// zone: profiles are account-wide objects that name no domain and are
// applied to any domain of the account, so no narrower grant is enough.
func (s *Server) canManageProfiles(subj *identity.Subject) bool {
	return subj != nil && !scope.Delegated(subj) && s.cfg.Policy.Current().GrantsPattern(subj.Roles, policy.ActionZoneProfile, "*")
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
	deny := func(provider string, err *zonewrite.Error) (*profileResult, error) {
		rec(ctx, provider, "deny", string(err.Reason), extra, nil)
		return nil, err
	}
	if !s.canManageProfiles(subj) {
		return deny(c.Provider, profileForbidden())
	}
	if !s.profileLimiter.allow(subj.String()) {
		return deny(c.Provider, &zonewrite.Error{Reason: reasonProfileRate, Message: "too many zone profile requests, retry in a minute"})
	}
	if s.cfg.EuroDNS == nil {
		return deny(c.Provider, &zonewrite.Error{Reason: eurodnsapi.ReasonProfilesDisabled, Message: "no EuroDNS provider: zone profiles exist only on EuroDNS providers"})
	}
	ep, err := s.cfg.EuroDNS.ProfileAccount(c.Provider)
	if err != nil {
		rec(ctx, c.Provider, "deny", profileErrorReason(err), extra, nil)
		return nil, err
	}
	pid := ep.ID()
	write := c.Op == profileCreate || c.Op == profileUpdate || c.Op == profileDelete
	if write {
		if e := s.stepUp(subj, c.Session); e != nil {
			return deny(pid, &zonewrite.Error{Reason: reasonReauth, Message: e.msg})
		}
	}
	if c.Op == profileCreate || c.Op == profileUpdate {
		if msg := checkProfile(c.Profile); msg != "" {
			return deny(pid, &zonewrite.Error{Reason: reasonInvalidProfile, Message: msg})
		}
	}
	if c.Op == profileCreate || c.Op == profileUpdate || c.Op == profileCheck {
		if c.Profile == nil {
			return deny(pid, &zonewrite.Error{Reason: reasonInvalidProfile, Message: "a zone profile is required"})
		}
		if msg := profileForwardProblem(c.Profile); msg != "" {
			return deny(pid, &zonewrite.Error{Reason: reasonInvalidProfile, Message: msg})
		}
		if msg := s.protectedInProfile(c.Profile); msg != "" {
			return deny(pid, &zonewrite.Error{Reason: reasonProtectedProfile, Message: msg})
		}
	}
	out := &profileResult{Provider: pid}
	var before, after *eurodnsprov.ZoneProfile
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
		after = c.Profile.Clean()
		extra["profile"] = after
		out.Profile, err = ep.CreateZoneProfile(ctx, c.Profile)
		if err == nil && out.Profile.ID != nil {
			extra["profile_id"] = *out.Profile.ID
		}
	case profileUpdate:
		before, err = ep.GetZoneProfile(ctx, c.ID)
		if err != nil {
			break
		}
		before = before.Clean()
		extra["previous"] = before
		next := *c.Profile
		if c.KeepForwards && next.URLForwards == nil {
			next.URLForwards = before.URLForwards
		}
		if c.KeepForwards && next.MailForwards == nil {
			next.MailForwards = before.MailForwards
		}
		after = next.Clean()
		extra["profile"] = after
		out.Profile, err = ep.UpdateZoneProfile(ctx, c.ID, &next)
	case profileDelete:
		before, err = ep.GetZoneProfile(ctx, c.ID)
		if err == nil {
			before = before.Clean()
			extra["profile"] = before
			err = ep.DeleteZoneProfile(ctx, c.ID)
		}
	default:
		err = &zonewrite.Error{Reason: reasonInvalidProfile, Message: "unknown zone profile operation " + c.Op}
	}
	var changes []uiapi.Change
	if write {
		changes = profileChanges(before, after)
	}
	if err != nil {
		rec(ctx, pid, "error", profileErrorReason(err), extra, changes)
		return nil, err
	}
	rec(ctx, pid, "allow", "", extra, changes)
	return out, nil
}

// protectedInProfile returns why a profile holds a record of the protected
// list, "" when it holds none. Mail forwards count as the apex MX, URL
// forwards as A, AAAA and CNAME records of their host. The zones of the
// protected entries are ignored: the profile is applied to domains the gate
// does not know yet.
func (s *Server) protectedInProfile(p *eurodnsprov.ZoneProfile) string {
	return protectedRecordIn(s.cfg.Policy.Current(), p)
}

// profileForwardProblem tells why a URL forward of a profile is refused,
// with the checks of a forward written through the gate.
func profileForwardProblem(p *eurodnsprov.ZoneProfile) string {
	for _, raw := range p.URLForwards {
		if msg := eurodnsprov.ForwardEntryProblem(raw); msg != "" {
			return "invalid URL forward: " + msg
		}
	}
	return ""
}

func protectedRecordIn(snap *policy.Snapshot, p *eurodnsprov.ZoneProfile) string {
	type rec struct{ host, typ, what string }
	var recs []rec
	for _, r := range p.Records {
		recs = append(recs, rec{r.Host, r.Type, "record"})
	}
	if len(p.MailForwards) > 0 {
		recs = append(recs, rec{"@", "MX", "mail forward"})
	}
	for _, raw := range p.URLForwards {
		var f struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return "invalid URL forward"
		}
		recs = append(recs, rec{f.Host, dns.TypeURLForward, "URL forward"})
	}
	for _, r := range recs {
		if pe, ok := snap.ProtectedRecord(r.host, r.typ); ok {
			host := r.host
			if host == "" {
				host = "@"
			}
			return fmt.Sprintf("%s %s %s is protected (hosts %s, types %s): zone profiles may not hold protected records, whatever the zones of the protected entry",
				r.what, host, strings.ToUpper(r.typ), strings.Join(pe.Hosts, ","), strings.Join(pe.Types, ","))
		}
	}
	return ""
}

// profileChanges lists, per host and type, the records a profile write
// creates, changes or deletes, for the audit journal. Values and TTLs are
// left out: the journal is readable by holders of ui.read, the content stays
// in the profile and previous fields of the event.
func profileChanges(before, after *eurodnsprov.ZoneProfile) []uiapi.Change {
	group := func(p *eurodnsprov.ZoneProfile) map[dns.Key]string {
		out := map[dns.Key][]string{}
		if p != nil {
			for _, r := range p.Records {
				h := strings.TrimSuffix(strings.ToLower(r.Host), ".")
				if h == "" {
					h = "@"
				}
				k := dns.Key{Host: h, Type: strings.ToUpper(r.Type)}
				out[k] = append(out[k], fmt.Sprintf("%d %s", r.TTL, r.RData))
			}
		}
		sum := map[dns.Key]string{}
		for k, v := range out {
			sort.Strings(v)
			sum[k] = strings.Join(v, "\x00")
		}
		return sum
	}
	old, cur := group(before), group(after)
	keys := map[dns.Key]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range cur {
		keys[k] = true
	}
	var out []uiapi.Change
	for k := range keys {
		o, inOld := old[k]
		n, inNew := cur[k]
		c := uiapi.Change{Host: k.Host, Type: k.Type}
		switch {
		case !inOld:
			c.Op = "create"
		case !inNew:
			c.Op = "delete"
		case o != n:
			c.Op = "update"
		default:
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// profileActions are the EuroDNS operation ids of zone profiles.
var profileActions = map[string]bool{"listZoneProfiles": true, "createZoneProfile": true, "checkZoneProfile": true,
	"getProfile": true, "updateUserAPiZoneProfile": true, "deleteZoneProfile": true}

// isProfileEvent reports whether an audit action is a zone profile
// operation, on any channel.
func isProfileEvent(action string) bool {
	return strings.HasPrefix(action, "zone_profile.") || profileActions[action] ||
		(strings.HasPrefix(action, "mcp.") && (strings.HasSuffix(action, "_zone_profile") || strings.HasSuffix(action, "_zone_profiles")))
}

// auditVisible reports whether subj may see an audit event of the journal
// whose zone check passed: zone profile events need dns.zone.profile.
func (s *Server) auditVisible(subj *identity.Subject, e audit.Event) bool {
	return !isProfileEvent(e.Action) || s.canManageProfiles(subj)
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
		switch ze.Reason {
		case reasonInvalidProfile, eurodnsapi.ReasonInvalidProvider:
			status = http.StatusBadRequest
		case reasonProtectedProfile, reasonReauth, eurodnsapi.ReasonProfilesDisabled:
			status = http.StatusForbidden
		case reasonProfileRate:
			status = http.StatusTooManyRequests
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
func (s *Server) profileEvent(ctx context.Context, subj *identity.Subject, action, provider, decision, reason string, extra map[string]any, changes []uiapi.Change) audit.Event {
	e := audit.Event{
		Time: s.now().UTC(), RequestID: requestid.From(ctx), Action: action, Provider: provider,
		Decision: decision, Reason: reason, Extra: map[string]any{}, Changes: changes,
	}
	if e.RequestID == "" {
		e.RequestID = requestid.New()
	}
	if subj != nil {
		e.Subject, e.SubjectName, e.SubjectCategory, e.Teams = subj.String(), subj.Name, subj.Category, subj.Teams
		e.SetClient(subj.ClientID(), subj.ClientName())
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
	rec := func(ctx context.Context, provider, decision, reason string, extra map[string]any, changes []uiapi.Change) {
		s.cfg.Audit.Log(ctx, s.profileEvent(ctx, subj, m.Operation.ID, provider, decision, reason, extra, changes))
	}
	c := profileCall{Provider: strings.TrimSpace(r.Header.Get(eurodnsapi.ProviderHeader))}
	bad := func(msg string) {
		rec(r.Context(), c.Provider, "deny", "bad_request", map[string]any{"message": msg}, nil)
		writeError(w, http.StatusBadRequest, "bad_request", msg)
	}
	if c.Provider != "" && !providerIDRe.MatchString(c.Provider) {
		c.Provider = ""
		bad("invalid " + eurodnsapi.ProviderHeader + " header")
		return
	}
	if id := m.Params["id"]; id != "" {
		n, err := strconv.ParseInt(id, 10, 32)
		if err != nil || n <= 0 {
			bad("invalid zone profile id")
			return
		}
		c.ID = n
	}
	switch m.Operation.ID {
	case "listZoneProfiles":
		c.Op = profileList
		pg, msg := paginationOf(r.Header)
		if msg != "" {
			bad(msg)
			return
		}
		c.Page = pg
	case "getProfile":
		c.Op = profileGet
	case "checkZoneProfile", "createZoneProfile", "updateUserAPiZoneProfile":
		c.Op = map[string]string{"checkZoneProfile": profileCheck, "createZoneProfile": profileCreate, "updateUserAPiZoneProfile": profileUpdate}[m.Operation.ID]
		var p eurodnsprov.ZoneProfile
		if !decodeBody(w, r, &p) {
			rec(r.Context(), c.Provider, "deny", "bad_request", map[string]any{"message": "invalid body"}, nil)
			return
		}
		c.Profile = &p
	case "deleteZoneProfile":
		c.Op = profileDelete
	default:
		writeError(w, http.StatusForbidden, "operation_denied", "operation not allowed by the gate")
		return
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
		s.writeProfileError(w, r, err)
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

// writeProfileError writes an error of runProfile in the gate format.
func (s *Server) writeProfileError(w http.ResponseWriter, r *http.Request, err error) {
	status, body := s.profileErrorBody(r.Context(), err)
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, status, body)
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

// maxProfilePageSize caps the page size a client may ask for.
const maxProfilePageSize = 100

// paginationOf reads the pagination-* request headers of a listing.
func paginationOf(h http.Header) (eurodnsprov.ProfilePage, string) {
	var pg eurodnsprov.ProfilePage
	for _, f := range []struct {
		name string
		dst  *int
		max  int
	}{{"pagination-page", &pg.Page, 1 << 20}, {"pagination-size", &pg.Size, maxProfilePageSize}} {
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
func (s *Server) handleZoneProfilesAPI(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, pattern string, params map[string]string) {
	c := profileCall{Provider: params["provider"], Session: sess}
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
	action := "zone_profile." + c.Op
	rec := func(ctx context.Context, provider, decision, reason string, extra map[string]any, changes []uiapi.Change) {
		e := s.profileEvent(ctx, subj, action, provider, decision, reason, extra, changes)
		e.Extra["via"] = "api"
		s.cfg.Audit.Log(ctx, e)
	}
	bad := func(msg string) {
		rec(r.Context(), c.Provider, "deny", "bad_request", map[string]any{"message": msg}, nil)
		writeError(w, http.StatusBadRequest, "bad_request", msg)
	}
	if !providerIDRe.MatchString(c.Provider) {
		c.Provider = ""
		bad("invalid provider")
		return
	}
	if pattern == routeProfile {
		n, err := strconv.ParseInt(params["id"], 10, 32)
		if err != nil || n <= 0 {
			bad("invalid zone profile id")
			return
		}
		c.ID = n
	}
	if c.Op == profileCreate || c.Op == profileUpdate || c.Op == profileCheck {
		var p eurodnsprov.ZoneProfile
		if !decodeBody(w, r, &p) {
			rec(r.Context(), c.Provider, "deny", "bad_request", map[string]any{"message": "invalid body"}, nil)
			return
		}
		c.Profile = &p
	}
	out, err := s.runProfile(r.Context(), subj, c, rec)
	if err != nil {
		s.writeProfileError(w, r, err)
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
