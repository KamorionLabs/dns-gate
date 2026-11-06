package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// RRset REST API (see api/dns-gate.openapi.yaml and docs/API.md):
//
//	GET    /api/v1/zones/{zone}/rrsets/{host}/{type} -> uiapi.RRset, ETag "<hash>"   (ui.read or dns.read)
//	PUT    /api/v1/zones/{zone}/rrsets/{host}/{type} rrsetBody -> uiapi.RRset, ETag (engine RBAC)
//	DELETE /api/v1/zones/{zone}/rrsets/{host}/{type} -> 204                         (engine RBAC)
//	POST   /api/v1/zones/{zone}/plan  planRequest  -> uiapi.PlanResult with plan_id
//	POST   /api/v1/zones/{zone}/apply applyRequest -> uiapi.PlanResult
//
// GET reads the inventory cache of the engine (no provider call once the
// zone is cached). PUT honours If-None-Match: * (create only, MustNotExist)
// and If-Match: "<hash>" (ExpectedHash), DELETE If-Match; both are enforced
// by the engine under the zone lock against a fresh provider read, without
// any zone version check.

// FeatureRRsetAPI is advertised by GET /.well-known/dns-gate when the RRset
// REST API is served.
const FeatureRRsetAPI = "rrset-api"

// FeaturePlans is advertised when REST plan/apply is served.
const FeaturePlans = "plans"

const maxPlanChanges = 100

var (
	typeRe  = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}$`)
	labelRe = regexp.MustCompile(`^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)$`)

	errPlanUnknown = errors.New("unknown or already used plan_id: plan again")
	errPlanExpired = errors.New("plan expired: plan again")
	errPlanOwner   = errors.New("plan belongs to another caller")
)

type rrsetBody struct {
	TTL    int        `json:"ttl,omitempty"`
	Values []string   `json:"values,omitempty"`
	Alias  *dns.Alias `json:"alias,omitempty"`
}

type planRequest struct {
	Changes []uiapi.RRsetChange `json:"changes"`
	Team    string              `json:"team,omitempty"`
}

type applyRequest struct {
	PlanID string `json:"plan_id"`
	Team   string `json:"team,omitempty"`
}

// rrsetKey validates and normalizes the zone, host and type of a path.
func rrsetKey(zoneIn, hostIn, typeIn string) (string, dns.Key, string) {
	zone := dns.NormalizeZone(zoneIn)
	if !config.ValidFQDN(zone) {
		return "", dns.Key{}, "invalid zone"
	}
	host := dns.NormalizeHost(hostIn, zone)
	if host != dns.Apex {
		if len(host) > 253 {
			return "", dns.Key{}, "invalid host"
		}
		for i, l := range strings.Split(host, ".") {
			if !labelRe.MatchString(l) || (l == "*" && i != 0) {
				return "", dns.Key{}, "invalid host: relative to the zone, @ for the apex, * only as the first label"
			}
		}
	}
	typ := strings.ToUpper(strings.TrimSpace(typeIn))
	if !typeRe.MatchString(typ) {
		return "", dns.Key{}, "invalid type"
	}
	return zone, dns.Key{Host: host, Type: typ}, ""
}

// handleRRset serves /api/v1/zones/{zone}/rrsets/{host}/{type}.
func (s *Server) handleRRset(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, zoneIn, hostIn, typeIn string) {
	zone, key, msg := rrsetKey(zoneIn, hostIn, typeIn)
	if msg != "" {
		writeError(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	if r.Method == http.MethodGet {
		s.getRRset(w, r, subj, zone, key)
		return
	}
	if !s.pol.Managed(zone) {
		writeError(w, http.StatusNotFound, "not_found", "zone not managed by the gate")
		return
	}
	if s.cfg.Ops == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "RRset writes are not available")
		return
	}
	if key.IsForward() {
		writeError(w, http.StatusBadRequest, "invalid", "URL forwards are written at /api/v1/zones/{zone}/forwards/{host}")
		return
	}
	action := "api.rrset.put"
	if r.Method == http.MethodDelete {
		action = "api.rrset.delete"
	}
	if sess != nil {
		if e := s.stepUp(subj, sess); e != nil {
			s.apiAudit(r, subj, action, zone, "deny", e.reason, map[string]any{"host": key.Host, "type": key.Type})
			s.writePolicyError(w, e)
			return
		}
	}
	change := uiapi.RRsetChange{Host: key.Host, Type: key.Type}
	if msg := preconditions(r, &change); msg != "" {
		writeError(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	if r.Method == http.MethodDelete {
		change.Delete = true
	} else {
		var body rrsetBody
		if e := decodeStrict(r, &body); e != nil {
			if e.status == http.StatusBadRequest {
				e.reason = "invalid"
			}
			s.writePolicyError(w, e)
			return
		}
		switch {
		case body.Alias == nil && len(body.Values) == 0:
			writeError(w, http.StatusBadRequest, "invalid", "values or alias is required (DELETE removes an RRset)")
			return
		case body.Alias != nil && len(body.Values) > 0:
			writeError(w, http.StatusBadRequest, "invalid", "values and alias are mutually exclusive")
			return
		case body.TTL < 0:
			writeError(w, http.StatusBadRequest, "invalid", "ttl must be positive")
			return
		}
		change.TTL, change.Values, change.Alias = body.TTL, body.Values, body.Alias
	}
	if _, err := s.cfg.Ops.ApplyRRsets(r.Context(), subj, zone, []uiapi.RRsetChange{change}, 0); err != nil {
		s.apiError(w, r, action, zone, err)
		return
	}
	if change.Delete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rs := s.writtenRRset(r.Context(), subj, zone, key, change)
	setETag(w, rs.Hash)
	writeJSON(w, http.StatusOK, rs)
}

// preconditions maps If-Match and If-None-Match to the change.
func preconditions(r *http.Request, c *uiapi.RRsetChange) string {
	im, inm := strings.TrimSpace(r.Header.Get("If-Match")), strings.TrimSpace(r.Header.Get("If-None-Match"))
	switch {
	case im != "" && inm != "":
		return "If-Match and If-None-Match are mutually exclusive"
	case inm != "":
		if inm != "*" || r.Method != http.MethodPut {
			return `only If-None-Match: * is supported, on PUT`
		}
		c.MustNotExist = true
	case im != "":
		tag := normalizeETag(im)
		if tag == "" || tag == "*" || strings.Contains(tag, ",") {
			return `If-Match takes exactly one RRset hash, e.g. If-Match: "<hash>"`
		}
		c.ExpectedHash = tag
	}
	return ""
}

// writtenRRset returns the RRset after a write, from the engine cache, or
// as requested when the subject cannot read it.
func (s *Server) writtenRRset(ctx context.Context, subj *identity.Subject, zone string, key dns.Key, c uiapi.RRsetChange) uiapi.RRset {
	if rs, err := s.cfg.Engine.RRset(ctx, subj, zone, key); err == nil {
		return withHash(*rs)
	}
	rs := uiapi.RRset{Host: key.Host, Type: key.Type, TTL: c.TTL, Values: c.Values, Alias: c.Alias, Forward: c.Forward, Status: uiapi.StatusManaged}
	if rs.Values == nil {
		rs.Values = []string{}
	}
	rs.Hash = rrsetHash(rs)
	return rs
}

func (s *Server) getRRset(w http.ResponseWriter, r *http.Request, subj *identity.Subject, zone string, key dns.Key) {
	if !s.canRead(subj, zone) {
		writeError(w, http.StatusForbidden, "forbidden", "ui.read or dns.read not granted on "+zone)
		return
	}
	got, err := s.cfg.Engine.RRset(r.Context(), subj, zone, key)
	if err != nil {
		s.inventoryError(w, zone, err)
		return
	}
	rs := withHash(*got)
	setETag(w, rs.Hash)
	writeJSON(w, http.StatusOK, rs)
}

// canRead reports whether the subject may read a managed or discovered zone.
func (s *Server) canRead(subj *identity.Subject, zone string) bool {
	if !s.pol.Managed(zone) && !s.pol.IsUnmanaged(zone) {
		return false
	}
	return s.cfg.Authz.Allow(subj, policy.ActionUIRead, zone) || s.cfg.Authz.Allow(subj, policy.ActionDNSRead, zone)
}

func (s *Server) inventoryError(w http.ResponseWriter, zone string, err error) {
	if ze, ok := zonewrite.AsError(err); ok && (ze.Reason == zonewrite.ReasonForbidden || ze.Reason == zonewrite.ReasonNotFound) {
		status := http.StatusForbidden
		if ze.Reason == zonewrite.ReasonNotFound {
			status = http.StatusNotFound
		}
		writeError(w, status, string(ze.Reason), ze.Message)
		return
	}
	s.log.Error("inventory", "zone", zone, "err", err)
	writeError(w, http.StatusBadGateway, "upstream", "inventory unavailable")
}

// withHash fills the values and content hash the engine may leave empty.
func withHash(rs uiapi.RRset) uiapi.RRset {
	if rs.Values == nil {
		rs.Values = []string{}
	}
	if rs.Hash == "" {
		rs.Hash = rrsetHash(rs)
	}
	return rs
}

func rrsetHash(rs uiapi.RRset) string {
	return dns.ContentHash(dns.RRset{Key: dns.Key{Host: rs.Host, Type: rs.Type}, TTL: rs.TTL, Values: rs.Values, Alias: rs.Alias, Forward: rs.Forward})
}

// fillHashes sets the content hash the engine left empty.
func fillHashes(sets []uiapi.RRset) {
	for i := range sets {
		if sets[i].Hash == "" {
			sets[i].Hash = rrsetHash(sets[i])
		}
	}
}

func zoneETag(v int64) string { return `"v` + strconv.FormatInt(v, 10) + `"` }

// handlePlan serves POST /api/v1/zones/{zone}/plan: a dry run whose
// allowed result is persisted as a single-use plan of the subject.
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request, subj *identity.Subject, zoneIn string) {
	zone := dns.NormalizeZone(zoneIn)
	if !config.ValidFQDN(zone) || !s.pol.Managed(zone) {
		writeError(w, http.StatusNotFound, "not_found", "zone not managed by the gate")
		return
	}
	if s.cfg.Ops == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "plans are not available")
		return
	}
	var req planRequest
	if e := decodeStrict(r, &req); e != nil {
		if e.status == http.StatusBadRequest {
			e.reason = "invalid"
		}
		s.writePolicyError(w, e)
		return
	}
	if len(req.Changes) == 0 || len(req.Changes) > maxPlanChanges {
		writeError(w, http.StatusBadRequest, "invalid", "between 1 and 100 changes are required")
		return
	}
	subj, e := forTeam(subj, req.Team)
	if e != nil {
		s.writePolicyError(w, e)
		return
	}
	team := selectedTeam(r, req.Team)
	plan, err := s.cfg.Ops.PlanRRsets(r.Context(), subj, zone, req.Changes)
	if err != nil {
		s.apiError(w, r, "api.plan", zone, err)
		return
	}
	plan.Team = team
	if plan.Allowed {
		if plan.PlanID, err = s.savePlan(r.Context(), subj, zone, team, req.Changes, plan.ZoneVersion); err != nil {
			s.log.Error("save plan", "zone", zone, "err", err)
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "plan storage unavailable")
			return
		}
	}
	if plan.Changes == nil {
		plan.Changes = []uiapi.Change{}
	}
	s.apiAudit(r, subj, "api.plan", zone, "allow", plan.Reason, map[string]any{"plan_id": plan.PlanID, "allowed": plan.Allowed})
	writeJSON(w, http.StatusOK, plan)
}

// handleApply serves POST /api/v1/zones/{zone}/apply.
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, zoneIn string) {
	zone := dns.NormalizeZone(zoneIn)
	if !config.ValidFQDN(zone) || !s.pol.Managed(zone) {
		writeError(w, http.StatusNotFound, "not_found", "zone not managed by the gate")
		return
	}
	if s.cfg.Ops == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "plans are not available")
		return
	}
	var req applyRequest
	if e := decodeStrict(r, &req); e != nil {
		if e.status == http.StatusBadRequest {
			e.reason = "invalid"
		}
		s.writePolicyError(w, e)
		return
	}
	if req.PlanID == "" {
		writeError(w, http.StatusBadRequest, "invalid", "plan_id is required")
		return
	}
	extra := map[string]any{"plan_id": req.PlanID}
	if sess != nil {
		if e := s.stepUp(subj, sess); e != nil {
			s.apiAudit(r, subj, "api.apply", zone, "deny", e.reason, extra)
			s.writePolicyError(w, e)
			return
		}
	}
	p, err := s.takePlan(r.Context(), req.PlanID, subj)
	if err == nil && p.Zone != zone {
		err = errPlanUnknown
	}
	if err != nil {
		status, reason := planErrorStatus(err)
		s.apiAudit(r, subj, "api.apply", zone, "deny", reason, extra)
		writeError(w, status, reason, err.Error())
		return
	}
	team := p.Team
	if want := selectedTeam(r, req.Team); want != "" && team != "" && want != team {
		s.apiAudit(r, subj, "api.apply", zone, "deny", "team_mismatch", extra)
		writeError(w, http.StatusBadRequest, "team_mismatch", "the plan was made for team "+team+", not "+want)
		return
	} else if team == "" {
		team = want
	}
	subj, e := forTeam(subj, team)
	if e != nil {
		s.writePolicyError(w, e)
		return
	}
	res, err := s.cfg.Ops.ApplyRRsets(r.Context(), subj, p.Zone, p.Changes, p.ZoneVersion)
	if err != nil {
		s.apiAudit(r, subj, "api.apply", zone, "error", reasonOf(err), extra)
		s.apiError(w, r, "api.apply", zone, err)
		return
	}
	s.apiAudit(r, subj, "api.apply", zone, "allow", "", extra)
	withNewHashes(res)
	res.PlanID, res.Team = req.PlanID, team
	if res.Changes == nil {
		res.Changes = []uiapi.Change{}
	}
	writeJSON(w, http.StatusOK, res)
}

// Reasons of a refused apply: the plan is unknown, already applied or made
// for another zone (404), or expired (410). Both mean planning again.
const (
	reasonPlanNotFound = "plan_not_found"
	reasonPlanExpired  = "plan_expired"
)

func planErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errPlanOwner):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, errPlanExpired):
		return http.StatusGone, reasonPlanExpired
	case errors.Is(err, errPlanUnknown):
		return http.StatusNotFound, reasonPlanNotFound
	default:
		return http.StatusServiceUnavailable, "store_unavailable"
	}
}

func (s *Server) planTTL() time.Duration {
	if d := s.cfg.Config.MCP.PlanTTL.D(); d > 0 {
		return d
	}
	return 10 * time.Minute
}

// savePlan persists a plan of subj and returns its id.
func (s *Server) savePlan(ctx context.Context, subj *identity.Subject, zone, team string, changes []uiapi.RRsetChange, version int64) (string, error) {
	var b [16]byte
	_, _ = rand.Read(b[:])
	now := s.now().UTC()
	p := store.Plan{
		ID: "plan-" + hex.EncodeToString(b[:]), Subject: subj.String(), Zone: zone, Team: team,
		Changes: changes, ZoneVersion: version, CreatedAt: now, ExpiresAt: now.Add(s.planTTL()),
	}
	if err := s.cfg.Plans.PutPlan(ctx, p); err != nil {
		return "", err
	}
	return p.ID, nil
}

// takePlan consumes a plan of subj; errors are errPlan* or a storage error.
func (s *Server) takePlan(ctx context.Context, id string, subj *identity.Subject) (*store.Plan, error) {
	p, err := s.cfg.Plans.TakePlan(ctx, id, subj.String(), s.now())
	switch {
	case err == nil:
		return p, nil
	case errors.Is(err, store.ErrNotFound):
		return nil, errPlanUnknown
	case errors.Is(err, store.ErrPlanOwner):
		return nil, errPlanOwner
	case errors.Is(err, store.ErrPlanExpired):
		return nil, errPlanExpired
	}
	s.log.Error("take plan", "err", err)
	return nil, errors.New("plan storage unavailable")
}

// selectedTeam is the team a request names: the team field of its body,
// else the X-DNS-Gate-Team header.
func selectedTeam(r *http.Request, field string) string {
	if field != "" {
		return field
	}
	return strings.TrimSpace(r.Header.Get(TeamHeader))
}

// apiError maps engine errors of the REST API to HTTP: 423 when the zone
// is locked, "invalid" for 400.
func (s *Server) apiError(w http.ResponseWriter, r *http.Request, action, zone string, err error) {
	if ze, ok := zonewrite.AsError(err); ok {
		status, reason := apiStatus(w, err, ze)
		writeJSON(w, status, errorBody{Reason: reason, Message: ze.Message, Details: ze.Details})
		return
	}
	s.opsError(w, r, nil, action, zone, err)
}

// apiStatus is the status and reason of an engine error on the REST API.
func apiStatus(w http.ResponseWriter, err error, ze *zonewrite.Error) (int, string) {
	status, reason := reasonStatus(ze.Reason), string(ze.Reason)
	switch ze.Reason {
	case zonewrite.ReasonLocked:
		status = http.StatusLocked
		w.Header().Set("Retry-After", "5")
	case zonewrite.ReasonNotFound:
		status = http.StatusNotFound
	case zonewrite.ReasonInvalid:
		reason = "invalid"
		var ie *provider.InvalidError
		if errors.As(err, &ie) && ie.Code != "" {
			reason = ie.Code
		}
	}
	return status, reason
}

// apiAudit records a decision of the REST API itself (the engine audits the
// writes it performs).
func (s *Server) apiAudit(r *http.Request, subj *identity.Subject, action, zone, decision, reason string, extra map[string]any) {
	e := audit.Event{
		Time: s.now().UTC(), RequestID: requestid.From(r.Context()), Action: action, Zone: zone,
		Decision: decision, Reason: reason, Extra: map[string]any{"via": "api"},
		Subject: subj.String(), SubjectName: subj.Name, SubjectCategory: subj.Category, Teams: subj.Teams,
	}
	for k, v := range extra {
		e.Extra[k] = v
	}
	s.cfg.Audit.Log(r.Context(), e)
}
