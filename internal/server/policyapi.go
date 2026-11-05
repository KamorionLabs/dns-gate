package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/discovery"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// OwnershipLister counts owned RRsets for the impact analysis.
type OwnershipLister interface {
	List(ctx context.Context, zone string) ([]store.Ownership, error)
}

var revisionIDRe = regexp.MustCompile(`^[a-z0-9-]{8,64}$`)

type policyError struct {
	status int
	reason string
	msg    string
	errs   []uiapi.ValidationError
}

func perr(status int, reason, msg string) *policyError {
	return &policyError{status: status, reason: reason, msg: msg}
}

func (s *Server) writePolicyError(w http.ResponseWriter, e *policyError) {
	writeJSON(w, e.status, errorBody{Reason: e.reason, Message: e.msg, Errors: e.errs})
}

// handlePolicyAPI serves /api/v1/policy (see internal/uiapi/policy.go).
func (s *Server) handlePolicyAPI(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, rest string) {
	if s.cfg.Policy == nil || s.cfg.PolicyStore == nil {
		writeError(w, http.StatusNotFound, "not_found", "policy storage not configured")
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if rest == "" {
		parts = nil
	}
	get, post := r.Method == http.MethodGet, r.Method == http.MethodPost
	var e *policyError
	switch {
	case len(parts) >= 1 && parts[0] == "delegated":
		e = s.handleDelegated(w, r, subj, sess, parts)
	case len(parts) == 0 && get:
		e = s.policyEffective(w, r, subj)
	case len(parts) == 1 && parts[0] == "revisions" && get:
		e = s.policyList(w, r, subj)
	case len(parts) == 1 && parts[0] == "revisions" && post:
		e = s.policyPropose(w, r, subj, sess)
	case len(parts) == 2 && parts[0] == "revisions" && get:
		e = s.policyDetail(w, r, subj, parts[1])
	case len(parts) == 3 && parts[0] == "revisions" && parts[2] == "export" && get:
		e = s.policyExport(w, r, subj, parts[1])
	case len(parts) == 3 && parts[0] == "revisions" && post:
		switch parts[2] {
		case "approve", "reject":
			e = s.policyDecide(w, r, subj, sess, parts[1], parts[2])
		case "activate":
			e = s.policyActivate(w, r, subj, sess, parts[1])
		case "rollback":
			e = s.policyRollback(w, r, subj, sess, parts[1])
		default:
			e = perr(http.StatusNotFound, "not_found", "unknown policy endpoint")
		}
	case len(parts) == 1 && parts[0] == "explain" && post:
		e = s.policyExplain(w, r, subj)
	case len(parts) == 1 && parts[0] == "who-can" && get:
		e = s.policyWhoCan(w, r, subj)
	case len(parts) == 2 && parts[0] == "virtual-keys" && parts[1] == "generate" && post:
		e = s.policyGenerateKey(w, r, subj, sess)
	default:
		e = perr(http.StatusNotFound, "not_found", "unknown policy endpoint")
	}
	if e != nil {
		s.writePolicyError(w, e)
	}
}

func (s *Server) requireMeta(subj *identity.Subject, action string) *policyError {
	if !s.pol.AllowMeta(subj, action) {
		return perr(http.StatusForbidden, "forbidden", action+" not granted")
	}
	return nil
}

// stepUp requires a recent authentication (and the configured AMR values)
// from humans before a policy mutation. Pipelines are not concerned.
func (s *Server) stepUp(subj *identity.Subject, sess *session) *policyError {
	if subj.Category != identity.CategoryHuman {
		return nil
	}
	var authTime int64
	var amr []string
	if sess != nil {
		authTime, amr = sess.AuthTime, sess.AMR
	} else {
		if v, ok := subj.Claims["auth_time"].(float64); ok {
			authTime = int64(v)
		}
		amr = policy.ClaimStrings(subj.Claims["amr"])
	}
	maxAge := s.cfg.Config.Policy.EditMaxAge.D()
	if authTime == 0 || s.now().Sub(time.Unix(authTime, 0)) > maxAge {
		return perr(http.StatusForbidden, "reauth_required", "a recent login is required for this action")
	}
	for _, want := range s.cfg.Config.Policy.RequireAMR {
		if !contains(amr, want) {
			return perr(http.StatusForbidden, "reauth_required", "authentication method "+want+" is required for this action")
		}
	}
	return nil
}

func (s *Server) activeID(ctx context.Context) (string, *policyError) {
	rev, err := s.cfg.PolicyStore.ActiveRevision(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		s.log.Error("policy store", "err", err)
		return "", perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	return rev.ID, nil
}

func (s *Server) loadRevision(ctx context.Context, id string) (*store.PolicyRevision, uiapi.PolicyDocument, *policyError) {
	if !revisionIDRe.MatchString(id) {
		return nil, uiapi.PolicyDocument{}, perr(http.StatusBadRequest, "bad_request", "invalid revision id")
	}
	rev, err := s.cfg.PolicyStore.GetRevision(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, uiapi.PolicyDocument{}, perr(http.StatusNotFound, "not_found", "unknown revision")
	}
	if err != nil {
		return nil, uiapi.PolicyDocument{}, perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	doc, err := policy.DecodeDocument(rev.Document)
	if err != nil {
		return nil, uiapi.PolicyDocument{}, perr(http.StatusInternalServerError, "internal", "stored revision is unreadable")
	}
	return rev, doc, nil
}

func actor(subject, name, category string) uiapi.Actor {
	return uiapi.Actor{Subject: subject, Name: name, Category: category}
}

func summary(rev *store.PolicyRevision) uiapi.RevisionSummary {
	out := uiapi.RevisionSummary{
		ID: rev.ID, ParentID: rev.ParentID, Status: rev.Status,
		Author: actor(rev.Author, rev.AuthorName, rev.AuthorCat), CreatedAt: rev.CreatedAt, Comment: rev.Comment,
		ActivatedAt: rev.ActivatedAt,
	}
	for _, a := range rev.Approvals {
		out.Approvals = append(out.Approvals, uiapi.Approval{By: actor(a.By, a.ByName, a.ByCategory), At: a.At, Decision: a.Decision, Comment: a.Comment})
	}
	if rev.ActivatedBy != "" {
		a := actor(rev.ActivatedBy, "", "")
		out.ActivatedBy = &a
	}
	return out
}

func (s *Server) settings() uiapi.PolicySettings {
	p := s.cfg.Config.Policy
	return uiapi.PolicySettings{Editable: p.Editable, RequireApproval: *p.RequireApproval, EditMaxAge: p.EditMaxAge.D().String(), RequireAMR: p.RequireAMR}
}

func (s *Server) baseLayer() uiapi.BaseLayer {
	c := s.cfg.Config
	b := uiapi.BaseLayer{
		ConfigHash: c.Hash, LoadedAt: c.LoadedAt, Zones: c.Zones,
		Bounds:   uiapi.Bounds{Zones: nonNil(c.Policy.Bounds.Zones), Actions: nonNil(c.Policy.Bounds.Actions)},
		Document: s.cfg.Policy.Base(), Issuers: []uiapi.Issuer{}, Protected: []uiapi.Protected{},
	}
	if len(c.Policy.Delegations) > 0 {
		b.Delegations = policy.DelegationViews(c)
	}
	for _, is := range c.AllIssuers() {
		if is.Self {
			continue
		}
		ui := uiapi.Issuer{Name: is.Name, Issuer: is.Issuer, Audiences: is.Audiences, SubjectClaim: is.SubjectClaim, Category: is.Category, CategoryClaim: is.CategoryClaim}
		if is.SubjectTemplate != "" {
			ui.SubjectClaim = is.SubjectTemplate
		}
		if len(is.BoundClaims) > 0 {
			ui.BoundClaims = map[string][]string{}
			for k, v := range is.BoundClaims {
				ui.BoundClaims[k] = []string(v)
			}
		}
		b.Issuers = append(b.Issuers, ui)
	}
	for _, p := range c.Protected {
		b.Protected = append(b.Protected, uiapi.Protected{Zones: p.Zones, Hosts: p.Hosts, Types: p.Types})
	}
	if c.ZonesDiscovery.Enabled {
		zd := &uiapi.ZonesDiscovery{
			Enabled: true, Include: nonNil(c.ZonesDiscovery.Include), Exclude: nonNil(c.ZonesDiscovery.Exclude),
			Refresh: c.ZonesDiscovery.Refresh.D().String(),
		}
		if s.cfg.Discovery != nil {
			st := s.cfg.Discovery.Status()
			zd.Loaded, zd.Count = st.Loaded, st.Count
			if !st.LastRefreshAt.IsZero() {
				t := st.LastRefreshAt
				zd.LastRefreshAt = &t
			}
			if st.Err != nil {
				zd.Error = "the last listing of the EuroDNS account failed"
			}
		}
		b.Discovery = zd
	}
	return b
}

func (s *Server) rights(subj *identity.Subject) uiapi.MyPolicyRights {
	return uiapi.MyPolicyRights{
		CanPropose: s.cfg.Config.Policy.Editable && s.pol.AllowMeta(subj, uiapi.ActionPolicyPropose),
		CanApprove: s.cfg.Config.Policy.Editable && s.pol.AllowMeta(subj, uiapi.ActionPolicyApprove),
	}
}

func (s *Server) policyEffective(w http.ResponseWriter, r *http.Request, subj *identity.Subject) *policyError {
	if e := s.requireMeta(subj, uiapi.ActionPolicyRead); e != nil {
		return e
	}
	out := uiapi.EffectivePolicy{Settings: s.settings(), Base: s.baseLayer(), Me: s.rights(subj)}
	rev, err := s.cfg.PolicyStore.ActiveRevision(r.Context())
	switch {
	case err == nil:
		doc, derr := policy.DecodeDocument(rev.Document)
		if derr != nil {
			return perr(http.StatusInternalServerError, "internal", "active revision is unreadable")
		}
		sum := summary(rev)
		out.Active, out.Managed = &sum, &doc
	case !errors.Is(err, store.ErrNotFound):
		return perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) policyList(w http.ResponseWriter, r *http.Request, subj *identity.Subject) *policyError {
	if e := s.requireMeta(subj, uiapi.ActionPolicyRead); e != nil {
		return e
	}
	q := r.URL.Query()
	status := q.Get("status")
	switch status {
	case "", uiapi.RevisionProposed, uiapi.RevisionApproved, uiapi.RevisionRejected, uiapi.RevisionActive, uiapi.RevisionSuperseded:
	default:
		return perr(http.StatusBadRequest, "bad_request", "invalid status")
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return perr(http.StatusBadRequest, "bad_request", "limit must be between 1 and 200")
		}
		limit = n
	}
	revs, next, err := s.cfg.PolicyStore.ListRevisions(r.Context(), status, limit, q.Get("cursor"))
	if err != nil {
		return perr(http.StatusBadRequest, "bad_request", "invalid revision query")
	}
	page := uiapi.RevisionPage{Revisions: []uiapi.RevisionSummary{}, NextCursor: next}
	for i := range revs {
		page.Revisions = append(page.Revisions, summary(&revs[i]))
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// detail builds the revision view: diff and impact against its parent.
func (s *Server) detail(ctx context.Context, rev *store.PolicyRevision, doc uiapi.PolicyDocument) (*uiapi.RevisionDetail, *policyError) {
	var parentDoc *uiapi.PolicyDocument
	parentName := "(none)"
	if rev.ParentID != "" {
		_, pd, e := s.loadRevision(ctx, rev.ParentID)
		if e != nil && e.status != http.StatusNotFound {
			return nil, e
		}
		if e == nil {
			parentDoc, parentName = &pd, "revision "+rev.ParentID
		}
	}
	empty := uiapi.PolicyDocument{}
	from := empty
	if parentDoc != nil {
		from = *parentDoc
	}
	a, err := policy.DocumentYAML(from)
	if err != nil {
		return nil, perr(http.StatusInternalServerError, "internal", "cannot render the parent revision")
	}
	b, err := policy.DocumentYAML(doc)
	if err != nil {
		return nil, perr(http.StatusInternalServerError, "internal", "cannot render the revision")
	}
	activeID, e := s.activeID(ctx)
	if e != nil {
		return nil, e
	}
	h := s.cfg.Policy
	out := &uiapi.RevisionDetail{
		RevisionSummary: summary(rev),
		Document:        doc,
		DiffYAML:        policy.UnifiedDiff(a, b, parentName, "revision "+rev.ID),
		Impact:          policy.Impact(h.CompileUnchecked(parentDoc, rev.ParentID), h.CompileUnchecked(&doc, rev.ID), s.ownedCounter(ctx)),
		Stale:           (rev.Status == uiapi.RevisionProposed || rev.Status == uiapi.RevisionApproved) && rev.ParentID != activeID,
	}
	return out, nil
}

func (s *Server) ownedCounter(ctx context.Context) policy.OwnedCounter {
	if s.cfg.Ownership == nil {
		return nil
	}
	cache := map[string]map[string]int{}
	return func(team, zone string) int {
		counts, ok := cache[zone]
		if !ok {
			counts = map[string]int{}
			if list, err := s.cfg.Ownership.List(ctx, zone); err == nil {
				for _, o := range list {
					if o.State != store.StatePending {
						counts[o.Owner]++
						counts["\x00all"]++
					}
				}
			}
			cache[zone] = counts
		}
		if team == "" {
			return counts["\x00all"]
		}
		return counts[team]
	}
}

func (s *Server) policyDetail(w http.ResponseWriter, r *http.Request, subj *identity.Subject, id string) *policyError {
	if e := s.requireMeta(subj, uiapi.ActionPolicyRead); e != nil {
		return e
	}
	rev, doc, e := s.loadRevision(r.Context(), id)
	if e != nil {
		return e
	}
	d, e := s.detail(r.Context(), rev, doc)
	if e != nil {
		return e
	}
	writeJSON(w, http.StatusOK, d)
	return nil
}

func (s *Server) policyExport(w http.ResponseWriter, r *http.Request, subj *identity.Subject, id string) *policyError {
	if e := s.requireMeta(subj, uiapi.ActionPolicyRead); e != nil {
		return e
	}
	_, doc, e := s.loadRevision(r.Context(), id)
	if e != nil {
		return e
	}
	y, err := policy.DocumentYAML(doc)
	if err != nil {
		return perr(http.StatusInternalServerError, "internal", "cannot render the revision")
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="policy-%s.yaml"`, id))
	_, _ = w.Write([]byte(y))
	return nil
}

func decodeStrict(r *http.Request, v any) *policyError {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return perr(http.StatusUnsupportedMediaType, "bad_request", "application/json expected")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return perr(http.StatusRequestEntityTooLarge, "too_large", "request body too large")
		}
		return perr(http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
	}
	if dec.More() {
		return perr(http.StatusBadRequest, "bad_request", "trailing data after JSON body")
	}
	return nil
}

// mutation checks common to every policy write.
func (s *Server) mutation(subj *identity.Subject, sess *session, action string) *policyError {
	if !s.cfg.Config.Policy.Editable {
		return perr(http.StatusForbidden, "policy_not_editable", "the managed policy is disabled")
	}
	if e := s.requireMeta(subj, action); e != nil {
		return e
	}
	return s.stepUp(subj, sess)
}

// validateZonesExist checks that the zones a document adds exist in the
// EuroDNS account. A zone not seen yet triggers one more listing when the
// last one is older than discovery.MinOnDemand (a domain added just before).
func (s *Server) validateZonesExist(ctx context.Context, doc uiapi.PolicyDocument) []uiapi.ValidationError {
	cur := s.cfg.Policy.Current()
	if s.cfg.Discovery == nil {
		return policy.ValidateZonesDiscovered(doc, cur, nil, false)
	}
	d := s.cfg.Discovery
	errs := policy.ValidateZonesDiscovered(doc, cur, d, d.Loaded())
	if len(errs) > 0 {
		if err := d.RefreshIfOlder(ctx, discovery.MinOnDemand); err != nil {
			s.log.Warn("zone discovery refresh", "err", err)
		}
		errs = policy.ValidateZonesDiscovered(doc, cur, d, d.Loaded())
	}
	return errs
}

func newRevisionID(now time.Time) string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%013d-%s", now.UnixMilli(), hex.EncodeToString(b[:]))
}

func (s *Server) createRevision(ctx context.Context, subj *identity.Subject, parentID, comment string, doc uiapi.PolicyDocument) (*store.PolicyRevision, *policyError) {
	policy.Normalize(&doc)
	errs := policy.ValidateManaged(s.cfg.Config, s.cfg.Policy.Base(), doc)
	if len(errs) == 0 {
		errs = s.validateZonesExist(ctx, doc)
	}
	if len(errs) > 0 {
		return nil, &policyError{status: http.StatusBadRequest, reason: "invalid_policy", msg: "the policy document is invalid", errs: errs}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, perr(http.StatusInternalServerError, "internal", "cannot encode the document")
	}
	if len(comment) > 2000 {
		return nil, perr(http.StatusBadRequest, "bad_request", "comment too long")
	}
	rev := store.PolicyRevision{
		ID: newRevisionID(s.now()), ParentID: parentID, Document: raw,
		Author: subj.String(), AuthorName: subj.Name, AuthorCat: subj.Category,
		CreatedAt: s.now().UTC(), Comment: comment, Status: uiapi.RevisionProposed,
	}
	if err := s.cfg.PolicyStore.CreateRevision(ctx, rev); err != nil {
		s.log.Error("policy create revision", "err", err)
		return nil, perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	return &rev, nil
}

func (s *Server) policyPropose(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session) *policyError {
	if e := s.mutation(subj, sess, uiapi.ActionPolicyPropose); e != nil {
		return e
	}
	var req uiapi.ProposeRequest
	if e := decodeStrict(r, &req); e != nil {
		return e
	}
	active, activeDoc, e := s.activeDoc(r.Context())
	if e != nil {
		return e
	}
	activeID := revID(active)
	if req.ParentID != activeID {
		return perr(http.StatusConflict, "stale_revision", "the policy changed since the edit started: reload and reapply")
	}
	if e := s.carryDelegated(subj, &req.Document, activeDoc, req.TakeOver); e != nil {
		s.policyAudit(r, subj, "policy.propose", "", "deny", e.reason, map[string]any{"take_over": req.TakeOver})
		return e
	}
	rev, e := s.createRevision(r.Context(), subj, activeID, req.Comment, req.Document)
	if e != nil {
		if e.reason == "invalid_policy" {
			s.policyAudit(r, subj, "policy.propose", "", "deny", "invalid_policy", nil)
		}
		return e
	}
	var extra map[string]any
	if len(req.TakeOver) > 0 {
		extra = map[string]any{"take_over": req.TakeOver}
		s.policyAudit(r, subj, "policy.delegated.take_over", rev.ID, "allow", "", extra)
	}
	s.policyAudit(r, subj, "policy.propose", rev.ID, "allow", "", extra)
	d, e := s.detail(r.Context(), rev, req.Document)
	if e != nil {
		return e
	}
	writeJSON(w, http.StatusCreated, d)
	return nil
}

func (s *Server) policyRollback(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, id string) *policyError {
	if e := s.mutation(subj, sess, uiapi.ActionPolicyPropose); e != nil {
		return e
	}
	var req uiapi.DecisionRequest
	if r.ContentLength != 0 {
		if e := decodeStrict(r, &req); e != nil {
			return e
		}
	}
	src, doc, e := s.loadRevision(r.Context(), id)
	if e != nil {
		return e
	}
	active, activeDoc, e := s.activeDoc(r.Context())
	if e != nil {
		return e
	}
	activeID := revID(active)
	// A rollback restores the objects edited by humans; delegated objects
	// stay as they are in the active revision.
	doc.Delegated = activeDoc.Delegated
	comment := strings.TrimSpace("rollback to " + src.ID + ". " + req.Comment)
	rev, e := s.createRevision(r.Context(), subj, activeID, comment, doc)
	if e != nil {
		return e
	}
	s.policyAudit(r, subj, "policy.propose", rev.ID, "allow", "", map[string]any{"rollback_of": src.ID})
	d, e := s.detail(r.Context(), rev, doc)
	if e != nil {
		return e
	}
	writeJSON(w, http.StatusCreated, d)
	return nil
}

func (s *Server) policyDecide(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, id, decision string) *policyError {
	var req uiapi.DecisionRequest
	if r.ContentLength != 0 {
		if e := decodeStrict(r, &req); e != nil {
			return e
		}
	}
	rev, doc, e := s.loadRevision(r.Context(), id)
	if e != nil {
		return e
	}
	isAuthor := rev.Author == subj.String()
	action := uiapi.ActionPolicyApprove
	if decision == "reject" && isAuthor {
		action = uiapi.ActionPolicyPropose // authors may withdraw their own proposal
	}
	if e := s.mutation(subj, sess, action); e != nil {
		return e
	}
	if rev.Status != uiapi.RevisionProposed && rev.Status != uiapi.RevisionApproved {
		return perr(http.StatusConflict, "invalid_status", "revision is "+rev.Status)
	}
	if decision == "approve" {
		if isAuthor {
			s.policyAudit(r, subj, "policy.approve", rev.ID, "deny", "self_approval", nil)
			return perr(http.StatusForbidden, "self_approval", "the author of a revision cannot approve it")
		}
		for _, a := range rev.Approvals {
			if a.By == subj.String() {
				return perr(http.StatusConflict, "already_decided", "you already decided on this revision")
			}
		}
		activeID, e := s.activeID(r.Context())
		if e != nil {
			return e
		}
		if rev.ParentID != activeID {
			return perr(http.StatusConflict, "stale_revision", "the policy changed since this revision was proposed")
		}
	}
	if len(req.Comment) > 2000 {
		return perr(http.StatusBadRequest, "bad_request", "comment too long")
	}
	rev.Approvals = append(rev.Approvals, store.PolicyApproval{
		By: subj.String(), ByName: subj.Name, ByCategory: subj.Category, At: s.now().UTC(), Decision: decision, Comment: req.Comment,
	})
	if decision == "approve" {
		rev.Status = uiapi.RevisionApproved
	} else {
		rev.Status = uiapi.RevisionRejected
	}
	if err := s.cfg.PolicyStore.UpdateRevision(r.Context(), *rev); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return perr(http.StatusConflict, "conflict", "the revision changed concurrently: reload")
		}
		return perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	rev.Version++
	s.policyAudit(r, subj, "policy."+decision, rev.ID, "allow", "", nil)
	d, e := s.detail(r.Context(), rev, doc)
	if e != nil {
		return e
	}
	writeJSON(w, http.StatusOK, d)
	return nil
}

func (s *Server) policyActivate(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, id string) *policyError {
	required := *s.cfg.Config.Policy.RequireApproval
	action := uiapi.ActionPolicyPropose
	if required {
		action = uiapi.ActionPolicyApprove
	}
	if e := s.mutation(subj, sess, action); e != nil {
		return e
	}
	rev, doc, e := s.loadRevision(r.Context(), id)
	if e != nil {
		return e
	}
	switch {
	case required && rev.Status != uiapi.RevisionApproved:
		return perr(http.StatusConflict, "approval_required", "the revision must be approved by another approver first")
	case !required && rev.Status != uiapi.RevisionProposed && rev.Status != uiapi.RevisionApproved:
		return perr(http.StatusConflict, "invalid_status", "revision is "+rev.Status)
	}
	if required {
		approved := false
		for _, a := range rev.Approvals {
			if a.Decision == "approve" && a.By != rev.Author {
				approved = true
			}
		}
		if !approved {
			return perr(http.StatusConflict, "approval_required", "the revision must be approved by another approver first")
		}
	}
	activeID, e := s.activeID(r.Context())
	if e != nil {
		return e
	}
	if rev.ParentID != activeID {
		return perr(http.StatusConflict, "stale_revision", "the policy changed since this revision was proposed")
	}
	errs := policy.ValidateManaged(s.cfg.Config, s.cfg.Policy.Base(), doc)
	if len(errs) == 0 {
		errs = s.validateZonesExist(r.Context(), doc)
	}
	if len(errs) > 0 {
		return &policyError{status: http.StatusBadRequest, reason: "invalid_policy", msg: "the revision no longer validates against the base policy", errs: errs}
	}
	if err := s.cfg.PolicyStore.Activate(r.Context(), rev.ID, activeID, subj.String(), s.now().UTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.policyAudit(r, subj, "policy.activate", rev.ID, "deny", "conflict", nil)
			return perr(http.StatusConflict, "conflict", "another revision was activated concurrently")
		}
		return perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	if err := s.cfg.Policy.Refresh(r.Context(), s.cfg.PolicyStore); err != nil {
		s.log.Error("policy refresh after activation", "err", err)
	}
	s.policyAudit(r, subj, "policy.activate", rev.ID, "allow", "", map[string]any{"previous_revision_id": activeID})
	rev, doc, e = s.loadRevision(r.Context(), id)
	if e != nil {
		return e
	}
	d, e := s.detail(r.Context(), rev, doc)
	if e != nil {
		return e
	}
	writeJSON(w, http.StatusOK, d)
	return nil
}

// snapshotFor returns the active snapshot or the one of a revision.
func (s *Server) snapshotFor(ctx context.Context, revisionID string) (*policy.Snapshot, *policyError) {
	if revisionID == "" {
		return s.cfg.Policy.Current(), nil
	}
	_, doc, e := s.loadRevision(ctx, revisionID)
	if e != nil {
		return nil, e
	}
	return s.cfg.Policy.CompileUnchecked(&doc, revisionID), nil
}

func (s *Server) policyExplain(w http.ResponseWriter, r *http.Request, subj *identity.Subject) *policyError {
	if e := s.requireMeta(subj, uiapi.ActionPolicyRead); e != nil {
		return e
	}
	var req uiapi.ExplainRequest
	if e := decodeStrict(r, &req); e != nil {
		return e
	}
	if req.Action == "" || (!policy.IsMeta(req.Action) && req.Zone == "") {
		return perr(http.StatusBadRequest, "bad_request", "action and zone are required")
	}
	snap, e := s.snapshotFor(r.Context(), req.RevisionID)
	if e != nil {
		return e
	}
	claims := map[string]any{}
	for k, v := range req.Subject.Claims {
		if len(v) == 1 {
			claims[k] = v[0]
			continue
		}
		arr := make([]any, len(v))
		for i, x := range v {
			arr[i] = x
		}
		claims[k] = arr
	}
	writeJSON(w, http.StatusOK, snap.Explain(req.Subject.Issuer, claims, req.Action, req.Zone, req.Host, req.Type))
	return nil
}

func (s *Server) policyWhoCan(w http.ResponseWriter, r *http.Request, subj *identity.Subject) *policyError {
	if e := s.requireMeta(subj, uiapi.ActionPolicyRead); e != nil {
		return e
	}
	q := r.URL.Query()
	for k := range q {
		switch k {
		case "zone", "host", "type", "action", "revision_id":
		default:
			return perr(http.StatusBadRequest, "bad_request", "unknown query parameter "+k)
		}
	}
	action := q.Get("action")
	if action == "" {
		action = policy.ActionRecordWrite
	}
	if q.Get("zone") == "" && !policy.IsMeta(action) {
		return perr(http.StatusBadRequest, "bad_request", "zone is required")
	}
	snap, e := s.snapshotFor(r.Context(), q.Get("revision_id"))
	if e != nil {
		return e
	}
	writeJSON(w, http.StatusOK, snap.WhoCan(action, q.Get("zone"), q.Get("host"), q.Get("type")))
	return nil
}

func (s *Server) policyGenerateKey(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session) *policyError {
	if e := s.mutation(subj, sess, uiapi.ActionPolicyPropose); e != nil {
		return e
	}
	var key [32]byte
	var app [6]byte
	_, _ = rand.Read(key[:])
	_, _ = rand.Read(app[:])
	k := base64.RawURLEncoding.EncodeToString(key[:])
	sum := sha256.Sum256([]byte(k))
	out := uiapi.GeneratedKey{AppID: "vk-" + hex.EncodeToString(app[:]), Key: k, KeySHA256: hex.EncodeToString(sum[:])}
	s.policyAudit(r, subj, "policy.generate_key", "", "allow", "", map[string]any{"app_id": out.AppID, "key_sha256": out.KeySHA256})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) policyAudit(r *http.Request, subj *identity.Subject, action, revisionID, decision, reason string, extra map[string]any) {
	e := audit.Event{
		Time: s.now().UTC(), RequestID: requestid.From(r.Context()),
		Subject: subj.String(), SubjectName: subj.Name, SubjectCategory: subj.Category, Teams: subj.Teams,
		Action: action, Decision: decision, Reason: reason, Extra: map[string]any{},
	}
	for k, v := range extra {
		e.Extra[k] = v
	}
	if revisionID != "" {
		e.Extra["revision_id"] = revisionID
	}
	s.cfg.Audit.Log(r.Context(), e)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
