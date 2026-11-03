package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-gate/internal/uiapi"
)

// FeaturePolicyDelegation is advertised by GET /.well-known/eurodns-gate
// when the delegation API (/api/v1/policy/delegated) is served.
const FeaturePolicyDelegation = "policy-delegation"

// maxDelegatedAttempts bounds the server-side retries of a delegated write
// when another revision is activated concurrently (another replica).
const maxDelegatedAttempts = 5

var delegatedNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

// handleDelegated serves /api/v1/policy/delegated (see internal/uiapi/policy.go).
func (s *Server) handleDelegated(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, parts []string) *policyError {
	if !s.cfg.Config.Policy.Editable {
		return perr(http.StatusForbidden, "policy_not_editable", "the managed policy is disabled")
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			return perr(http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		}
		return s.delegatedIndex(w, r, subj)
	}
	if len(parts) != 3 || (parts[1] != "roles" && parts[1] != "bindings") {
		return perr(http.StatusNotFound, "not_found", "unknown policy endpoint")
	}
	kind := uiapi.DelegatedKindRole
	if parts[1] == "bindings" {
		kind = uiapi.DelegatedKindBinding
	}
	name := parts[2]
	if !delegatedNameRe.MatchString(name) {
		return perr(http.StatusBadRequest, "bad_request", "the name must be a lowercase identifier")
	}
	switch r.Method {
	case http.MethodGet:
		return s.delegatedGet(w, r, subj, kind, name)
	case http.MethodPut:
		op := delegatedOp{kind: kind, name: name, ifMatch: r.Header.Get("If-Match"), ifNoneMatch: r.Header.Get("If-None-Match")}
		if kind == uiapi.DelegatedKindRole {
			op.role = &uiapi.DelegatedRoleRequest{}
			if e := decodeStrict(r, op.role); e != nil {
				return e
			}
			op.delegation, op.managedBy = op.role.Delegation, op.role.ManagedBy
		} else {
			op.binding = &uiapi.DelegatedBindingRequest{}
			if e := decodeStrict(r, op.binding); e != nil {
				return e
			}
			op.delegation, op.managedBy = op.binding.Delegation, op.binding.ManagedBy
		}
		return s.delegatedWrite(w, r, subj, sess, op)
	case http.MethodDelete:
		op := delegatedOp{kind: kind, name: name, del: true, ifMatch: r.Header.Get("If-Match"), delegation: r.URL.Query().Get("delegation")}
		return s.delegatedWrite(w, r, subj, sess, op)
	}
	return perr(http.StatusMethodNotAllowed, "method_not_allowed", "GET, PUT or DELETE")
}

// activeDoc returns the active revision (nil if none) and its document.
func (s *Server) activeDoc(ctx context.Context) (*store.PolicyRevision, uiapi.PolicyDocument, *policyError) {
	rev, err := s.cfg.PolicyStore.ActiveRevision(ctx)
	if errors.Is(err, store.ErrNotFound) {
		doc := uiapi.PolicyDocument{}
		policy.Normalize(&doc)
		return nil, doc, nil
	}
	if err != nil {
		s.log.Error("policy store", "err", err)
		return nil, uiapi.PolicyDocument{}, perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
	}
	doc, err := policy.DecodeDocument(rev.Document)
	if err != nil {
		return nil, uiapi.PolicyDocument{}, perr(http.StatusInternalServerError, "internal", "active revision is unreadable")
	}
	return rev, doc, nil
}

func revID(rev *store.PolicyRevision) string {
	if rev == nil {
		return ""
	}
	return rev.ID
}

// delegatedObject builds the API view of a delegated object.
func delegatedObject(doc uiapi.PolicyDocument, kind, name, revisionID string) (*uiapi.DelegatedObject, bool) {
	switch kind {
	case uiapi.DelegatedKindRole:
		dr, ok := doc.Delegated.Role(name)
		if !ok {
			return nil, false
		}
		role := dr.Role
		return &uiapi.DelegatedObject{Kind: kind, Name: name, Role: &role, Owner: dr.Owner, ETag: policy.ObjectETag(dr), RevisionID: revisionID}, true
	default:
		db, ok := doc.Delegated.Binding(name)
		if !ok {
			return nil, false
		}
		b := db.Binding
		return &uiapi.DelegatedObject{Kind: kind, Name: name, Binding: &b, Owner: db.Owner, ETag: policy.ObjectETag(db), RevisionID: revisionID}, true
	}
}

// canSeeDelegation: subjects of the delegation and policy.read holders.
func (s *Server) canSeeDelegation(subj *identity.Subject, delegation string) bool {
	return contains(subj.Delegations, delegation) || s.pol.AllowMeta(subj, uiapi.ActionPolicyRead)
}

func (s *Server) delegatedGet(w http.ResponseWriter, r *http.Request, subj *identity.Subject, kind, name string) *policyError {
	if len(subj.Delegations) == 0 && !s.pol.AllowMeta(subj, uiapi.ActionPolicyRead) {
		return perr(http.StatusForbidden, "forbidden", "no policy delegation for this identity")
	}
	rev, doc, e := s.activeDoc(r.Context())
	if e != nil {
		return e
	}
	obj, ok := delegatedObject(doc, kind, name, revID(rev))
	if !ok || !s.canSeeDelegation(subj, obj.Owner.Delegation) {
		return perr(http.StatusNotFound, "not_found", "no delegated "+kind+" "+name)
	}
	w.Header().Set("ETag", obj.ETag)
	writeJSON(w, http.StatusOK, obj)
	return nil
}

func (s *Server) delegatedIndex(w http.ResponseWriter, r *http.Request, subj *identity.Subject) *policyError {
	reader := s.pol.AllowMeta(subj, uiapi.ActionPolicyRead)
	if len(subj.Delegations) == 0 && !reader {
		return perr(http.StatusForbidden, "forbidden", "no policy delegation for this identity")
	}
	rev, doc, e := s.activeDoc(r.Context())
	if e != nil {
		return e
	}
	out := uiapi.DelegatedIndex{Delegations: []uiapi.Delegation{}, Objects: []uiapi.DelegatedObject{}, RevisionID: revID(rev)}
	for _, d := range policy.DelegationViews(s.cfg.Config) {
		if reader || contains(subj.Delegations, d.Name) {
			out.Delegations = append(out.Delegations, d)
		}
	}
	if doc.Delegated != nil {
		for _, kind := range []string{uiapi.DelegatedKindRole, uiapi.DelegatedKindBinding} {
			var names []string
			if kind == uiapi.DelegatedKindRole {
				for n := range doc.Delegated.Roles {
					names = append(names, n)
				}
			} else {
				for n := range doc.Delegated.Bindings {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			for _, n := range names {
				if obj, ok := delegatedObject(doc, kind, n, out.RevisionID); ok && s.canSeeDelegation(subj, obj.Owner.Delegation) {
					out.Objects = append(out.Objects, *obj)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

type delegatedOp struct {
	kind, name            string
	del                   bool
	role                  *uiapi.DelegatedRoleRequest
	binding               *uiapi.DelegatedBindingRequest
	delegation, managedBy string
	ifMatch, ifNoneMatch  string
}

func (op delegatedOp) action() string {
	verb := "put"
	if op.del {
		verb = "delete"
	}
	return "policy.delegated." + verb + "_" + op.kind
}

// etagMatches compares If-Match values (a list, weak or strong) with a tag.
func etagMatches(header, tag string) bool {
	for _, v := range strings.Split(header, ",") {
		v = strings.TrimSpace(v)
		if v == "*" {
			return true
		}
		if strings.TrimPrefix(v, "W/") == tag {
			return true
		}
	}
	return false
}

// chooseDelegation picks the delegation acting on an object: its owner for
// an existing object, else the requested one or the only one of the caller.
func chooseDelegation(subj *identity.Subject, owner, requested string) (string, *policyError) {
	if owner != "" {
		if requested != "" && requested != owner {
			return "", perr(http.StatusConflict, "not_owner", "the object belongs to delegation "+owner)
		}
		if !contains(subj.Delegations, owner) {
			return "", perr(http.StatusForbidden, "not_owner", "the object belongs to delegation "+owner+", which this identity cannot act for")
		}
		return owner, nil
	}
	switch {
	case requested != "":
		if !contains(subj.Delegations, requested) {
			return "", perr(http.StatusForbidden, "forbidden", "this identity cannot act for delegation "+requested)
		}
		return requested, nil
	case len(subj.Delegations) == 1:
		return subj.Delegations[0], nil
	default:
		return "", perr(http.StatusBadRequest, "delegation_required", "this identity matches several delegations ("+strings.Join(subj.Delegations, ", ")+"): set delegation")
	}
}

// applyDelegated applies op to doc (a private copy of the active document).
// It returns whether the document changed.
func (s *Server) applyDelegated(doc *uiapi.PolicyDocument, subj *identity.Subject, op delegatedOp, base uiapi.PolicyDocument) (string, bool, *policyError) {
	cur, exists := delegatedObject(*doc, op.kind, op.name, "")
	owner := ""
	if exists {
		owner = cur.Owner.Delegation
	}
	switch {
	case op.ifNoneMatch != "" && strings.TrimSpace(op.ifNoneMatch) == "*" && exists:
		return "", false, perr(http.StatusPreconditionFailed, "precondition", "delegated "+op.kind+" "+op.name+" already exists: import it")
	case op.ifNoneMatch != "" && strings.TrimSpace(op.ifNoneMatch) != "*":
		return "", false, perr(http.StatusBadRequest, "bad_request", "only If-None-Match: * is supported")
	case op.ifMatch != "" && !exists:
		return "", false, perr(http.StatusPreconditionFailed, "precondition", "delegated "+op.kind+" "+op.name+" does not exist")
	case op.ifMatch != "" && !etagMatches(op.ifMatch, cur.ETag):
		return "", false, perr(http.StatusPreconditionFailed, "precondition", "delegated "+op.kind+" "+op.name+" changed since it was read")
	case op.del && !exists:
		return "", false, perr(http.StatusNotFound, "not_found", "no delegated "+op.kind+" "+op.name)
	}
	dl, e := chooseDelegation(subj, owner, op.delegation)
	if e != nil {
		return "", false, e
	}
	if !exists && op.kind == uiapi.DelegatedKindRole {
		if _, ok := base.Roles[op.name]; ok {
			return dl, false, perr(http.StatusConflict, "name_taken", "role "+op.name+" is defined by the base policy")
		}
		if _, ok := doc.Roles[op.name]; ok {
			return dl, false, perr(http.StatusConflict, "name_taken", "role "+op.name+" is a managed role edited by humans (defined in the managed policy or taken over)")
		}
	}
	if doc.Delegated == nil {
		doc.Delegated = &uiapi.DelegatedObjects{}
	}
	if doc.Delegated.Roles == nil {
		doc.Delegated.Roles = map[string]uiapi.DelegatedRole{}
	}
	if doc.Delegated.Bindings == nil {
		doc.Delegated.Bindings = map[string]uiapi.DelegatedBinding{}
	}
	if op.del {
		if op.kind == uiapi.DelegatedKindRole {
			delete(doc.Delegated.Roles, op.name)
		} else {
			delete(doc.Delegated.Bindings, op.name)
		}
		return dl, true, nil
	}
	now := s.now().UTC()
	o := uiapi.DelegatedOwner{Delegation: dl, CreatedBy: subj.String(), CreatedAt: now}
	if exists {
		o = cur.Owner
	}
	if op.kind == uiapi.DelegatedKindRole {
		next := op.role.Role
		normalizeRole(&next)
		if exists && sameJSON(*cur.Role, next) && o.ManagedBy == op.managedBy {
			return dl, false, nil
		}
		o.UpdatedBy, o.UpdatedAt, o.ManagedBy = subj.String(), now, op.managedBy
		doc.Delegated.Roles[op.name] = uiapi.DelegatedRole{Role: next, Owner: o}
		return dl, true, nil
	}
	next := op.binding.Binding
	normalizeBinding(&next)
	if exists && sameJSON(*cur.Binding, next) && o.ManagedBy == op.managedBy {
		return dl, false, nil
	}
	o.UpdatedBy, o.UpdatedAt, o.ManagedBy = subj.String(), now, op.managedBy
	doc.Delegated.Bindings[op.name] = uiapi.DelegatedBinding{Binding: next, Owner: o}
	return dl, true, nil
}

func normalizeRole(r *uiapi.Role) {
	for i := range r.Rules {
		if sc := r.Rules[i].Records; sc != nil && len(sc.Hosts) == 0 && len(sc.Types) == 0 {
			r.Rules[i].Records = nil
		}
	}
}

func normalizeBinding(b *uiapi.Binding) {
	if len(b.Groups) == 0 {
		b.Groups = nil
	}
	if len(b.Subjects) == 0 {
		b.Subjects = nil
	}
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// cloneDoc deep-copies a document (snapshots share the active one).
func cloneDoc(d uiapi.PolicyDocument) (uiapi.PolicyDocument, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return uiapi.PolicyDocument{}, err
	}
	return policy.DecodeDocument(b)
}

// delegatedWrite applies a delegated change on the active revision and
// activates the result as a new revision, without approval. Writes are
// serialized in the replica; a concurrent activation by another replica is
// retried on the new active revision (the change and its preconditions are
// evaluated again), then answered 409 policy_busy.
func (s *Server) delegatedWrite(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, op delegatedOp) *policyError {
	ctx := r.Context()
	deny := func(e *policyError, extra map[string]any) *policyError {
		x := map[string]any{"kind": op.kind, "name": op.name}
		for k, v := range extra {
			x[k] = v
		}
		s.policyAudit(r, subj, op.action(), "", "deny", e.reason, x)
		return e
	}
	if subj.Kind != identity.KindOIDC || len(subj.Delegations) == 0 {
		return deny(perr(http.StatusForbidden, "forbidden", "no policy delegation for this identity"), nil)
	}
	if e := s.stepUp(subj, sess); e != nil {
		return e
	}
	s.delegMu.Lock()
	defer s.delegMu.Unlock()

	base := s.cfg.Policy.Base()
	for attempt := 1; ; attempt++ {
		rev, doc, e := s.activeDoc(ctx)
		if e != nil {
			return e
		}
		activeID := revID(rev)
		next, err := cloneDoc(doc)
		if err != nil {
			return perr(http.StatusInternalServerError, "internal", "cannot copy the active revision")
		}
		dl, changed, e := s.applyDelegated(&next, subj, op, base)
		if e != nil {
			return deny(e, map[string]any{"delegation": dl})
		}
		if !changed {
			obj, _ := delegatedObject(doc, op.kind, op.name, activeID)
			if obj != nil {
				w.Header().Set("ETag", obj.ETag)
			}
			writeJSON(w, http.StatusOK, uiapi.DelegatedResult{Object: obj, RevisionID: activeID, Impact: []uiapi.ImpactItem{}})
			return nil
		}
		policy.Normalize(&next)
		if errs := policy.ValidateManaged(s.cfg.Config, base, next); len(errs) > 0 {
			return deny(&policyError{status: http.StatusBadRequest, reason: "invalid_policy", msg: "the change is outside the delegation or the managed policy", errs: errs}, map[string]any{"delegation": dl})
		}
		raw, err := json.Marshal(next)
		if err != nil {
			return perr(http.StatusInternalServerError, "internal", "cannot encode the document")
		}
		verb := "put"
		if op.del {
			verb = "delete"
		}
		now := s.now().UTC()
		nrev := store.PolicyRevision{
			ID: newRevisionID(now), ParentID: activeID, Document: raw,
			Author: subj.String(), AuthorName: subj.Name, AuthorCat: subj.Category, CreatedAt: now,
			Comment: fmt.Sprintf("delegation %s: %s %s %s", dl, verb, op.kind, op.name), Status: uiapi.RevisionProposed,
		}
		if err := s.cfg.PolicyStore.CreateRevision(ctx, nrev); err != nil {
			s.log.Error("policy create revision", "err", err)
			return perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
		}
		if err := s.cfg.PolicyStore.Activate(ctx, nrev.ID, activeID, subj.String(), now); err != nil {
			s.withdrawRevision(ctx, nrev.ID)
			if errors.Is(err, store.ErrConflict) && attempt < maxDelegatedAttempts {
				continue
			}
			if errors.Is(err, store.ErrConflict) {
				return deny(perr(http.StatusConflict, "policy_busy", "the policy keeps changing concurrently: retry"), map[string]any{"delegation": dl})
			}
			return perr(http.StatusServiceUnavailable, "store_unavailable", "policy store unavailable")
		}
		if err := s.cfg.Policy.Refresh(ctx, s.cfg.PolicyStore); err != nil {
			s.log.Error("policy refresh after delegated change", "err", err)
		}
		var oldDoc *uiapi.PolicyDocument
		if rev != nil {
			oldDoc = &doc
		}
		h := s.cfg.Policy
		impact := policy.Impact(h.CompileUnchecked(oldDoc, activeID), h.CompileUnchecked(&next, nrev.ID), s.ownedCounter(ctx))
		msgs := make([]string, 0, len(impact))
		for _, it := range impact {
			msgs = append(msgs, it.Kind+": "+it.Message)
		}
		extra := map[string]any{"delegation": dl, "kind": op.kind, "name": op.name, "previous_revision_id": activeID, "impact": msgs}
		if op.managedBy != "" {
			extra["managed_by"] = op.managedBy
		}
		s.policyAudit(r, subj, op.action(), nrev.ID, "allow", "", extra)
		s.policyAudit(r, subj, "policy.activate", nrev.ID, "allow", "", map[string]any{"previous_revision_id": activeID, "delegation": dl})
		res := uiapi.DelegatedResult{Changed: true, RevisionID: nrev.ID, Impact: impact}
		if !op.del {
			res.Object, _ = delegatedObject(next, op.kind, op.name, nrev.ID)
			w.Header().Set("ETag", res.Object.ETag)
		}
		if res.Impact == nil {
			res.Impact = []uiapi.ImpactItem{}
		}
		writeJSON(w, http.StatusOK, res)
		return nil
	}
}

// withdrawRevision rejects a delegated revision that lost an activation
// race, so that it does not linger as a proposal (best effort).
func (s *Server) withdrawRevision(ctx context.Context, id string) {
	rev, err := s.cfg.PolicyStore.GetRevision(ctx, id)
	if err != nil || rev.Status != uiapi.RevisionProposed {
		return
	}
	rev.Status = uiapi.RevisionRejected
	if err := s.cfg.PolicyStore.UpdateRevision(ctx, *rev); err != nil {
		s.log.Warn("withdraw delegated revision", "revision", id, "err", err)
	}
}

// carryDelegated sets the delegated section of a human proposal: the one of
// the active revision, minus the objects taken over. A proposal may only
// send the delegated section unchanged; taking objects over requires
// policy.approve.
func (s *Server) carryDelegated(subj *identity.Subject, doc *uiapi.PolicyDocument, active uiapi.PolicyDocument, takeOver []string) *policyError {
	carried := active.Delegated
	if doc.Delegated != nil {
		sent := *doc
		policy.Normalize(&sent)
		if !sameJSON(sent.Delegated, carried) {
			return perr(http.StatusForbidden, "delegated_object", "delegated roles and bindings are changed through the delegation API; to change or remove one, take it over (take_over)")
		}
	}
	if len(takeOver) == 0 {
		doc.Delegated = carried
		return nil
	}
	if !s.pol.AllowMeta(subj, uiapi.ActionPolicyApprove) {
		return perr(http.StatusForbidden, "forbidden", "taking over delegated objects requires policy.approve")
	}
	copied := &uiapi.DelegatedObjects{Roles: map[string]uiapi.DelegatedRole{}, Bindings: map[string]uiapi.DelegatedBinding{}}
	if carried != nil {
		for k, v := range carried.Roles {
			copied.Roles[k] = v
		}
		for k, v := range carried.Bindings {
			copied.Bindings[k] = v
		}
	}
	for _, ref := range takeOver {
		kind, name, _ := strings.Cut(ref, "/")
		switch kind {
		case "roles":
			if _, ok := copied.Roles[name]; !ok {
				return perr(http.StatusBadRequest, "bad_request", "take_over: no delegated role "+name)
			}
			delete(copied.Roles, name)
		case "bindings":
			if _, ok := copied.Bindings[name]; !ok {
				return perr(http.StatusBadRequest, "bad_request", "take_over: no delegated binding "+name)
			}
			delete(copied.Bindings, name)
		default:
			return perr(http.StatusBadRequest, "bad_request", "take_over: expected roles/<name> or bindings/<name>, got "+ref)
		}
	}
	doc.Delegated = copied
	policy.Normalize(doc)
	return nil
}
