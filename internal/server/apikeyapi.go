package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/apikey"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

const (
	routeAPIKeys      = "/api/v1/api-keys"
	routeAPIKey       = "/api/v1/api-keys/{id}"
	routeAPIKeyRotate = "/api/v1/api-keys/{id}/rotate"

	defaultKeyOverlap = 24 * time.Hour
	maxKeyOverlap     = 30 * 24 * time.Hour
)

var (
	keyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,63}$`)
	keyTeamRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
)

// handleAPIKeys serves /api/v1/api-keys: gate-issued API keys, managed by
// subjects holding gate.apikey.manage (never by keys).
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, pattern, id string) {
	if s.cfg.APIKeys == nil {
		writeError(w, http.StatusNotFound, "not_found", "API keys are not enabled")
		return
	}
	snap := s.cfg.Policy.Current()
	relaxed := pattern == routeAPIKey && (r.Method == http.MethodDelete || r.Method == http.MethodGet)
	if subj.Kind == identity.KindAPIKey || subj.Kind == identity.KindVirtualKey || (!relaxed && !snap.GrantsAnywhere(subj.Roles, policy.ActionAPIKeyManage)) {
		s.apiAudit(r, subj, "apikey.manage", "", "deny", "forbidden", nil)
		writeError(w, http.StatusForbidden, "forbidden", policy.ActionAPIKeyManage+" not granted")
		return
	}
	var e *policyError
	switch {
	case pattern == routeAPIKeys && r.Method == http.MethodGet:
		e = s.listAPIKeys(w, r, subj, snap)
	case pattern == routeAPIKeys:
		e = s.createAPIKey(w, r, subj, sess, snap)
	case pattern == routeAPIKeyRotate:
		e = s.rotateAPIKey(w, r, subj, sess, snap, id)
	case r.Method == http.MethodGet:
		e = s.getAPIKey(w, r, subj, snap, id)
	case r.Method == http.MethodPut:
		e = s.replaceAPIKey(w, r, subj, sess, snap, id)
	case r.Method == http.MethodDelete:
		e = s.revokeAPIKey(w, r, subj, snap, id)
	}
	if e != nil {
		s.writePolicyError(w, e)
	}
}

// canManageKey: a team of the subject (any team for gate-wide managers,
// holding gate.apikey.manage on "*") and gate.apikey.manage on every zone of
// the key role.
func canManageKey(snap *policy.Snapshot, subj *identity.Subject, team, role string) bool {
	if !slices.Contains(subj.Teams, team) && !snap.GrantsPattern(subj.Roles, policy.ActionAPIKeyManage, "*") {
		return false
	}
	zones := snap.RoleZones(role)
	if len(zones) == 0 {
		return snap.GrantsAnywhere(subj.Roles, policy.ActionAPIKeyManage)
	}
	for _, z := range zones {
		if !snap.GrantsPattern(subj.Roles, policy.ActionAPIKeyManage, z) {
			return false
		}
	}
	return true
}

// canRevokeKey: managers of the key, its creator, and the members of its
// team holding gate.apikey.manage anywhere may always see and revoke it,
// even after its role changed.
func canRevokeKey(snap *policy.Snapshot, subj *identity.Subject, k *store.APIKey) bool {
	return canManageKey(snap, subj, k.Team, k.Role) || k.CreatedBy == subj.String() ||
		(slices.Contains(subj.Teams, k.Team) && snap.GrantsAnywhere(subj.Roles, policy.ActionAPIKeyManage))
}

func (s *Server) loadKey(ctx context.Context, snap *policy.Snapshot, subj *identity.Subject, id string) (*store.APIKey, *policyError) {
	return s.loadKeyFor(ctx, id, func(k *store.APIKey) bool { return canManageKey(snap, subj, k.Team, k.Role) })
}

func (s *Server) loadKeyFor(ctx context.Context, id string, allowed func(*store.APIKey) bool) (*store.APIKey, *policyError) {
	if !apikey.ValidID(id) {
		return nil, perr(http.StatusNotFound, "not_found", "unknown API key")
	}
	k, err := s.cfg.APIKeys.GetAPIKey(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !allowed(k)) {
		return nil, perr(http.StatusNotFound, "not_found", "unknown API key")
	}
	if err != nil {
		s.log.Error("api key read", "err", err)
		return nil, perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	return k, nil
}

func (s *Server) keyView(ctx context.Context, k store.APIKey) (uiapi.APIKey, []store.ACMERegistration, error) {
	regs, err := s.cfg.APIKeys.ListACMERegistrations(ctx, k.ID)
	if err != nil {
		return uiapi.APIKey{}, nil, err
	}
	v := uiapi.APIKey{
		ID: k.ID, Name: k.Name, Description: k.Description, Team: k.Team, Role: k.Role, Status: uiapi.APIKeyActive,
		ExpiresAt: k.ExpiresAt, AllowedCIDRs: nonNil(k.AllowedCIDRs), ACMEDomains: []string{}, ACMEDNS: []uiapi.ACMEDNSRegistration{},
		CreatedAt: k.CreatedAt, CreatedBy: k.CreatedBy, CreatedByName: k.CreatedByName, RotatedAt: k.RotatedAt,
		RevokedAt: k.RevokedAt, RevokedBy: k.RevokedBy, LastUsedAt: k.LastUsedAt, LastUsedIP: k.LastUsedIP,
	}
	now := s.now()
	switch {
	case k.RevokedAt != nil:
		v.Status = uiapi.APIKeyRevoked
	case k.ExpiresAt != nil && !now.Before(*k.ExpiresAt):
		v.Status = uiapi.APIKeyExpired
	}
	if k.PreviousHash != "" && k.PreviousExpiresAt != nil && now.Before(*k.PreviousExpiresAt) {
		v.PreviousKeyExpiresAt = k.PreviousExpiresAt
	}
	var dns []store.ACMERegistration
	for _, rg := range regs {
		if rg.Origin == store.ACMEOriginHTTPReq {
			continue
		}
		dns = append(dns, rg)
		if rg.Origin == store.ACMEOriginAPI && !slices.Contains(v.ACMEDomains, rg.Domain) {
			v.ACMEDomains = append(v.ACMEDomains, rg.Domain)
		}
		v.ACMEDNS = append(v.ACMEDNS, uiapi.ACMEDNSRegistration{Subdomain: rg.Subdomain, Domain: rg.Domain, Origin: rg.Origin, AllowFrom: nonNil(rg.AllowFrom)})
	}
	return v, dns, nil
}

// issued is the answer of a creation or rotation, with the acme-dns
// accounts of the registrations created through the API (subdomain != domain).
func issued(v uiapi.APIKey, regs []store.ACMERegistration, key string) uiapi.IssuedAPIKey {
	out := uiapi.IssuedAPIKey{APIKey: v, Key: key, ACMEDNSAccounts: map[string]uiapi.ACMEDNSAccount{}}
	for _, rg := range regs {
		if _, dup := out.ACMEDNSAccounts[rg.Domain]; dup {
			continue
		}
		out.ACMEDNSAccounts[rg.Domain] = acmeAccount(v.ID, key, rg)
	}
	return out
}

func acmeAccount(id, key string, rg store.ACMERegistration) uiapi.ACMEDNSAccount {
	return uiapi.ACMEDNSAccount{Username: id, Password: key, FullDomain: acmeChallengePrefix + rg.Domain, SubDomain: rg.Subdomain, AllowFrom: nonNil(rg.AllowFrom)}
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request, subj *identity.Subject, snap *policy.Snapshot) *policyError {
	q := r.URL.Query()
	for k := range q {
		if k != "team" && k != "include_revoked" {
			return perr(http.StatusBadRequest, "bad_request", "unknown query parameter "+k)
		}
	}
	keys, err := s.cfg.APIKeys.ListAPIKeys(r.Context())
	if err != nil {
		s.log.Error("api key list", "err", err)
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	out := []uiapi.APIKey{}
	for _, k := range keys {
		if !canManageKey(snap, subj, k.Team, k.Role) || (q.Get("team") != "" && k.Team != q.Get("team")) ||
			(k.RevokedAt != nil && q.Get("include_revoked") != "true") {
			continue
		}
		v, _, err := s.keyView(r.Context(), k)
		if err != nil {
			return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) getAPIKey(w http.ResponseWriter, r *http.Request, subj *identity.Subject, snap *policy.Snapshot, id string) *policyError {
	k, e := s.loadKeyFor(r.Context(), id, func(k *store.APIKey) bool { return canRevokeKey(snap, subj, k) })
	if e != nil {
		return e
	}
	v, _, err := s.keyView(r.Context(), *k)
	if err != nil {
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

// validateKeyRequest checks the mutable fields of a request and returns the
// normalized acme-dns domains.
func (s *Server) validateKeyRequest(snap *policy.Snapshot, req *uiapi.APIKeyRequest, role string) ([]string, *policyError) {
	req.Name = strings.TrimSpace(req.Name)
	if !keyNameRe.MatchString(req.Name) {
		return nil, perr(http.StatusBadRequest, "invalid", "name: 1 to 64 letters, digits, spaces and . _ @ - required")
	}
	if len(req.Description) > 512 {
		return nil, perr(http.StatusBadRequest, "invalid", "description: at most 512 characters")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(s.now()) {
		return nil, perr(http.StatusBadRequest, "invalid", "expires_at: must be in the future")
	}
	if len(req.AllowedCIDRs) > 64 {
		return nil, perr(http.StatusBadRequest, "invalid", "allowed_cidrs: at most 64 prefixes")
	}
	for i, c := range req.AllowedCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, perr(http.StatusBadRequest, "invalid", fmt.Sprintf("allowed_cidrs[%d]: %q is not a CIDR prefix", i, c))
		}
		req.AllowedCIDRs[i] = p.Masked().String()
	}
	if max := s.cfg.Config.ACME.MaxRegistrations; len(req.ACMEDomains) > max {
		return nil, perr(http.StatusBadRequest, "invalid", fmt.Sprintf("acme_domains: at most %d domains (acme.max_registrations)", max))
	}
	var domains []string
	for i, d := range req.ACMEDomains {
		t, msg := s.acmeTarget(d)
		if msg == "" {
			msg = s.acmeRoleProblem(snap, role, t)
		}
		if msg != "" {
			return nil, perr(http.StatusBadRequest, "invalid", fmt.Sprintf("acme_domains[%d]: %s", i, msg))
		}
		if !slices.Contains(domains, t.domain) {
			domains = append(domains, t.domain)
		}
	}
	sort.Strings(domains)
	return domains, nil
}

// acmeRoleProblem explains why role cannot answer the challenges of t.
func (s *Server) acmeRoleProblem(snap *policy.Snapshot, role string, t acmeTarget) string {
	if d := snap.Decide([]string{role}, policy.ActionRecordWrite, t.zone, &t.key); !d.Allowed {
		return fmt.Sprintf("role %s may not write %s TXT in %s", role, t.key.Host, t.zone)
	}
	if s.cfg.Authz.EphemeralTTL(&identity.Subject{Roles: []string{role}}) <= 0 {
		return fmt.Sprintf("role %s has no ephemeral_ttl: ACME challenge records must expire", role)
	}
	return ""
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, snap *policy.Snapshot) *policyError {
	if e := s.stepUp(subj, sess); e != nil {
		return e
	}
	var req uiapi.APIKeyRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	if !keyTeamRe.MatchString(req.Team) {
		return perr(http.StatusBadRequest, "invalid", "team: a lowercase identifier is required")
	}
	if msg := snap.KeyRoleProblem(subj.Roles, req.Role); msg != "" {
		s.apiAudit(r, subj, "apikey.create", "", "deny", "forbidden", map[string]any{"team": req.Team, "role": req.Role})
		return perr(http.StatusForbidden, "forbidden", msg)
	}
	if !canManageKey(snap, subj, req.Team, req.Role) {
		s.apiAudit(r, subj, "apikey.create", "", "deny", "forbidden", map[string]any{"team": req.Team, "role": req.Role})
		return perr(http.StatusForbidden, "forbidden", "API keys of team "+req.Team+" are not managed by this identity")
	}
	domains, e := s.validateKeyRequest(snap, &req, req.Role)
	if e != nil {
		return e
	}
	now := s.now().UTC()
	id := apikey.NewID()
	key := apikey.NewSecret(id)
	grant, _ := snap.RoleGrant(req.Role)
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return perr(http.StatusInternalServerError, "internal", "role grant")
	}
	k := store.APIKey{
		ID: id, Name: req.Name, Description: req.Description, Team: req.Team, Role: req.Role, RoleGrant: string(grantJSON),
		SecretHash: apikey.Hash(key), ExpiresAt: req.ExpiresAt, AllowedCIDRs: req.AllowedCIDRs,
		CreatedAt: now, CreatedBy: subj.String(), CreatedByName: subj.Name,
	}
	if err := s.cfg.APIKeys.CreateAPIKey(r.Context(), k); err != nil {
		s.log.Error("api key create", "err", err)
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	if err := s.syncRegistrations(r.Context(), id, domains, now); err != nil {
		s.log.Error("acme registration create", "err", err)
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	created, _ := s.cfg.APIKeys.GetAPIKey(r.Context(), id)
	if created == nil {
		created = &k
	}
	v, regs, err := s.keyView(r.Context(), *created)
	if err != nil {
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	s.apiAudit(r, subj, "apikey.create", "", "allow", "", map[string]any{"key_id": id, "team": k.Team, "role": k.Role, "acme_domains": domains})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, issued(v, regs, key))
	return nil
}

// syncRegistrations makes the registrations a key got through the API (one
// random subdomain per domain) match domains. Registrations of clients
// (/register, domain names used as subdomain) are left alone.
func (s *Server) syncRegistrations(ctx context.Context, id string, domains []string, now time.Time) error {
	regs, err := s.cfg.APIKeys.ListACMERegistrations(ctx, id)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, rg := range regs {
		if rg.Origin != store.ACMEOriginAPI {
			continue
		}
		if !slices.Contains(domains, rg.Domain) {
			if err := s.cfg.APIKeys.DeleteACMERegistration(ctx, id, rg.Subdomain); err != nil {
				return err
			}
			continue
		}
		have[rg.Domain] = true
	}
	for _, d := range domains {
		if have[d] {
			continue
		}
		rg := store.ACMERegistration{KeyID: id, Subdomain: newUUID(), Domain: d, Origin: store.ACMEOriginAPI, CreatedAt: now, UpdatedAt: now}
		if err := s.cfg.APIKeys.PutACMERegistration(ctx, rg); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) replaceAPIKey(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, snap *policy.Snapshot, id string) *policyError {
	if e := s.stepUp(subj, sess); e != nil {
		return e
	}
	k, e := s.loadKey(r.Context(), snap, subj, id)
	if e != nil {
		return e
	}
	var req uiapi.APIKeyRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	if (req.Team != "" && req.Team != k.Team) || (req.Role != "" && req.Role != k.Role) {
		return perr(http.StatusConflict, "immutable", "team and role of an API key cannot change: create another key")
	}
	if k.RevokedAt != nil {
		return perr(http.StatusConflict, "revoked", "the API key is revoked")
	}
	domains, e := s.validateKeyRequest(snap, &req, k.Role)
	if e != nil {
		return e
	}
	k.Name, k.Description, k.ExpiresAt, k.AllowedCIDRs = req.Name, req.Description, req.ExpiresAt, req.AllowedCIDRs
	if e := s.updateKey(r.Context(), *k); e != nil {
		return e
	}
	if req.ACMEDomains != nil {
		if err := s.syncRegistrations(r.Context(), id, domains, s.now().UTC()); err != nil {
			return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
		}
	}
	s.apiAudit(r, subj, "apikey.update", "", "allow", "", map[string]any{"key_id": id, "acme_domains": domains})
	return s.getAPIKey(w, r, subj, snap, id)
}

func (s *Server) updateKey(ctx context.Context, k store.APIKey) *policyError {
	err := s.cfg.APIKeys.UpdateAPIKey(ctx, k)
	switch {
	case errors.Is(err, store.ErrConflict):
		return perr(http.StatusConflict, "conflict", "the API key changed meanwhile: retry")
	case err != nil:
		s.log.Error("api key update", "err", err)
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	return nil
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, subj *identity.Subject, snap *policy.Snapshot, id string) *policyError {
	k, e := s.loadKeyFor(r.Context(), id, func(k *store.APIKey) bool { return canRevokeKey(snap, subj, k) })
	if e != nil {
		return e
	}
	if k.RevokedAt == nil {
		now := s.now().UTC()
		k.RevokedAt, k.RevokedBy = &now, subj.String()
		if e := s.updateKey(r.Context(), *k); e != nil {
			return e
		}
		s.apiAudit(r, subj, "apikey.revoke", "", "allow", "", map[string]any{"key_id": id, "team": k.Team, "role": k.Role})
	}
	regs, err := s.cfg.APIKeys.ListACMERegistrations(r.Context(), id)
	if err == nil {
		for _, rg := range regs {
			_ = s.cfg.APIKeys.DeleteACMERegistration(r.Context(), id, rg.Subdomain)
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, snap *policy.Snapshot, id string) *policyError {
	if e := s.stepUp(subj, sess); e != nil {
		return e
	}
	k, e := s.loadKey(r.Context(), snap, subj, id)
	if e != nil {
		return e
	}
	var req uiapi.APIKeyRotate
	if r.ContentLength != 0 && !decodeBody(w, r, &req) {
		return nil
	}
	overlap := defaultKeyOverlap
	if req.Overlap != "" {
		d, err := time.ParseDuration(req.Overlap)
		if err != nil || d < 0 || d > maxKeyOverlap {
			return perr(http.StatusBadRequest, "invalid", "overlap: a duration between 0s and 720h is required")
		}
		overlap = d
	}
	if k.RevokedAt != nil {
		return perr(http.StatusConflict, "revoked", "the API key is revoked")
	}
	now := s.now().UTC()
	key := apikey.NewSecret(k.ID)
	k.PreviousHash, k.PreviousExpiresAt = "", nil
	if overlap > 0 {
		end := now.Add(overlap)
		k.PreviousHash, k.PreviousExpiresAt = k.SecretHash, &end
	}
	k.SecretHash, k.RotatedAt = apikey.Hash(key), &now
	if e := s.updateKey(r.Context(), *k); e != nil {
		return e
	}
	k.Version++
	v, regs, err := s.keyView(r.Context(), *k)
	if err != nil {
		return perr(http.StatusServiceUnavailable, "unavailable", "API key store unavailable")
	}
	s.apiAudit(r, subj, "apikey.rotate", "", "allow", "", map[string]any{"key_id": id, "overlap": overlap.String()})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, issued(v, regs, key))
	return nil
}

// newUUID returns a random (version 4) UUID, the form of acme-dns
// subdomains and user names.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// acmeTarget is the _acme-challenge TXT RRset of a domain.
type acmeTarget struct {
	domain string // validated domain, without wildcard nor challenge label
	zone   string // managed zone
	key    dns.Key
}

const acmeChallengePrefix = "_acme-challenge."

// acmeTarget resolves the challenge RRset of a domain ("www.example.com",
// "*.example.com" or "_acme-challenge.www.example.com", trailing dot
// allowed) in the most specific managed zone; msg explains a refusal.
func (s *Server) acmeTarget(name string) (acmeTarget, string) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, acmeChallengePrefix)
	if !config.ValidFQDN(d) {
		return acmeTarget{}, fmt.Sprintf("%q is not a domain name", name)
	}
	zone := ""
	for _, z := range s.pol.ManagedZones() {
		if (d == z || strings.HasSuffix(d, "."+z)) && len(z) > len(zone) {
			zone = z
		}
	}
	if zone == "" {
		return acmeTarget{}, fmt.Sprintf("%s is in no zone managed by the gate", d)
	}
	host := "_acme-challenge"
	if d != zone {
		host += "." + strings.TrimSuffix(d, "."+zone)
	}
	return acmeTarget{domain: d, zone: zone, key: dns.Key{Host: host, Type: "TXT"}}, ""
}
