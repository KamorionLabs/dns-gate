package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// ACME DNS-01 endpoints: the lego httpreq provider (HTTPREQ_ENDPOINT =
// <gate>/acme/httpreq) and the acme-dns API (<gate>/acme/acme-dns). They
// write _acme-challenge TXT RRsets through the zone engine, as the caller:
// RBAC, record scopes, ownership and audit apply, and the caller must have
// an ephemeral role so that leftovers are garbage-collected.
const (
	ACMEHTTPReqPath = "/acme/httpreq"
	ACMEDNSPath     = "/acme/acme-dns"

	acmeTTL = 60
)

var (
	httpreqValueRe = regexp.MustCompile(`^[A-Za-z0-9_+/=-]{1,255}$`)
	acmeDNSTXTRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// acmeRoutes are the ACME endpoints, all POST.
var acmeRoutes = []string{
	ACMEHTTPReqPath + "/present",
	ACMEHTTPReqPath + "/cleanup",
	ACMEDNSPath + "/register",
	ACMEDNSPath + "/update",
}

type acmeError struct {
	status  int
	reason  string
	message string
}

func (e *acmeError) Error() string { return e.reason + ": " + e.message }

func (s *Server) handleACME(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if !slices.Contains(acmeRoutes, p) || r.URL.RawQuery != "" {
		writeError(w, http.StatusNotFound, "not_found", "unknown ACME endpoint")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	switch p {
	case ACMEHTTPReqPath + "/present":
		s.handleHTTPReq(w, r, true)
	case ACMEHTTPReqPath + "/cleanup":
		s.handleHTTPReq(w, r, false)
	case ACMEDNSPath + "/register":
		s.handleACMEDNSRegister(w, r)
	case ACMEDNSPath + "/update":
		s.handleACMEDNSUpdate(w, r)
	}
}

// readACMEBody decodes a JSON body whatever its Content-Type: ACME clients
// often send none.
func readACMEBody(r *http.Request, v any) *acmeError {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &acmeError{http.StatusRequestEntityTooLarge, "too_large", "request body too large"}
		}
		return &acmeError{http.StatusBadRequest, "malformed_json_payload", "invalid JSON body"}
	}
	if dec.More() {
		return &acmeError{http.StatusBadRequest, "malformed_json_payload", "trailing data after JSON body"}
	}
	return nil
}

func authFailure(err error) *acmeError {
	var ae *authn.Error
	if !errors.As(err, &ae) {
		return &acmeError{http.StatusUnauthorized, "unauthenticated", "authentication failed"}
	}
	return &acmeError{ae.Status, ae.Reason, ae.Message}
}

// httpreqRequest is the body of the lego httpreq provider: fqdn and value
// in the default mode, domain, token and keyAuth in the RAW mode.
type httpreqRequest struct {
	FQDN    string `json:"fqdn"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

func (s *Server) handleHTTPReq(w http.ResponseWriter, r *http.Request, present bool) {
	op := "acme.cleanup"
	if present {
		op = "acme.present"
	}
	subj, err := s.cfg.Authn.Authenticate(r)
	if err != nil {
		ae := authFailure(err)
		s.audit(r, nil, op, "", "deny", ae.reason)
		writeError(w, ae.status, ae.reason, ae.message)
		return
	}
	authn.StripCredentials(r.Header)
	r = r.WithContext(identity.With(r.Context(), subj))
	var req httpreqRequest
	if ae := readACMEBody(r, &req); ae != nil {
		writeError(w, ae.status, ae.reason, ae.message)
		return
	}
	name, value := req.FQDN, req.Value
	switch {
	case req.FQDN != "":
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.FQDN)), acmeChallengePrefix) {
			writeError(w, http.StatusBadRequest, "bad_request", "fqdn must be an _acme-challenge name")
			return
		}
	case req.Domain != "" && req.KeyAuth != "":
		sum := sha256.Sum256([]byte(req.KeyAuth))
		name, value = req.Domain, base64.RawURLEncoding.EncodeToString(sum[:])
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "fqdn and value (default mode) or domain and keyAuth (RAW mode) required")
		return
	}
	if !httpreqValueRe.MatchString(value) {
		writeError(w, http.StatusBadRequest, "bad_request", "value: 1 to 255 base64 characters required")
		return
	}
	t, msg := s.acmeTarget(name)
	if msg != "" {
		writeError(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	err = s.acmeWrite(r.Context(), subj, t, op, func(vals []string) ([]string, error) {
		if present {
			if slices.Contains(vals, value) {
				return vals, nil
			}
			return append(vals, value), nil
		}
		return slices.DeleteFunc(vals, func(v string) bool { return v == value }), nil
	})
	if err != nil {
		s.acmeFailure(w, r, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"fqdn": acmeChallengePrefix + t.domain + ".", "value": value})
}

// acmeFailure writes an error of an ACME endpoint: {"reason","message"} or,
// for acme-dns clients, {"error","message"}.
func (s *Server) acmeFailure(w http.ResponseWriter, r *http.Request, err error, acmeDNS bool) {
	status, reason, msg := http.StatusInternalServerError, "internal", "internal error"
	var ae *acmeError
	if ze, ok := zonewrite.AsError(err); ok {
		status, reason, msg = reasonStatus(ze.Reason), string(ze.Reason), ze.Message
		if ze.Reason == zonewrite.ReasonLocked {
			w.Header().Set("Retry-After", "5")
		}
		if ze.Reason == zonewrite.ReasonUpstream {
			s.log.Warn("upstream error", "request_id", requestid.From(r.Context()), "path", r.URL.Path, "err", ze.Err)
		}
	} else if errors.As(err, &ae) {
		status, reason, msg = ae.status, ae.reason, ae.message
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		status, reason, msg = http.StatusGatewayTimeout, "timeout", "request timed out"
	} else {
		s.log.Error("acme error", "request_id", requestid.From(r.Context()), "path", r.URL.Path, "err", err)
	}
	if acmeDNS {
		writeJSON(w, status, map[string]string{"error": reason, "message": msg})
		return
	}
	writeError(w, status, reason, msg)
}

// acmeWrite changes the values of the challenge RRset of t under the zone
// lock; mutate gets the current values (nil when absent) and returns the
// new ones (none deletes the RRset).
func (s *Server) acmeWrite(ctx context.Context, subj *identity.Subject, t acmeTarget, op string, mutate func([]string) ([]string, error)) error {
	if s.cfg.Authz.EphemeralTTL(subj) <= 0 {
		return &acmeError{http.StatusForbidden, "ephemeral_required", "ACME endpoints need a role with ephemeral_ttl: challenge records must expire"}
	}
	p, err := s.cfg.Engine.Authorize(ctx, subj, t.zone, policy.ActionRecordWrite, op)
	if err != nil {
		return err
	}
	if !s.cfg.Authz.AllowRRset(subj, policy.ActionRecordWrite, t.zone, t.key) {
		return &acmeError{http.StatusForbidden, "forbidden", "not allowed to write " + t.key.Host + " TXT in " + t.zone}
	}
	ttl := challengeTTL(p.Capabilities())
	_, _, err = s.cfg.Engine.Write(ctx, subj, t.zone, "", op, func(cur *dns.Zone) (*zonewrite.Plan, error) {
		var old *dns.RRset
		var vals []string
		if set, ok := cur.Set(t.key); ok {
			old, vals, ttl = &set, slices.Clone(set.Values), set.TTL
		}
		next, err := mutate(slices.Clone(vals))
		if err != nil {
			return nil, err
		}
		if sameValues(vals, next) {
			return &zonewrite.Plan{}, nil
		}
		c := dns.Change{Key: t.key, Old: old}
		if len(next) > 0 {
			c.New = &dns.RRset{Key: t.key, TTL: ttl, Values: next}
		}
		return &zonewrite.Plan{Changes: []dns.Change{c}}, nil
	})
	return err
}

func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	return true
}

// challengeTTL is the TTL of a new challenge RRset: 60s, or the closest
// value the provider accepts.
func challengeTTL(c provider.Capabilities) int {
	if len(c.TTLs) > 0 {
		best := 0
		for _, t := range c.TTLs {
			if t >= acmeTTL && (best == 0 || t < best) {
				best = t
			}
		}
		if best == 0 {
			best = slices.Max(c.TTLs)
		}
		return best
	}
	ttl := acmeTTL
	if ttl < c.MinTTL {
		ttl = c.MinTTL
	}
	if c.MaxTTL > 0 && ttl > c.MaxTTL {
		ttl = c.MaxTTL
	}
	return ttl
}

// acmeDNSSubject authenticates an acme-dns request: X-Api-User and
// X-Api-Key first (they win over basic authentication taken from the URL),
// else the Authorization header. It returns the presented API key.
func (s *Server) acmeDNSSubject(r *http.Request) (*identity.Subject, string, *acmeError) {
	user, key := r.Header.Get("X-Api-User"), r.Header.Get("X-Api-Key")
	var subj *identity.Subject
	var err error
	switch {
	case user != "" || key != "":
		if user == "" || key == "" {
			return nil, "", &acmeError{http.StatusUnauthorized, "forbidden", "X-Api-User and X-Api-Key required"}
		}
		subj, err = s.cfg.Authn.AuthenticateAPIKey(r, user, key)
	case r.Header.Get("Authorization") != "":
		scheme, v, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if strings.EqualFold(scheme, "Bearer") {
			key = strings.TrimSpace(v)
		} else if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
			_, key, _ = strings.Cut(string(b), ":")
		}
		subj, err = s.cfg.Authn.Authenticate(r)
	default:
		return nil, "", &acmeError{http.StatusUnauthorized, "forbidden", "a gate API key is required: X-Api-User (key id) and X-Api-Key (key)"}
	}
	if err != nil {
		return nil, "", authFailure(err)
	}
	if subj.Kind != identity.KindAPIKey {
		return nil, "", &acmeError{http.StatusUnauthorized, "forbidden", "acme-dns accounts are gate API keys: OIDC tokens and virtual keys are not accepted here"}
	}
	authn.StripCredentials(r.Header)
	return subj, key, nil
}

// acmeDNSRegisterRequest is the acme-dns /register body; domain is a gate
// extension (acme-dns has no such field and relies on a CNAME instead).
type acmeDNSRegisterRequest struct {
	AllowFrom []string `json:"allowfrom"`
	Domain    string   `json:"domain"`
}

func (s *Server) handleACMEDNSRegister(w http.ResponseWriter, r *http.Request) {
	const op = "acme.register"
	subj, key, ae := s.acmeDNSSubject(r)
	if ae != nil {
		if ae.reason == "forbidden" && r.Header.Get("X-Api-Key") == "" && r.Header.Get("Authorization") == "" {
			ae = &acmeError{http.StatusUnauthorized, "registration_requires_api_key",
				"this gate has no anonymous acme-dns registration: create a gate API key with acme_domains (POST /api/v1/api-keys) " +
					"and use its acme_dns_accounts, or call /register with the key (basic auth) and {\"domain\": \"<name>\"}"}
		}
		s.audit(r, nil, op, "", "deny", ae.reason)
		writeJSON(w, ae.status, map[string]string{"error": ae.reason, "message": ae.message})
		return
	}
	r = r.WithContext(identity.With(r.Context(), subj))
	var req acmeDNSRegisterRequest
	if r.ContentLength != 0 {
		if ae := readACMEBody(r, &req); ae != nil {
			writeJSON(w, ae.status, map[string]string{"error": ae.reason, "message": ae.message})
			return
		}
	}
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain_required",
			"message": "acme-dns registrations of this gate name their domain: send {\"domain\": \"<name>\"}, or create them with the key (acme_domains)"})
		return
	}
	allow := []string{}
	for _, c := range req.AllowFrom {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_allowfrom_cidr", "message": c + " is not a CIDR prefix"})
			return
		}
		allow = append(allow, p.Masked().String())
	}
	t, msg := s.acmeTarget(req.Domain)
	if msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_domain", "message": msg})
		return
	}
	if !s.cfg.Authz.AllowRRset(subj, policy.ActionRecordWrite, t.zone, t.key) || s.cfg.Authz.EphemeralTTL(subj) <= 0 {
		s.apiAudit(r, subj, op, t.zone, "deny", "forbidden", map[string]any{"domain": t.domain})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden",
			"message": "the role of this key may not answer challenges of " + t.domain + " (record scope or ephemeral_ttl)"})
		return
	}
	now := s.now().UTC()
	rg := store.ACMERegistration{KeyID: subj.ID, Subdomain: newUUID(), Domain: t.domain, AllowFrom: allow, CreatedAt: now, UpdatedAt: now}
	if err := s.cfg.APIKeys.PutACMERegistration(r.Context(), rg); err != nil {
		s.acmeFailure(w, r, err, true)
		return
	}
	s.apiAudit(r, subj, op, t.zone, "allow", "", map[string]any{"domain": t.domain, "subdomain": rg.Subdomain})
	writeJSON(w, http.StatusCreated, acmeAccount(subj.ID, key, rg))
}

type acmeDNSUpdateRequest struct {
	Subdomain string `json:"subdomain"`
	TXT       string `json:"txt"`
}

func (s *Server) handleACMEDNSUpdate(w http.ResponseWriter, r *http.Request) {
	const op = "acme.update"
	subj, _, ae := s.acmeDNSSubject(r)
	if ae != nil {
		s.audit(r, nil, op, "", "deny", ae.reason)
		writeJSON(w, ae.status, map[string]string{"error": ae.reason, "message": ae.message})
		return
	}
	r = r.WithContext(identity.With(r.Context(), subj))
	var req acmeDNSUpdateRequest
	if ae := readACMEBody(r, &req); ae != nil {
		writeJSON(w, ae.status, map[string]string{"error": ae.reason, "message": ae.message})
		return
	}
	reg, ae := s.acmeRegistration(r.Context(), subj, req.Subdomain)
	if ae != nil {
		writeJSON(w, ae.status, map[string]string{"error": ae.reason, "message": ae.message})
		return
	}
	if !acmeDNSTXTRe.MatchString(req.TXT) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_txt", "message": "txt: 43 base64url characters required"})
		return
	}
	if !cidrsAllow(reg.AllowFrom, s.cfg.Authn.ClientIP(r)) {
		s.apiAudit(r, subj, op, "", "deny", "source_ip", map[string]any{"subdomain": reg.Subdomain})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "forbidden", "message": "registration not allowed from this address"})
		return
	}
	t, msg := s.acmeTarget(reg.Domain)
	if msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_subdomain", "message": msg})
		return
	}
	err := s.acmeWrite(r.Context(), subj, t, op, func(vals []string) ([]string, error) {
		cur := reg
		fresh, err := s.cfg.APIKeys.GetACMERegistration(r.Context(), reg.KeyID, reg.Subdomain)
		switch {
		case err == nil:
			cur = fresh
		case !errors.Is(err, store.ErrNotFound):
			return nil, err
		case reg.Version > 0:
			return nil, &acmeError{http.StatusConflict, "conflict", "the registration was removed meanwhile"}
		}
		recent := append(slices.DeleteFunc(slices.Clone(cur.Values), func(v string) bool { return v == req.TXT }), req.TXT)
		var evicted []string
		if n := len(recent) - store.MaxACMEValues; n > 0 {
			evicted, recent = recent[:n], recent[n:]
		}
		cur.Values, cur.UpdatedAt = recent, s.now().UTC()
		if err := s.cfg.APIKeys.PutACMERegistration(r.Context(), *cur); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return nil, &acmeError{http.StatusConflict, "conflict", "concurrent update of the registration: retry"}
			}
			return nil, err
		}
		vals = slices.DeleteFunc(vals, func(v string) bool { return slices.Contains(evicted, v) })
		if !slices.Contains(vals, req.TXT) {
			vals = append(vals, req.TXT)
		}
		return vals, nil
	})
	if err != nil {
		s.acmeFailure(w, r, err, true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"txt": req.TXT})
}

// acmeRegistration finds the registration of a subdomain of the key. A
// subdomain that is a domain name is its own registration, created on first
// use: acme.sh and cert-manager configurations can name the domain directly.
func (s *Server) acmeRegistration(ctx context.Context, subj *identity.Subject, sub string) (*store.ACMERegistration, *acmeError) {
	sub = strings.TrimSpace(sub)
	if sub == "" || len(sub) > 253 {
		return nil, &acmeError{http.StatusBadRequest, "bad_subdomain", "subdomain required"}
	}
	if strings.Contains(sub, ".") {
		sub = strings.TrimSuffix(strings.ToLower(sub), ".")
	}
	reg, err := s.cfg.APIKeys.GetACMERegistration(ctx, subj.ID, sub)
	switch {
	case err == nil:
		return reg, nil
	case !errors.Is(err, store.ErrNotFound):
		s.log.Error("acme registration read", "err", err)
		return nil, &acmeError{http.StatusServiceUnavailable, "unavailable", "registration store unavailable"}
	}
	t, msg := s.acmeTarget(sub)
	if msg != "" || t.domain != sub {
		return nil, &acmeError{http.StatusBadRequest, "bad_subdomain", "unknown subdomain: use a registration of this key or the domain name"}
	}
	now := s.now().UTC()
	return &store.ACMERegistration{KeyID: subj.ID, Subdomain: sub, Domain: sub, CreatedAt: now, UpdatedAt: now}, nil
}

func cidrsAllow(cidrs []string, ip netip.Addr) bool {
	if len(cidrs) == 0 {
		return true
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && ip.IsValid() && p.Contains(ip) {
			return true
		}
	}
	return false
}
