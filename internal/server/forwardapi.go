package server

import (
	"net/http"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// URL forward REST API (see api/dns-gate.openapi.yaml and docs/API.md):
//
//	GET    /api/v1/zones/{zone}/forwards        -> forwardList                 (ui.read or dns.read)
//	GET    /api/v1/zones/{zone}/forwards/{host} -> forwardView, ETag "<hash>"  (ui.read or dns.read)
//	PUT    /api/v1/zones/{zone}/forwards/{host} forwardBody -> forwardView     (engine RBAC: dns.forward.write)
//	DELETE /api/v1/zones/{zone}/forwards/{host} -> 204                         (engine RBAC: dns.forward.write)
//
// A forward is the RRset {host, URLFWD} of the engine: the RRset routes,
// plans, adoption and transfers accept it too. PUT and DELETE honour
// If-Match and If-None-Match like the RRset routes.

// FeatureForwards is advertised by GET /.well-known/dns-gate when the URL
// forward API is served.
const FeatureForwards = "forwards"

type forwardBody struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Title       string `json:"title,omitempty"`
	Keywords    string `json:"keywords,omitempty"`
	Description string `json:"description,omitempty"`
	// RequireHTTPS refuses the write unless the forwards of the zone answer
	// HTTPS; it is not stored.
	RequireHTTPS bool `json:"require_https,omitempty"`
}

// forwardView is a forward with its ownership and the HTTPS status of the
// forwards of its zone.
type forwardView struct {
	uiapi.RRset
	HTTPS *provider.HTTPSRedirect `json:"https,omitempty"`
}

type forwardList struct {
	Zone     string                  `json:"zone"`
	HTTPS    *provider.HTTPSRedirect `json:"https,omitempty"`
	Forwards []uiapi.RRset           `json:"forwards"`
}

// handleForwards serves GET /api/v1/zones/{zone}/forwards.
func (s *Server) handleForwards(w http.ResponseWriter, r *http.Request, subj *identity.Subject, zoneIn string) {
	zone, _, msg := rrsetKey(zoneIn, dns.Apex, dns.TypeURLForward)
	if msg != "" {
		writeError(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	if !s.canRead(subj, zone) {
		writeError(w, http.StatusForbidden, "forbidden", "ui.read or dns.read not granted on "+zone)
		return
	}
	inv, err := s.cfg.Engine.Inventory(r.Context(), subj, zone)
	if err != nil {
		s.inventoryError(w, zone, err)
		return
	}
	out := forwardList{Zone: zone, Forwards: []uiapi.RRset{}, HTTPS: s.httpsOf(r, subj, zone)}
	for _, rs := range inv.RRsets {
		if (dns.Key{Host: rs.Host, Type: rs.Type}).IsForward() {
			out.Forwards = append(out.Forwards, withHash(rs))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// httpsOf is the HTTPS status of the forwards of a managed zone, nil when
// it cannot be read.
func (s *Server) httpsOf(r *http.Request, subj *identity.Subject, zone string) *provider.HTTPSRedirect {
	if !s.pol.Managed(zone) {
		return nil
	}
	st, err := s.cfg.Engine.HTTPSRedirect(r.Context(), subj, zone)
	if err != nil {
		return nil
	}
	return &st
}

// handleForward serves /api/v1/zones/{zone}/forwards/{host}.
func (s *Server) handleForward(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, zoneIn, hostIn string) {
	zone, key, msg := rrsetKey(zoneIn, hostIn, dns.TypeURLForward)
	if msg != "" {
		writeError(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	if r.Method == http.MethodGet {
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
		writeJSON(w, http.StatusOK, forwardView{RRset: rs, HTTPS: s.httpsOf(r, subj, zone)})
		return
	}
	if !s.pol.Managed(zone) {
		writeError(w, http.StatusNotFound, "not_found", "zone not managed by the gate")
		return
	}
	if s.cfg.Ops == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "forward writes are not available")
		return
	}
	action := "api.forward.put"
	if r.Method == http.MethodDelete {
		action = "api.forward.delete"
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
		var body forwardBody
		if e := decodeStrict(r, &body); e != nil {
			if e.status == http.StatusBadRequest {
				e.reason = "invalid"
			}
			s.writePolicyError(w, e)
			return
		}
		if strings.TrimSpace(body.Type) == "" || strings.TrimSpace(body.URL) == "" {
			writeError(w, http.StatusBadRequest, "invalid", "type ("+strings.Join(dns.ForwardModes, ", ")+") and url are required (DELETE removes a forward)")
			return
		}
		change.Forward = &dns.Forward{Mode: body.Type, URL: body.URL, Title: body.Title, Keywords: body.Keywords, Description: body.Description}
		change.RequireHTTPS = body.RequireHTTPS
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
	writeJSON(w, http.StatusOK, forwardView{RRset: rs, HTTPS: s.httpsOf(r, subj, zone)})
}
