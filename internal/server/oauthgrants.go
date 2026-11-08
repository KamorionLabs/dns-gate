package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

const (
	routeOAuthGrants = "/api/v1/oauth/grants"
	routeOAuthGrant  = "/api/v1/oauth/grants/{id}"
)

// oauthManager reports whether subj may manage every grant: a person
// signed in directly (no key, no delegated client) holding
// gate.oauth.manage.
func (s *Server) oauthManager(subj *identity.Subject) bool {
	return subj.Kind == identity.KindOIDC && subj.Category == identity.CategoryHuman && !scope.Delegated(subj) &&
		s.cfg.Policy.Current().GrantsAnywhere(subj.Roles, policy.ActionOAuthManage)
}

// handleOAuthGrants serves /api/v1/oauth/grants: the connected
// applications of the caller, and with gate.oauth.manage the grants of a
// client or a subject.
func (s *Server) handleOAuthGrants(w http.ResponseWriter, r *http.Request, subj *identity.Subject, pattern, id string) {
	if subj.Kind != identity.KindOIDC || scope.Delegated(subj) {
		s.apiAudit(r, subj, "oauth.grants", "", "deny", "forbidden", nil)
		writeError(w, http.StatusForbidden, "forbidden", "connected applications are managed by people signed in to the gate")
		return
	}
	manager := s.oauthManager(subj)
	q := r.URL.Query()
	client, subject := q.Get("client"), q.Get("subject")
	if (client != "" || subject != "") && !manager {
		s.apiAudit(r, subj, "oauth.grants", "", "deny", "forbidden", nil)
		writeError(w, http.StatusForbidden, "forbidden", policy.ActionOAuthManage+" not granted")
		return
	}
	if len(client) > 128 || len(subject) > 512 {
		writeError(w, http.StatusBadRequest, "bad_request", "filter too long")
		return
	}
	ctx := r.Context()
	switch {
	case pattern == routeOAuthGrant:
		g, err := s.cfg.OAuth.GetOAuthGrant(ctx, id)
		if err != nil || (g.Subject != subj.String() && !manager) {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.Error("oauth grants", "err", err)
				writeError(w, http.StatusServiceUnavailable, "store_unavailable", "grant store unavailable")
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "no grant "+id)
			return
		}
		if err := s.revokeGrant(ctx, g, subj.String(), revokeReason(g, subj)); err != nil {
			s.log.Error("oauth revoke", "err", err)
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "grant store unavailable")
			return
		}
		s.grantRevokedAudit(r, subj, g)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet:
		if !manager || (client == "" && subject == "") {
			subject = subj.String()
		}
		gs, err := s.cfg.OAuth.ListOAuthGrants(ctx, store.OAuthGrantQuery{ClientID: client, Subject: subject})
		if err != nil {
			s.log.Error("oauth grants", "err", err)
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "grant store unavailable")
			return
		}
		out := uiapi.OAuthGrantList{Grants: []uiapi.OAuthGrant{}, Manage: manager}
		now := s.now()
		for i := range gs {
			out.Grants = append(out.Grants, s.grantView(&gs[i], now))
		}
		writeJSON(w, http.StatusOK, out)
	default:
		if !manager || (client == "" && subject == "") {
			s.apiAudit(r, subj, "oauth.revoke", "", "deny", "forbidden", nil)
			writeError(w, http.StatusForbidden, "forbidden", policy.ActionOAuthManage+" and a client or subject filter are required")
			return
		}
		gs, err := s.cfg.OAuth.ListOAuthGrants(ctx, store.OAuthGrantQuery{ClientID: client, Subject: subject})
		if err != nil {
			s.log.Error("oauth grants", "err", err)
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "grant store unavailable")
			return
		}
		n := 0
		for i := range gs {
			g := &gs[i]
			if g.RevokedAt != nil {
				continue
			}
			if err := s.revokeGrant(ctx, g, subj.String(), "admin"); err != nil {
				s.log.Error("oauth revoke", "err", err)
				writeError(w, http.StatusServiceUnavailable, "store_unavailable", "grant store unavailable")
				return
			}
			s.grantRevokedAudit(r, subj, g)
			n++
		}
		writeJSON(w, http.StatusOK, uiapi.OAuthRevoked{Revoked: n})
	}
}

func revokeReason(g *store.OAuthGrant, by *identity.Subject) string {
	if g.Subject == by.String() {
		return "user"
	}
	return "admin"
}

func (s *Server) grantRevokedAudit(r *http.Request, by *identity.Subject, g *store.OAuthGrant) {
	extra := map[string]any{"grant_id": g.ID, "grant_subject": g.Subject}
	if oc := s.cfg.Config.OAuthClient(g.ClientID); oc != nil {
		extra["client_id"], extra["client_name"] = oc.ID, oc.Name
	} else {
		extra["client_id"] = g.ClientID
	}
	s.apiAudit(r, by, "oauth.revoke", "", "allow", revokeReason(g, by), extra)
}

func (s *Server) grantView(g *store.OAuthGrant, now time.Time) uiapi.OAuthGrant {
	v := uiapi.OAuthGrant{
		ID: g.ID, ClientID: g.ClientID, ClientName: g.ClientID, Subject: g.Subject, SubjectName: g.SubjectName,
		Scopes: append([]string{}, g.Scopes...), Status: uiapi.OAuthGrantActive, CreatedAt: g.CreatedAt, ConsentedAt: g.ConsentedAt,
		LastUsedAt: g.LastUsedAt, ExpiresAt: g.ExpiresAt, RevokedAt: g.RevokedAt, RevokedBy: g.RevokedBy,
	}
	oc := s.cfg.Config.OAuthClient(g.ClientID)
	if oc != nil {
		v.ClientName = oc.Name
		if idle := g.LastUsedAt.Add(oc.RefreshIdleTTL.D()); idle.Before(v.ExpiresAt) {
			v.ExpiresAt = idle
		}
	}
	switch {
	case g.RevokedAt != nil:
		v.Status = uiapi.OAuthGrantRevoked
	case !now.Before(v.ExpiresAt) || oc == nil:
		v.Status = uiapi.OAuthGrantExpired
	}
	return v
}
