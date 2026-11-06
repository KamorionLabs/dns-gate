package server

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// TeamHeader selects, among the teams of the caller, the one it writes for
// on the gate API (/api/v1): created and adopted RRsets go to that team and
// only its RRsets may be changed. Without it, the caller writes for its
// default team (the first one) and changes the RRsets of any of its teams.
const TeamHeader = "X-DNS-Gate-Team"

// TombstoneLister lists the tombstones of a zone (store.Store).
type TombstoneLister interface {
	ListTombstones(ctx context.Context, zone string) ([]store.Tombstone, error)
}

const (
	routeTeams           = "/api/v1/teams"
	routeTeam            = "/api/v1/teams/{team}"
	routeTeamRename      = "/api/v1/teams/{team}/rename"
	routeZoneTransfers   = "/api/v1/zones/{zone}/transfers"
	routeTransfers       = "/api/v1/transfers"
	routeTransfer        = "/api/v1/transfers/{id}"
	routeTransferApprove = "/api/v1/transfers/{id}/approve"
	routeTransferReject  = "/api/v1/transfers/{id}/reject"
)

// forTeam narrows the subject to one of its teams; "" keeps it.
func forTeam(subj *identity.Subject, team string) (*identity.Subject, *policyError) {
	if team == "" {
		return subj, nil
	}
	if !slices.Contains(subj.Teams, team) {
		return nil, perr(http.StatusForbidden, "not_team_member", "team "+team+" is not one of your teams")
	}
	return subj.ForTeam(team), nil
}

// ownerCounts caches the RRsets and tombstones per team of each zone for
// the team views (one store read per zone and minute).
type ownerCounts struct {
	mu    sync.Mutex
	zones map[string]zoneOwners
}

type zoneOwners struct {
	at         time.Time
	rrsets     map[string]int
	tombstones map[string]int
}

const ownerCountsTTL = time.Minute

func (s *Server) zoneOwners(ctx context.Context, zone string) zoneOwners {
	now := s.now()
	s.owners.mu.Lock()
	if zo, ok := s.owners.zones[zone]; ok && now.Sub(zo.at) < ownerCountsTTL {
		s.owners.mu.Unlock()
		return zo
	}
	s.owners.mu.Unlock()
	zo := zoneOwners{at: now, rrsets: map[string]int{}, tombstones: map[string]int{}}
	if s.cfg.Ownership != nil {
		if list, err := s.cfg.Ownership.List(ctx, zone); err == nil {
			for _, o := range list {
				zo.rrsets[o.Owner]++
			}
		}
	}
	if s.cfg.Tombstones != nil {
		if list, err := s.cfg.Tombstones.ListTombstones(ctx, zone); err == nil {
			for _, t := range list {
				if now.Before(t.ExpiresAt) {
					zo.tombstones[t.Team]++
				}
			}
		}
	}
	s.owners.mu.Lock()
	if s.owners.zones == nil {
		s.owners.zones = map[string]zoneOwners{}
	}
	s.owners.zones[zone] = zo
	s.owners.mu.Unlock()
	return zo
}

// storeOwners returns the teams owning RRsets or tombstones in the readable
// managed zones.
func (s *Server) storeOwners(ctx context.Context, readable map[string]bool) []string {
	set := map[string]bool{}
	for _, z := range s.pol.ManagedZones() {
		if !readable[z] {
			continue
		}
		zo := s.zoneOwners(ctx, z)
		for t := range zo.rrsets {
			set[t] = true
		}
		for t := range zo.tombstones {
			set[t] = true
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	return out
}

// handleTeams serves GET /api/v1/teams and GET /api/v1/teams/{team}.
func (s *Server) handleTeams(w http.ResponseWriter, r *http.Request, subj *identity.Subject, readable map[string]bool, team string) {
	snap := s.cfg.Policy.Current()
	withMembers := s.pol.AllowMeta(subj, "policy.read")
	owners := s.storeOwners(r.Context(), readable)
	if team == "" {
		writeJSON(w, http.StatusOK, uiapi.TeamList{Strict: snap.StrictTeams(), Teams: snap.TeamInfos(owners, withMembers)})
		return
	}
	ti, ok := snap.TeamInfo(team, owners, withMembers)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "unknown team "+team)
		return
	}
	d := uiapi.TeamDetail{TeamInfo: ti, Owned: []uiapi.TeamZone{}, Transfers: []uiapi.Transfer{}}
	for _, z := range s.pol.ManagedZones() {
		if !readable[z] {
			continue
		}
		zo := s.zoneOwners(r.Context(), z)
		if n, nt := zo.rrsets[team], zo.tombstones[team]; n+nt > 0 {
			d.Owned = append(d.Owned, uiapi.TeamZone{Zone: z, RRsets: n, Tombstones: nt})
		}
	}
	if s.cfg.Transfers != nil {
		page, err := s.cfg.Transfers.ListTransfers(r.Context(), subj, store.TransferQuery{Status: uiapi.TransferProposed, Limit: 500})
		if err == nil {
			for _, t := range page.Transfers {
				if t.FromTeam == team || t.ToTeam == team {
					d.Transfers = append(d.Transfers, t)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, d)
}

// handleTransfers serves the transfer routes.
func (s *Server) handleTransfers(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, pattern string, params map[string]string) {
	if s.cfg.Transfers == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "ownership transfers are not available")
		return
	}
	ctx := r.Context()
	switch pattern {
	case routeTransfers:
		q := r.URL.Query()
		for k, v := range q {
			if (k != "zone" && k != "status" && k != "limit" && k != "cursor") || len(v) != 1 {
				writeError(w, http.StatusBadRequest, "bad_request", "unknown or repeated query parameter "+k)
				return
			}
		}
		tq := store.TransferQuery{Zone: dns.NormalizeZone(q.Get("zone")), Status: q.Get("status"), Cursor: q.Get("cursor"), Limit: 50}
		switch tq.Status {
		case "", uiapi.TransferProposed, uiapi.TransferApproved, uiapi.TransferApplied, uiapi.TransferRejected, uiapi.TransferExpired, uiapi.TransferFailed:
		default:
			writeError(w, http.StatusBadRequest, "bad_request", "status must be proposed, approved, applied, rejected, expired or failed")
			return
		}
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 500 {
				writeError(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 500")
				return
			}
			tq.Limit = n
		}
		page, err := s.cfg.Transfers.ListTransfers(ctx, subj, tq)
		if err != nil {
			s.apiError(w, r, "transfers", tq.Zone, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
	case routeTransfer:
		t, err := s.cfg.Transfers.GetTransfer(ctx, subj, params["id"])
		if err != nil {
			s.apiError(w, r, "transfers", "", err)
			return
		}
		writeJSON(w, http.StatusOK, t)
	case routeTransferApprove, routeTransferReject:
		var req uiapi.DecisionRequest
		if r.ContentLength != 0 {
			if e := decodeStrict(r, &req); e != nil {
				s.writePolicyError(w, e)
				return
			}
		}
		if e := s.stepUp(subj, sess); e != nil {
			s.writePolicyError(w, e)
			return
		}
		t, err := s.cfg.Transfers.DecideTransfer(ctx, subj, params["id"], pattern == routeTransferApprove, req.Comment)
		if err != nil {
			if ze, ok := zonewrite.AsError(err); ok && t != nil {
				status, reason := apiStatus(w, err, ze)
				writeJSON(w, status, struct {
					errorBody
					Transfer *uiapi.Transfer `json:"transfer"`
				}{errorBody{Reason: reason, Message: ze.Message, Details: ze.Details}, t})
				return
			}
			s.apiError(w, r, "transfers", "", err)
			return
		}
		writeJSON(w, http.StatusOK, t)
	case routeZoneTransfers:
		zone := dns.NormalizeZone(params["zone"])
		if !config.ValidFQDN(zone) || !s.pol.Managed(zone) {
			writeError(w, http.StatusNotFound, "not_found", "zone not managed by the gate")
			return
		}
		var req uiapi.TransferProposal
		if e := decodeStrict(r, &req); e != nil {
			if e.status == http.StatusBadRequest {
				e.reason = "invalid"
			}
			s.writePolicyError(w, e)
			return
		}
		if e := s.stepUp(subj, sess); e != nil {
			s.writePolicyError(w, e)
			return
		}
		t, err := s.cfg.Transfers.ProposeTransfer(ctx, subj, zone, req)
		if err != nil {
			s.apiError(w, r, "transfers", zone, err)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	case routeTeamRename:
		var req uiapi.TeamRenameRequest
		if e := decodeStrict(r, &req); e != nil {
			if e.status == http.StatusBadRequest {
				e.reason = "invalid"
			}
			s.writePolicyError(w, e)
			return
		}
		if e := s.stepUp(subj, sess); e != nil {
			s.writePolicyError(w, e)
			return
		}
		t, err := s.cfg.Transfers.ProposeRename(ctx, subj, strings.ToLower(params["team"]), req)
		if err != nil {
			s.apiError(w, r, "transfers", "", err)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	}
}
