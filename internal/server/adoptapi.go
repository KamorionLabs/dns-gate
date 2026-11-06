package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/routes"
	"github.com/KamorionLabs/dns-gate/internal/tfexport"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/version"
)

// Operations are the engine methods behind adoption and RRset plans
// (zonewrite engine, see internal/uiapi/adopt.go).
type Operations interface {
	PreviewAdopt(ctx context.Context, s *identity.Subject, zone string, sel uiapi.AdoptSelection) (*uiapi.AdoptPreview, error)
	AdoptMany(ctx context.Context, s *identity.Subject, zone string, req uiapi.AdoptApply) (*uiapi.AdoptResult, error)
	PlanRRsets(ctx context.Context, s *identity.Subject, zone string, changes []uiapi.RRsetChange) (*uiapi.PlanResult, error)
	ApplyRRsets(ctx context.Context, s *identity.Subject, zone string, changes []uiapi.RRsetChange, zoneVersion int64) (*uiapi.PlanResult, error)
}

// TerraformFilter selects the managed RRsets exported as HCL.
type TerraformFilter struct {
	// Provider is the Terraform provider targeted (default dnsgate).
	Provider tfexport.Provider
	Team     string
	Hosts    []string
	Types    []string
	RRsets   []uiapi.RRsetRef // exact selection, takes precedence over Hosts and Types
}

// TerraformRenderer renders the managed RRsets of a zone as Terraform.
type TerraformRenderer func(ctx context.Context, s *identity.Subject, zone string, f TerraformFilter) (string, error)

// handleZoneOps serves /api/v1/zones/{zone}/adopt[/preview] and
// /api/v1/zones/{zone}/terraform?provider=dnsgate|eurodns. op is the path
// after the zone.
func (s *Server) handleZoneOps(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session, zone string, op string) {
	zone = strings.ToLower(zone)
	if !config.ValidFQDN(zone) || !s.pol.Managed(zone) {
		writeError(w, http.StatusNotFound, "not_found", "unknown zone")
		return
	}
	switch {
	case op == "terraform" && r.Method == http.MethodGet:
		s.serveTerraform(w, r, subj, zone)
	case (op == "adopt/preview" || op == "adopt") && r.Method == http.MethodPost:
		if s.cfg.Ops == nil {
			writeError(w, http.StatusNotImplemented, "not_implemented", "adoption is not available")
			return
		}
		if !s.cfg.Authz.Allow(subj, policy.ActionRecordAdopt, zone) {
			s.audit(r, subj, "adopt", zone, "deny", "forbidden")
			writeError(w, http.StatusForbidden, "forbidden", "dns.record.adopt not granted on "+zone)
			return
		}
		if op == "adopt/preview" {
			var sel uiapi.AdoptSelection
			if e := decodeStrict(r, &sel); e != nil {
				s.writePolicyError(w, e)
				return
			}
			p, err := s.cfg.Ops.PreviewAdopt(r.Context(), subj, zone, sel)
			if err != nil {
				s.opsError(w, r, subj, "adopt.preview", zone, err)
				return
			}
			writeJSON(w, http.StatusOK, p)
			return
		}
		if e := s.stepUp(subj, sess); e != nil {
			s.writePolicyError(w, e)
			return
		}
		var req uiapi.AdoptApply
		if e := decodeStrict(r, &req); e != nil {
			s.writePolicyError(w, e)
			return
		}
		if strings.TrimSpace(req.Comment) == "" || len(req.Comment) > 2000 {
			writeError(w, http.StatusBadRequest, "bad_request", "a comment (up to 2000 characters) is required")
			return
		}
		if len(req.RRsets) == 0 || req.PreviewToken == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "rrsets and preview_token are required")
			return
		}
		res, err := s.cfg.Ops.AdoptMany(r.Context(), subj, zone, req)
		if err != nil {
			s.opsError(w, r, subj, "adopt", zone, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	}
}

func (s *Server) serveTerraform(w http.ResponseWriter, r *http.Request, subj *identity.Subject, zone string) {
	if !s.cfg.Authz.Allow(subj, policy.ActionUIRead, zone) {
		writeError(w, http.StatusForbidden, "forbidden", "ui.read not granted on "+zone)
		return
	}
	if s.cfg.Terraform == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "terraform export is not available")
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		switch {
		case (k == "team" || k == "provider") && len(v) == 1:
		case k == "hosts" || k == "types" || k == "rrsets":
		default:
			writeError(w, http.StatusBadRequest, "bad_request", "unknown or repeated query parameter "+k)
			return
		}
	}
	// hosts, types and rrsets accept comma-separated values and repeated parameters.
	prov, ok := tfexport.ParseProvider(q.Get("provider"))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "provider must be dnsgate or eurodns")
		return
	}
	f := TerraformFilter{Provider: prov, Team: q.Get("team"), Hosts: splitAll(q["hosts"]), Types: splitAll(q["types"])}
	for i := range f.Types {
		f.Types[i] = strings.ToUpper(f.Types[i])
	}
	for _, ref := range splitAll(q["rrsets"]) {
		host, typ, ok := strings.Cut(ref, "/")
		if !ok || host == "" || typ == "" || strings.Contains(typ, "/") {
			writeError(w, http.StatusBadRequest, "bad_request", "rrsets must be host/type pairs, e.g. www/A,@/MX")
			return
		}
		f.RRsets = append(f.RRsets, uiapi.RRsetRef{Host: strings.ToLower(host), Type: strings.ToUpper(typ)})
	}
	hcl, err := s.cfg.Terraform(r.Context(), subj, zone, f)
	if err != nil {
		s.opsError(w, r, subj, "terraform", zone, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tf"`, strings.ReplaceAll(zone, ".", "_")))
	_, _ = w.Write([]byte(hcl))
}

// opsError maps engine errors (zonewrite reasons, adopt_conflict) to HTTP.
func (s *Server) opsError(w http.ResponseWriter, r *http.Request, subj *identity.Subject, action, zone string, err error) {
	m := &matchInfo{op: action, zone: zone}
	s.engineError(w, r, subj, m.match(), err)
}

func splitAll(vs []string) []string {
	var out []string
	for _, v := range vs {
		out = append(out, splitList(v)...)
	}
	return out
}

func splitList(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type matchInfo struct{ op, zone string }

func (m *matchInfo) match() *routes.Match {
	return &routes.Match{Operation: routes.Operation{ID: m.op}, Zone: m.zone}
}

// InventoryTerraform renders the managed RRsets of the engine inventory
// with tfexport (filters: owner team, host globs, types).
func InventoryTerraform(e Engine) TerraformRenderer {
	return func(ctx context.Context, s *identity.Subject, zone string, f TerraformFilter) (string, error) {
		inv, err := e.Inventory(ctx, s, zone)
		if err != nil {
			return "", err
		}
		var sets []dns.RRset
		for _, r := range inv.RRsets {
			if r.Status != uiapi.StatusManaged || (f.Team != "" && r.Owner != f.Team) {
				continue
			}
			if len(f.RRsets) > 0 {
				if !selected(f.RRsets, r.Host, r.Type) {
					continue
				}
			} else {
				if len(f.Hosts) > 0 && !glob.Any(f.Hosts, r.Host) {
					continue
				}
				if len(f.Types) > 0 && !containsFold(f.Types, r.Type) {
					continue
				}
			}
			sets = append(sets, dns.RRset{Key: dns.Key{Host: r.Host, Type: r.Type}, TTL: r.TTL, Values: r.Values, Alias: r.Alias, Forward: r.Forward, ReadOnly: r.ReadOnly})
		}
		header := []string{"Managed RRsets exported by dns-gate " + version.Version + "."}
		if f.Team != "" {
			header = append(header, "Owner team: "+f.Team+".")
		}
		return tfexport.Render(zone, sets, tfexport.Options{Provider: f.Provider, Header: header}), nil
	}
}

func selected(refs []uiapi.RRsetRef, host, typ string) bool {
	for _, ref := range refs {
		h := strings.TrimSuffix(ref.Host, ".")
		if h == "" {
			h = "@"
		}
		if strings.EqualFold(h, host) && strings.EqualFold(ref.Type, typ) {
			return true
		}
	}
	return false
}

func containsFold(ss []string, s string) bool {
	for _, x := range ss {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
