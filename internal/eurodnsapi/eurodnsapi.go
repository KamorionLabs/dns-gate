// Package eurodnsapi is the EuroDNS-compatible API of the gate: the
// operations of the EuroDNS REST API that EuroDNS clients (the eurodns
// Terraform provider, lego, scripts) call, served for the zones of a
// provider of kind eurodns. Writes go through the provider-neutral engine
// (package zonewrite) with every business rule; the full-zone PUT keeps
// the URL and mail forwards, DomainConnect and unknown fields of the zone.
// Other read operations are proxied to the EuroDNS account of the zone.
package eurodnsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/version"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
	api "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// Config wires the facade.
type Config struct {
	Engine    zonewrite.Engine
	Authz     policy.Authorizer
	Providers provider.Resolver
	// Accounts are the configured providers, for the account-wide
	// operations (zone profiles) that name no zone.
	Accounts []provider.Provider
	// ZoneProfiles are the ids of the EuroDNS providers whose zone profiles
	// the gate serves (providers[].eurodns.zone_profiles).
	ZoneProfiles map[string]bool
	Log          *slog.Logger
}

// Facade serves the EuroDNS-compatible API. Safe for concurrent use.
type Facade struct {
	cfg     Config
	mu      sync.Mutex
	proxies map[string]http.Handler
}

// New builds the facade.
func New(cfg Config) *Facade {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Facade{cfg: cfg, proxies: map[string]http.Handler{}}
}

// Call is one engine-backed EuroDNS operation.
type Call struct {
	Op      string // operation id: getDnsZone, saveDnsZone, checkDnsZone, addDnsRecords, deleteDnsRecord
	Zone    string
	Params  map[string]string // validated path parameters
	Body    json.RawMessage   // request body, already checked to be JSON
	IfMatch string
}

// Reply is the response of a Call: Body is written as JSON unless nil.
type Reply struct {
	Status int
	ETag   string
	Body   any
}

// BadRequestError is a request the facade cannot decode.
type BadRequestError struct{ Message string }

func (e *BadRequestError) Error() string { return "bad request: " + e.Message }

func etag(v int64) string { return fmt.Sprintf("\"v%d\"", v) }

func notEuroDNS(zone string, p provider.Provider) *zonewrite.Error {
	return &zonewrite.Error{Reason: zonewrite.ReasonNotFound,
		Message: fmt.Sprintf("zone %s is served by provider %s (%s): the EuroDNS API only serves EuroDNS zones, use /api/v1", zone, p.ID(), p.Kind())}
}

// provider returns the EuroDNS provider of zone.
func (f *Facade) provider(zone string) (*eurodnsprov.Provider, error) {
	zone = dns.NormalizeZone(zone)
	p, err := f.cfg.Providers.Provider(zone)
	if err != nil {
		return nil, &zonewrite.Error{Reason: zonewrite.ReasonNotFound, Message: "no provider for zone " + zone + ": " + err.Error(), Err: err}
	}
	ep, ok := p.(*eurodnsprov.Provider)
	if !ok {
		return nil, notEuroDNS(zone, p)
	}
	return ep, nil
}

// Serves reports whether zone is served by a EuroDNS provider.
func (f *Facade) Serves(zone string) bool {
	_, err := f.provider(zone)
	return err == nil
}

// Do runs an engine-backed operation.
func (f *Facade) Do(ctx context.Context, s *identity.Subject, c Call) (*Reply, error) {
	switch c.Op {
	case "getDnsZone":
		z, err := f.GetZone(ctx, s, c.Zone)
		if err != nil {
			return nil, err
		}
		return &Reply{Status: http.StatusOK, ETag: z.ETag, Body: z}, nil
	case "checkDnsZone":
		var z api.Zone
		if err := decode(c.Body, &z); err != nil {
			return nil, err
		}
		out, err := f.CheckZone(ctx, s, c.Zone, &z)
		if err != nil {
			return nil, err
		}
		return &Reply{Status: http.StatusOK, Body: out}, nil
	case "saveDnsZone":
		var z api.Zone
		if err := decode(c.Body, &z); err != nil {
			return nil, err
		}
		if err := f.SaveZone(ctx, s, c.Zone, &z, c.IfMatch); err != nil {
			return nil, err
		}
		return &Reply{Status: http.StatusNoContent}, nil
	case "addDnsRecords":
		var recs []api.Record
		if err := decode(c.Body, &recs); err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return nil, &BadRequestError{Message: "at least one record is required"}
		}
		z, err := f.AddRecords(ctx, s, c.Zone, recs, c.IfMatch)
		if err != nil {
			return nil, err
		}
		return &Reply{Status: http.StatusOK, ETag: z.ETag, Body: z}, nil
	case "deleteDnsRecord":
		id, err := parseInt64(c.Params["record-id"])
		if err != nil {
			return nil, &BadRequestError{Message: "invalid record id"}
		}
		z, err := f.DeleteRecord(ctx, s, c.Zone, id, c.IfMatch)
		if err != nil {
			return nil, err
		}
		return &Reply{Status: http.StatusOK, ETag: z.ETag, Body: z}, nil
	}
	return nil, &zonewrite.Error{Reason: zonewrite.ReasonForbidden, Message: "operation not allowed by the gate"}
}

func decode(body json.RawMessage, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return &BadRequestError{Message: "invalid JSON body"}
	}
	return nil
}

func parseInt64(s string) (int64, error) {
	var n int64
	if s == "" || len(s) > 19 {
		return 0, fmt.Errorf("invalid")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return 0, fmt.Errorf("overflow")
		}
	}
	return n, nil
}

// withETag returns a copy of a native zone with the gate zone version.
func withETag(z *api.Zone, v int64) *api.Zone {
	cp := *z
	cp.ETag = etag(v)
	return &cp
}

// GetZone returns the upstream zone with ETag set to the gate zone version.
func (f *Facade) GetZone(ctx context.Context, s *identity.Subject, zone string) (*api.Zone, error) {
	if _, err := f.provider(zone); err != nil {
		return nil, err
	}
	z, v, err := f.cfg.Engine.ReadZone(ctx, s, zone, "getDnsZone")
	if err != nil {
		return nil, err
	}
	n, err := eurodnsprov.Native(z)
	if err != nil {
		return nil, err
	}
	return withETag(n, v), nil
}

// CheckZone runs the EuroDNS check on a client zone (dns.read).
func (f *Facade) CheckZone(ctx context.Context, s *identity.Subject, zone string, z *api.Zone) (*api.Zone, error) {
	ep, err := f.provider(zone)
	if err != nil {
		return nil, err
	}
	if _, err := f.cfg.Engine.Authorize(ctx, s, zone, policy.ActionDNSRead, "checkDnsZone"); err != nil {
		return nil, err
	}
	out, err := ep.Client().CheckZone(ctx, dns.NormalizeZone(zone), z)
	if err != nil {
		return nil, zonewrite.ProviderError("check zone", eurodnsprov.Wrap("check zone", err))
	}
	return out, nil
}

// write runs build through the engine and returns the zone read back after
// the write, or the zone as saved when that read failed.
func (f *Facade) write(ctx context.Context, s *identity.Subject, zone, ifMatch, action string,
	build func(name string, cur *api.Zone) (*zonewrite.Plan, error)) (*api.Zone, error) {
	if _, err := f.provider(zone); err != nil {
		return nil, err
	}
	var base *dns.Zone
	var plan *zonewrite.Plan
	after, v, err := f.cfg.Engine.Write(ctx, s, zone, ifMatch, action, func(cur *dns.Zone) (*zonewrite.Plan, error) {
		n, err := eurodnsprov.Native(cur)
		if err != nil {
			return nil, err
		}
		base = cur
		plan, err = build(cur.Name, n)
		if err == nil && plan.Base != nil {
			base = plan.Base
		}
		return plan, err
	})
	if err != nil {
		return nil, err
	}
	if after != nil {
		n, err := eurodnsprov.Native(after)
		if err != nil {
			return nil, err
		}
		return withETag(n, v), nil
	}
	var changes []dns.Change
	if plan != nil {
		changes = plan.Changes
	}
	desired, err := eurodnsprov.Desired(zone, base, changes)
	if err != nil {
		return nil, err
	}
	return withETag(desired, v), nil
}

func toSet(s *rrset.Set) *dns.RRset {
	if s == nil {
		return nil
	}
	return &dns.RRset{Key: dns.Key{Host: s.Key.Host, Type: s.Key.Type}, TTL: s.TTL, Values: slices.Clone(s.Values), Native: s.Records}
}

func toChange(c zonediff.Change) dns.Change {
	return dns.Change{Op: dns.Op(c.Op), Key: dns.Key{Host: c.Key.Host, Type: c.Key.Type}, Old: toSet(c.Old), New: toSet(c.New)}
}

func keyString(k rrset.Key) string { return k.Host + " " + k.Type }

func fail(r zonewrite.Reason, format string, a ...any) *zonewrite.Error {
	return &zonewrite.Error{Reason: r, Message: fmt.Sprintf(format, a...)}
}

// userSets groups the records that are not managed by EuroDNS (SOA, locked).
func userSets(zone string, recs []api.Record) map[rrset.Key]rrset.Set {
	user := make([]api.Record, 0, len(recs))
	for _, r := range recs {
		if !rrset.ServerManaged(r) {
			user = append(user, r)
		}
	}
	return rrset.Group(zone, user)
}

func findSet(sets map[rrset.Key]rrset.Set, k rrset.Key) (rrset.Set, rrset.Key, bool) {
	if s, ok := sets[k]; ok {
		return s, k, true
	}
	for key, s := range sets {
		if key.Host == k.Host && strings.EqualFold(key.Type, k.Type) {
			return s, key, true
		}
	}
	return rrset.Set{}, k, false
}

// newSet builds an RRset from records, forcing a uniform TTL.
func newSet(key rrset.Key, ttl int, recs []api.Record) rrset.Set {
	out := rrset.Set{Key: key, TTL: ttl}
	for _, r := range recs {
		r.TTL = ttl
		out.Records = append(out.Records, r)
		out.Values = append(out.Values, r.RData)
	}
	sort.Strings(out.Values)
	return out
}

// SaveZone handles a full-zone PUT: delta computed against the current zone
// under lock; out-of-scope differences are refused, except for subjects
// whose role sets rebase (ACME clients), where they are ignored. URL
// forward changes are forward writes (dns.forward.write, ownership); a
// dns.zone.admin holder may also change the forwards the gate does not own,
// as before forwards were owned. Mail forwards and other zone settings
// require dns.zone.admin.
func (f *Facade) SaveZone(ctx context.Context, s *identity.Subject, zone string, z *api.Zone, ifMatch string) error {
	if z == nil {
		return fail(zonewrite.ReasonInvalid, "empty zone")
	}
	rebase := f.cfg.Authz.RebaseOnSave(s)
	_, err := f.write(ctx, s, zone, ifMatch, "saveDnsZone", func(name string, cur *api.Zone) (*zonewrite.Plan, error) {
		d := zonediff.Diff(name, cur, z)
		plan := &zonewrite.Plan{Settings: d.OtherChanged || !sameRawList(cur.MailForwards, z.MailForwards), ForeignForwards: true}
		for _, c := range d.Changes {
			if f.cfg.Authz.AllowRRset(s, policy.ActionRecordWrite, name, dns.Key{Host: c.Key.Host, Type: c.Key.Type}) {
				plan.Changes = append(plan.Changes, toChange(c))
				continue
			}
			if !rebase {
				return nil, fail(zonewrite.ReasonForbidden, "not allowed to write %s in %s", keyString(c.Key), name)
			}
			plan.Ignored = append(plan.Ignored, string(c.Op)+" "+keyString(c.Key))
		}
		fwd := forwardChanges(name, cur, z)
		for _, h := range fwd.Duplicates {
			if !rebase {
				return nil, fail(zonewrite.ReasonInvalid, "several URL forwards for host %s: the gate does not change a host holding several forwards, send them unchanged or fix them at the provider", h)
			}
			plan.Ignored = append(plan.Ignored, "forwards of "+h+" (several entries)")
		}
		for _, h := range fwd.Unwritten {
			plan.Ignored = append(plan.Ignored, "forward "+h+": fields the gate does not write (id, updated, unknown fields)")
		}
		for _, c := range fwd.Changes {
			if f.cfg.Authz.AllowRRset(s, policy.ActionForwardWrite, name, c.Key) || f.cfg.Authz.AllowRRset(s, policy.ActionZoneAdmin, name, c.Key) {
				plan.Changes = append(plan.Changes, c)
				continue
			}
			if !rebase {
				return nil, fail(zonewrite.ReasonForbidden, "not allowed to write %s in %s", c.Key.Host+" "+c.Key.Type, name)
			}
			plan.Ignored = append(plan.Ignored, string(c.Op)+" "+c.Key.Host+" "+c.Key.Type)
		}
		if rebase && plan.Settings {
			plan.Ignored = append(plan.Ignored, "mail forwards/zone settings")
			plan.Settings = false
		}
		if plan.Settings {
			nb := *cur
			nb.MailForwards = z.MailForwards
			nb.DomainConnect, nb.Extra = z.DomainConnect, z.Extra
			plan.Base = eurodnsprov.FromNative("", name, &nb)
		}
		return plan, nil
	})
	return err
}

// forwardDelta is the URL forward part of a full-zone PUT.
type forwardDelta struct {
	// Changes are the neutral changes of the forward RRsets.
	Changes []dns.Change
	// Unwritten lists the hosts whose entries differ only in fields the
	// gate does not write (id, updated, unknown fields, formatting).
	Unwritten []string
	// Duplicates lists the hosts the client changes while they hold, or
	// would hold, several forwards.
	Duplicates []string
}

// forwardChanges compares the URL forwards of cur and desired host by host.
// A host whose entries are the same (canonical JSON, order kept) is no
// change, duplicates included; otherwise its forward RRsets are compared
// by content hash.
func forwardChanges(zone string, cur, desired *api.Zone) forwardDelta {
	group := func(raws []json.RawMessage) map[string][]string {
		out := map[string][]string{}
		for _, raw := range raws {
			var e struct {
				Host *string `json:"host"`
			}
			_ = json.Unmarshal(raw, &e)
			host := "@"
			if e.Host != nil {
				host = dns.NormalizeHost(*e.Host, zone)
			}
			out[host] = append(out[host], canonical(raw))
		}
		return out
	}
	forwards := func(z *api.Zone) map[dns.Key]dns.RRset {
		out := map[dns.Key]dns.RRset{}
		for _, s := range eurodnsprov.FromNative("", zone, &api.Zone{URLForwards: z.URLForwards}).RRsets {
			if s.Key.IsForward() {
				out[s.Key] = s
			}
		}
		return out
	}
	oldRaw, newRaw := group(cur.URLForwards), group(desired.URLForwards)
	old, next := forwards(cur), forwards(desired)
	hosts := make([]string, 0, len(oldRaw)+len(newRaw))
	for h := range oldRaw {
		hosts = append(hosts, h)
	}
	for h := range newRaw {
		if _, ok := oldRaw[h]; !ok {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	var d forwardDelta
	for _, h := range hosts {
		if slices.Equal(oldRaw[h], newRaw[h]) {
			continue
		}
		if len(oldRaw[h]) > 1 || len(newRaw[h]) > 1 {
			d.Duplicates = append(d.Duplicates, h)
			continue
		}
		k := dns.ForwardKey(h)
		o, hasOld := old[k]
		n, hasNew := next[k]
		switch {
		case hasOld && hasNew && dns.ContentHash(o) == dns.ContentHash(n):
			d.Unwritten = append(d.Unwritten, h)
		case hasOld && hasNew:
			d.Changes = append(d.Changes, dns.Change{Op: dns.OpUpdate, Key: k, Old: &o, New: &n})
		case hasOld:
			d.Changes = append(d.Changes, dns.Change{Op: dns.OpDelete, Key: k, Old: &o})
		default:
			d.Changes = append(d.Changes, dns.Change{Op: dns.OpCreate, Key: k, New: &n})
		}
	}
	return d
}

func canonical(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// sameRawList compares two lists of JSON values, ignoring formatting.
func sameRawList(a, b []json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if canonical(a[i]) != canonical(b[i]) {
			return false
		}
	}
	return true
}

// AddRecords adds records to their RRsets (POST dns-records).
func (f *Facade) AddRecords(ctx context.Context, s *identity.Subject, zone string, recs []api.Record, ifMatch string) (*api.Zone, error) {
	if len(recs) == 0 {
		return nil, fail(zonewrite.ReasonInvalid, "no records")
	}
	return f.write(ctx, s, zone, ifMatch, "addDnsRecords", func(name string, cur *api.Zone) (*zonewrite.Plan, error) {
		sets := userSets(name, cur.Records)
		clean := make([]api.Record, 0, len(recs))
		for _, r := range recs {
			clean = append(clean, api.Record{Type: r.Type, Host: r.Host, TTL: r.TTL, RData: r.RData, IsDynDNS: r.IsDynDNS, Proxy: r.Proxy, Extra: r.Extra})
		}
		requested := rrset.Group(name, clean)
		plan := &zonewrite.Plan{}
		for _, k := range rrset.SortedKeys(requested) {
			req := requested[k]
			old, key, exists := findSet(sets, k)
			if !exists {
				n := newSet(k, req.TTL, req.Records)
				plan.Changes = append(plan.Changes, toChange(zonediff.Change{Op: zonediff.OpCreate, Key: k, New: &n}))
				continue
			}
			merged := slices.Clone(old.Records)
			added := false
			for _, r := range req.Records {
				if !slices.Contains(old.Values, r.RData) {
					merged = append(merged, r)
					added = true
				}
			}
			if !added && req.TTL == old.TTL {
				continue
			}
			o := old
			n := newSet(key, req.TTL, merged)
			plan.Changes = append(plan.Changes, toChange(zonediff.Change{Op: zonediff.OpUpdate, Key: key, Old: &o, New: &n}))
		}
		return plan, nil
	})
}

// DeleteRecord deletes one record by id (DELETE dns-records/{id}).
func (f *Facade) DeleteRecord(ctx context.Context, s *identity.Subject, zone string, id int64, ifMatch string) (*api.Zone, error) {
	return f.write(ctx, s, zone, ifMatch, "deleteDnsRecord", func(name string, cur *api.Zone) (*zonewrite.Plan, error) {
		var target *api.Record
		for i := range cur.Records {
			if r := cur.Records[i]; r.ID != nil && *r.ID == id {
				target = &cur.Records[i]
				break
			}
		}
		if target == nil {
			return nil, fail(zonewrite.ReasonNotFound, "record %d not found in %s", id, name)
		}
		if rrset.ServerManaged(*target) {
			return nil, fail(zonewrite.ReasonForbidden, "record %d is managed by EuroDNS (SOA or locked record)", id)
		}
		sets := userSets(name, cur.Records)
		old, key, ok := findSet(sets, rrset.KeyOf(name, *target))
		if !ok {
			return nil, fail(zonewrite.ReasonNotFound, "record %d not found in %s", id, name)
		}
		var rest []api.Record
		for _, r := range old.Records {
			if r.ID == nil || *r.ID != id {
				rest = append(rest, r)
			}
		}
		o := old
		if len(rest) == 0 {
			return &zonewrite.Plan{Changes: []dns.Change{toChange(zonediff.Change{Op: zonediff.OpDelete, Key: key, Old: &o})}}, nil
		}
		n := newSet(key, old.TTL, rest)
		return &zonewrite.Plan{Changes: []dns.Change{toChange(zonediff.Change{Op: zonediff.OpUpdate, Key: key, Old: &o, New: &n})}}, nil
	})
}

// Adopt serves POST /.well-known/dns-gate/zones/{zone}/adopt for a EuroDNS
// zone (Terraform import in gate mode).
func (f *Facade) Adopt(ctx context.Context, s *identity.Subject, zone string, req api.AdoptRequest) error {
	if _, err := f.provider(zone); err != nil {
		return err
	}
	refs := make([]uiapi.RRsetRef, 0, len(req.RRsets))
	for _, r := range req.RRsets {
		refs = append(refs, uiapi.RRsetRef{Host: r.Host, Type: r.Type})
	}
	return f.cfg.Engine.Adopt(ctx, s, zone, refs, req.Owner)
}

// AdoptJSON decodes an adopt request body and runs Adopt.
func (f *Facade) AdoptJSON(ctx context.Context, s *identity.Subject, zone string, body json.RawMessage) error {
	var req api.AdoptRequest
	if err := decode(body, &req); err != nil {
		return err
	}
	if len(req.RRsets) == 0 {
		return &BadRequestError{Message: "rrsets required"}
	}
	return f.Adopt(ctx, s, zone, req)
}

type pathKey struct{}

// forwardedHeaders are the only client headers sent upstream.
var forwardedHeaders = []string{"Accept", "Content-Type"}

// Proxy forwards an authorized passthrough request to the EuroDNS account of
// zone; path is the validated upstream path. The request body is never
// forwarded.
func (f *Facade) Proxy(w http.ResponseWriter, r *http.Request, zone, path string) {
	ep, err := f.provider(zone)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	h, err := f.proxy(ep)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream", "invalid EuroDNS base URL")
		return
	}
	h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), pathKey{}, path)))
}

func (f *Facade) proxy(ep *eurodnsprov.Provider) (http.Handler, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.proxies[ep.ID()]; ok {
		return h, nil
	}
	up, err := url.Parse(ep.BaseURL())
	if err != nil {
		return nil, err
	}
	h := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			path, _ := pr.In.Context().Value(pathKey{}).(string)
			out := pr.Out
			out.URL.Scheme = up.Scheme
			out.URL.Host = up.Host
			out.URL.Path = strings.TrimSuffix(up.Path, "/") + path
			out.URL.RawPath = ""
			out.URL.RawQuery = ""
			out.Host = up.Host
			hd := http.Header{}
			for _, k := range forwardedHeaders {
				if v := pr.In.Header.Get(k); v != "" {
					hd.Set(k, v)
				}
			}
			hd.Set("User-Agent", "dns-gate/"+version.Version)
			out.Header = hd
			out.Body = http.NoBody
			out.ContentLength = 0
		},
		Transport: ep.Transport(),
		ModifyResponse: func(resp *http.Response) error {
			for _, k := range []string{"Set-Cookie", "Server", "X-Powered-By"} {
				resp.Header.Del(k)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f.cfg.Log.Warn("upstream proxy error", "request_id", requestid.From(r.Context()), "provider", ep.ID(), "err", err)
			writeError(w, http.StatusBadGateway, "upstream", "EuroDNS is unreachable")
		},
	}
	f.proxies[ep.ID()] = h
	return h, nil
}

func writeError(w http.ResponseWriter, status int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason, "message": msg})
}
