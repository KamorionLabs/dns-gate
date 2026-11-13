// Package scaleway is the Scaleway Domains and DNS provider adapter
// (API domain/v2beta1). One Provider fronts the DNS zones a Scaleway API
// key can see, optionally limited to a project.
//
// Scaleway stores one record per value. Apply reads the records of each
// changed RRset again, refuses the write when they differ from the RRset
// the change was computed against, then sends every record change of the
// Apply in one PATCH of the zone.
package scaleway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/provider/rdata"
	"github.com/KamorionLabs/dns-gate/internal/provider/restapi"
)

// Kind is the adapter kind of Scaleway providers.
const Kind = "scaleway"

// DefaultBaseURL is the Scaleway API.
const DefaultBaseURL = "https://api.scaleway.com"

const (
	apiPath        = "/domain/v2beta1"
	pageSize       = 100
	maxPages       = 1000
	defaultRetries = 3
)

var rules = rdata.Rules{
	Provider: Kind,
	Types: map[string]bool{
		"A": true, "AAAA": true, "CAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SRV": true, "SSHFP": true, "TLSA": true, "TXT": true,
	},
	MinTTL: 60,
	MaxTTL: 2592000,
}

// Config is the configuration of one Scaleway provider instance.
type Config struct {
	// SecretKey is the secret key of the API key (X-Auth-Token).
	SecretKey string
	// ProjectID and OrganizationID, when set, limit the zones listed.
	ProjectID      string
	OrganizationID string
	// BaseURL replaces DefaultBaseURL (tests).
	BaseURL string
	// MaxRetries of a request that may be sent again; 3 when nil.
	MaxRetries *int
	UserAgent  string
	HTTP       *http.Client
}

// Provider is the Scaleway implementation of provider.Provider.
type Provider struct {
	id   string
	cfg  Config
	base string
	api  *restapi.Client
}

var _ provider.Provider = (*Provider)(nil)

// New returns the Scaleway provider instance id. It makes no API call.
func New(id string, cfg Config) (*Provider, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("scaleway: provider id is empty")
	}
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("scaleway %s: no secret key", id)
	}
	base := DefaultBaseURL
	if cfg.BaseURL != "" {
		base = strings.TrimRight(cfg.BaseURL, "/")
	}
	retries := defaultRetries
	if cfg.MaxRetries != nil {
		retries = *cfg.MaxRetries
	}
	p := &Provider{id: id, cfg: cfg, base: base + apiPath}
	p.api = &restapi.Client{HTTP: cfg.HTTP, UserAgent: cfg.UserAgent, MaxRetries: retries,
		Auth: func(_ context.Context, req *http.Request, _ []byte) error {
			req.Header.Set("X-Auth-Token", cfg.SecretKey)
			return nil
		}}
	return p, nil
}

// ID returns the instance id from the configuration.
func (p *Provider) ID() string { return p.id }

// Kind returns "scaleway".
func (p *Provider) Kind() string { return Kind }

// Capabilities: writes checked against the content read, TTL from 60
// seconds to 30 days. The changes of an Apply go in one request, but the
// adapter does not rely on Scaleway applying it atomically.
func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		ConditionalWrite: true,
		Types:            rules.TypeList(),
		MinTTL:           rules.MinTTL,
		MaxTTL:           rules.MaxTTL,
	}
}

// Normalize validates a desired RRset, see rdata.Rules.Normalize.
func (p *Provider) Normalize(zone string, set dns.RRset) (dns.RRset, error) {
	return rules.Normalize(zone, set)
}

type dnsZone struct {
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain"`
}

// ListZones returns the DNS zones the key can see: the root zone of each
// domain and its sub-zones ("sub.example.com").
func (p *Provider) ListZones(ctx context.Context) ([]string, error) {
	var out []string
	seen := 0
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}, "order_by": {"domain_asc"}}
		if p.cfg.ProjectID != "" {
			q.Set("project_id", p.cfg.ProjectID)
		}
		if p.cfg.OrganizationID != "" {
			q.Set("organization_id", p.cfg.OrganizationID)
		}
		var resp struct {
			TotalCount int       `json:"total_count"`
			Zones      []dnsZone `json:"dns_zones"`
		}
		if _, err := p.api.JSON(ctx, http.MethodGet, p.base+"/dns-zones?"+q.Encode(), nil, nil, &resp); err != nil {
			return nil, fmt.Errorf("scaleway %s: list zones: %w", p.id, err)
		}
		for _, z := range resp.Zones {
			name := z.Domain
			if z.Subdomain != "" {
				name = z.Subdomain + "." + z.Domain
			}
			if n := dns.NormalizeZone(name); n != "" {
				out = append(out, n)
			}
		}
		seen += len(resp.Zones)
		if len(resp.Zones) == 0 || seen >= resp.TotalCount {
			break
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// record is a Scaleway DNS record.
type record struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Data     string `json:"data"`
	Priority uint32 `json:"priority"`
	TTL      uint32 `json:"ttl"`
	// Dynamic records (answers computed by Scaleway) are read-only.
	GeoIP    json.RawMessage `json:"geo_ip_config,omitempty"`
	HTTP     json.RawMessage `json:"http_service_config,omitempty"`
	Weighted json.RawMessage `json:"weighted_config,omitempty"`
	View     json.RawMessage `json:"view_config,omitempty"`
}

func set(m json.RawMessage) bool { return len(m) > 0 && string(m) != "null" }

func (r record) dynamic() bool { return set(r.GeoIP) || set(r.HTTP) || set(r.Weighted) || set(r.View) }

func (p *Provider) recordsURL(zone string) string {
	return p.base + "/dns-zones/" + url.PathEscape(zone) + "/records"
}

func (p *Provider) zoneError(zone, op string, err error) error {
	if restapi.Status(err) == http.StatusNotFound {
		return fmt.Errorf("%w: %s in scaleway %s", provider.ErrZoneNotFound, zone, p.id)
	}
	return fmt.Errorf("scaleway %s: %s of %s: %w", p.id, op, zone, err)
}

// listRecords returns the records of a zone, or with filter those of one
// name and type (the filter is checked again by the caller).
func (p *Provider) listRecords(ctx context.Context, zone string, filter *dns.Key) ([]record, error) {
	var out []record
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}, "order_by": {"name_asc"}}
		if filter != nil {
			q.Set("type", filter.Type)
			if filter.Host != dns.Apex {
				q.Set("name", filter.Host)
			}
		}
		var resp struct {
			TotalCount int      `json:"total_count"`
			Records    []record `json:"records"`
		}
		if _, err := p.api.JSON(ctx, http.MethodGet, p.recordsURL(zone)+"?"+q.Encode(), nil, nil, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Records...)
		if len(resp.Records) == 0 || len(out) >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// canonical converts a Scaleway record: the priority of MX and SRV records
// is a field of its own, names are absolute or relative to the zone.
func canonical(zone string, n record) rdata.Record[record] {
	typ := strings.ToUpper(n.Type)
	r := rdata.Record[record]{Key: dns.Key{Host: dns.NormalizeHost(n.Name, zone), Type: typ}, TTL: int(n.TTL), Native: n}
	data := n.Data
	fields := len(strings.Fields(data))
	if (typ == "MX" && fields == 1) || (typ == "SRV" && fields == 3) {
		data = strconv.FormatUint(uint64(n.Priority), 10) + " " + data
	}
	v, err := rdata.CanonicalIn(zone, typ, data)
	switch {
	case n.dynamic():
		r.ReadOnly = rdata.ReadOnlyRoutingPolicy
	case typ == "ALIAS":
		r.ReadOnly = rdata.ReadOnlyAlias
	case err != nil:
		r.ReadOnly = rdata.ReadOnlyUnreadable
	}
	if err != nil {
		v = rdata.Loose(data)
		if typ == "ALIAS" {
			if name, nerr := rdata.CanonName(data); nerr == nil {
				v = name
			}
		}
	}
	r.Value = v
	return r
}

// ReadZone returns the records of the zone as RRsets. The apex NS are
// read-only "server_managed", dynamic records (geo IP, HTTP service,
// weighted, views) "routing_policy" and ALIAS records "alias".
func (p *Provider) ReadZone(ctx context.Context, zone string) (*dns.Zone, error) {
	name := dns.NormalizeZone(zone)
	native, err := p.listRecords(ctx, name, nil)
	if err != nil {
		return nil, p.zoneError(name, "list records", err)
	}
	recs := make([]rdata.Record[record], len(native))
	for i, n := range native {
		recs[i] = canonical(name, n)
	}
	return &dns.Zone{Name: name, Provider: p.id, RRsets: rdata.Group(recs)}, nil
}

// wire converts a canonical value to the data and priority Scaleway stores.
func wire(typ, v string) (string, uint32, error) {
	switch typ {
	case "TXT":
		d, err := rdata.TXTPresentation(typ, v)
		return d, 0, err
	case "MX", "SRV":
		prio, rest, ok := strings.Cut(v, " ")
		n, err := strconv.ParseUint(prio, 10, 16)
		if !ok || err != nil {
			return "", 0, fmt.Errorf("bad %s value %q", typ, v)
		}
		return rest, uint32(n), nil
	}
	return v, 0, nil
}

type idFields struct {
	ID string `json:"id"`
}

type recordChange struct {
	Add *struct {
		Records []record `json:"records"`
	} `json:"add,omitempty"`
	Set *struct {
		ID      string   `json:"id"`
		Records []record `json:"records"`
	} `json:"set,omitempty"`
	Delete *idFields `json:"delete,omitempty"`
}

type patch struct {
	Changes                 []recordChange `json:"changes"`
	ReturnAllRecords        bool           `json:"return_all_records"`
	DisallowNewZoneCreation bool           `json:"disallow_new_zone_creation"`
}

// Apply sends the record changes of every change in one PATCH: records are
// deleted and rewritten by id, new ones added. Before it, the records of
// every changed RRset are read again: a create whose RRset exists, or an
// update or delete whose TTL or values differ from Old, is
// provider.ErrConflict and nothing is sent. A request Scaleway refuses
// writes nothing.
func (p *Provider) Apply(ctx context.Context, zone string, _ *dns.Zone, changes []dns.Change) error {
	if len(changes) == 0 {
		return nil
	}
	name := dns.NormalizeZone(zone)
	var dels, sets, adds []recordChange
	for _, c := range changes {
		key, ttl, diff, err := p.prepare(ctx, name, c)
		if err != nil {
			return err
		}
		newRecord := func(v string) (record, error) {
			data, prio, err := wire(key.Type, v)
			if err != nil {
				return record{}, &provider.InvalidError{Key: key, Message: err.Error()}
			}
			host := key.Host
			if host == dns.Apex {
				host = ""
			}
			return record{Name: host, Type: key.Type, Data: data, Priority: prio, TTL: uint32(ttl)}, nil
		}
		for _, old := range diff.Delete {
			dels = append(dels, recordChange{Delete: &idFields{ID: old.ID}})
		}
		for _, u := range diff.Update {
			r, err := newRecord(u.Value)
			if err != nil {
				return err
			}
			ch := recordChange{}
			ch.Set = &struct {
				ID      string   `json:"id"`
				Records []record `json:"records"`
			}{ID: u.Old.ID, Records: []record{r}}
			sets = append(sets, ch)
		}
		if len(diff.Create) > 0 {
			ch := recordChange{}
			ch.Add = &struct {
				Records []record `json:"records"`
			}{}
			for _, v := range diff.Create {
				r, err := newRecord(v)
				if err != nil {
					return err
				}
				ch.Add.Records = append(ch.Add.Records, r)
			}
			adds = append(adds, ch)
		}
	}
	body := patch{Changes: slices.Concat(dels, sets, adds), DisallowNewZoneCreation: true}
	if len(body.Changes) == 0 {
		return nil
	}
	if _, err := p.api.JSON(ctx, http.MethodPatch, p.recordsURL(name), nil, body, nil); err != nil {
		switch st := restapi.Status(err); {
		case st == http.StatusNotFound:
			return p.zoneError(name, "update records", err)
		case st == http.StatusBadRequest:
			return &provider.RejectedError{Message: "scaleway rejected the changes: " + err.Error()}
		case st != 0:
			return fmt.Errorf("%w: scaleway %s: update records of %s: %v", provider.ErrNotApplied, p.id, name, err)
		}
		return fmt.Errorf("scaleway %s: update records of %s: %w", p.id, name, err)
	}
	return nil
}

func (p *Provider) prepare(ctx context.Context, zone string, c dns.Change) (dns.Key, int, rdata.Diff[record], error) {
	key := dns.Key{Host: dns.NormalizeHost(c.Key.Host, zone), Type: strings.ToUpper(strings.TrimSpace(c.Key.Type))}
	var none rdata.Diff[record]
	bad := func(msg string) (dns.Key, int, rdata.Diff[record], error) {
		return key, 0, none, &provider.InvalidError{Key: key, Message: msg}
	}
	switch c.Op {
	case dns.OpCreate, dns.OpUpdate, dns.OpDelete:
	default:
		return bad(fmt.Sprintf("unknown operation %q", c.Op))
	}
	if c.Op != dns.OpCreate && c.Old == nil {
		return bad(string(c.Op) + " without the current RRset")
	}
	if c.Op != dns.OpDelete && c.New == nil {
		return bad(string(c.Op) + " without the desired RRset")
	}
	if c.Old != nil && c.Old.ReadOnly != "" {
		return bad("read-only RRset (" + c.Old.ReadOnly + ")")
	}
	var want []string
	ttl := 0
	if c.New != nil {
		n, err := p.Normalize(zone, *c.New)
		if err != nil {
			return key, 0, none, err
		}
		if n.Key != key {
			return bad("the desired RRset has another key (" + n.Key.String() + ")")
		}
		want, ttl = n.Values, n.TTL
	} else if !rules.Types[key.Type] {
		return bad("type " + key.Type + " is not supported by the scaleway provider")
	}
	native, err := p.listRecords(ctx, zone, &key)
	if err != nil {
		return key, 0, none, p.zoneError(zone, "read "+key.String(), err)
	}
	var have []rdata.Record[record]
	for _, n := range native {
		if r := canonical(zone, n); r.Key == key {
			have = append(have, r)
		}
	}
	sets := rdata.Group(have)
	switch {
	case c.Op == dns.OpCreate && len(sets) > 0:
		return key, 0, none, fmt.Errorf("%w: %s already exists in %s", provider.ErrConflict, key, zone)
	case c.Op == dns.OpCreate:
	case len(sets) == 1 && sets[0].ReadOnly != "":
		return bad("read-only RRset (" + sets[0].ReadOnly + ")")
	case len(sets) != 1 || sets[0].TTL != c.Old.TTL || !rdata.SameValues(sets[0].Values, c.Old.Values):
		return key, 0, none, fmt.Errorf("%w: %s of %s differs from the zone read", provider.ErrConflict, key, zone)
	}
	return key, ttl, rdata.Plan(have, want, ttl), nil
}
