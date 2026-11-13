// Package infomaniak is the Infomaniak DNS provider adapter (API v2,
// /2/zones/{zone}/records). One Provider fronts the DNS zones of the domains
// an Infomaniak API token can manage.
//
// Infomaniak stores one record per value and has no RRset operation: Apply
// reads the zone again, refuses the write when a changed RRset differs from
// the one the change was computed against, then deletes, rewrites and
// creates records one by one. A write is therefore not atomic.
package infomaniak

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
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/provider/rdata"
	"github.com/KamorionLabs/dns-gate/internal/provider/restapi"
)

// Kind is the adapter kind of Infomaniak providers.
const Kind = "infomaniak"

// DefaultBaseURL is the Infomaniak API.
const DefaultBaseURL = "https://api.infomaniak.com"

const (
	// DefaultEvery paces the requests: Infomaniak limits a token to 60
	// requests per minute.
	DefaultEvery   = time.Second
	defaultRetries = 3
	maxPages       = 1000
	apexSource     = "."
)

var rules = rdata.Rules{
	Provider: Kind,
	Types: map[string]bool{
		"A": true, "AAAA": true, "CAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SRV": true, "TXT": true,
	},
	MinTTL: 60,
	MaxTTL: rdata.MaxTTL,
}

// Config is the configuration of one Infomaniak provider instance.
type Config struct {
	// Token is an API token with the scopes domain:read, dns:read and
	// dns:write.
	Token string
	// Zones, when set, are the zones served: the account is not listed.
	Zones []string
	// BaseURL replaces DefaultBaseURL (tests).
	BaseURL string
	// Every is the minimum time between two requests: DefaultEvery when 0,
	// no pace when negative.
	Every time.Duration
	// MaxRetries of a request that may be sent again; 3 when nil.
	MaxRetries *int
	UserAgent  string
	HTTP       *http.Client
}

// Provider is the Infomaniak implementation of provider.Provider.
type Provider struct {
	id   string
	cfg  Config
	base string
	api  *restapi.Client
}

var _ provider.Provider = (*Provider)(nil)

// New returns the Infomaniak provider instance id. It makes no API call.
func New(id string, cfg Config) (*Provider, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("infomaniak: provider id is empty")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("infomaniak %s: no API token", id)
	}
	base := DefaultBaseURL
	if cfg.BaseURL != "" {
		base = strings.TrimRight(cfg.BaseURL, "/")
	}
	retries := defaultRetries
	if cfg.MaxRetries != nil {
		retries = *cfg.MaxRetries
	}
	every := cfg.Every
	if every == 0 {
		every = DefaultEvery
	}
	zones := make([]string, 0, len(cfg.Zones))
	for _, z := range cfg.Zones {
		if n := dns.NormalizeZone(z); n != "" {
			zones = append(zones, n)
		}
	}
	slices.Sort(zones)
	cfg.Zones = slices.Compact(zones)
	p := &Provider{id: id, cfg: cfg, base: base}
	p.api = &restapi.Client{HTTP: cfg.HTTP, UserAgent: cfg.UserAgent, MaxRetries: retries, Every: every,
		Auth: func(_ context.Context, req *http.Request, _ []byte) error {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
			return nil
		}}
	return p, nil
}

// ID returns the instance id from the configuration.
func (p *Provider) ID() string { return p.id }

// Kind returns "infomaniak".
func (p *Provider) Kind() string { return Kind }

// Capabilities: record by record writes, checked against the content read
// (not atomic), TTL of 60 seconds or more.
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

// envelope is the response of every Infomaniak API call.
type envelope struct {
	Result string          `json:"result"`
	Data   json.RawMessage `json:"data"`
	Error  json.RawMessage `json:"error"`
	Page   int             `json:"page"`
	Pages  int             `json:"pages"`
}

// call sends one request and decodes the data of its envelope in out. It
// returns the number of pages of a paginated listing.
func (p *Provider) call(ctx context.Context, method, u string, in, out any) (int, error) {
	var env envelope
	if _, err := p.api.JSON(ctx, method, u, nil, in, &env); err != nil {
		return 0, err
	}
	if env.Result != "" && env.Result != "success" {
		return 0, &restapi.Error{Method: method, URL: u, Status: http.StatusBadRequest, Body: string(env.Error)}
	}
	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return 0, fmt.Errorf("%s %s: decode data: %w", method, u, err)
		}
	}
	return env.Pages, nil
}

// ListZones returns the configured zones or, without any, the domains of
// the account (its "domain" products).
func (p *Provider) ListZones(ctx context.Context) ([]string, error) {
	if len(p.cfg.Zones) > 0 {
		return slices.Clone(p.cfg.Zones), nil
	}
	var out []string
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"service_name": {"domain"}, "page": {strconv.Itoa(page)}}
		var products []struct {
			CustomerName string `json:"customer_name"`
		}
		pages, err := p.call(ctx, http.MethodGet, p.base+"/1/product?"+q.Encode(), nil, &products)
		if err != nil {
			return nil, fmt.Errorf("infomaniak %s: list domains: %w", p.id, err)
		}
		for _, d := range products {
			if n := dns.NormalizeZone(d.CustomerName); n != "" {
				out = append(out, n)
			}
		}
		if len(products) == 0 || page >= pages {
			break
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// record is an Infomaniak DNS record.
type record struct {
	ID     int64  `json:"id,omitempty"`
	Source string `json:"source"`
	Type   string `json:"type"`
	TTL    int    `json:"ttl"`
	Target string `json:"target"`
	// Description holds, for some types, fields the target may omit
	// (priority, weight, port, flags, tag), each as {"value": ...}.
	Description json.RawMessage `json:"description,omitempty"`
}

// attr returns a field of the description of a record, as text.
func (r record) attr(name string) (string, bool) {
	var d map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if json.Unmarshal(r.Description, &d) != nil {
		return "", false
	}
	raw := strings.TrimSpace(string(d[name].Value))
	if raw == "" || raw == "null" {
		return "", false
	}
	var s string
	if json.Unmarshal([]byte(raw), &s) == nil {
		return s, s != ""
	}
	return raw, true
}

// presentation completes the target of a record with the fields Infomaniak
// may return apart from it.
func (r record) presentation(typ string) string {
	t := strings.TrimSpace(r.Target)
	n := len(strings.Fields(t))
	get := func(name string) string {
		v, _ := r.attr(name)
		return v
	}
	switch {
	case typ == "MX" && n == 1:
		return get("priority") + " " + t
	case typ == "SRV" && n == 3:
		return get("priority") + " " + t
	case typ == "SRV" && n == 1:
		return strings.Join([]string{get("priority"), get("weight"), get("port"), t}, " ")
	case typ == "CAA" && n == 1:
		if !strings.HasPrefix(t, `"`) {
			t = strconv.Quote(t)
		}
		return strings.Join([]string{get("flags"), get("tag"), t}, " ")
	}
	return t
}

func canonical(zone string, n record) rdata.Record[record] {
	typ := strings.ToUpper(n.Type)
	r := rdata.Record[record]{Key: dns.Key{Host: dns.NormalizeHost(n.Source, zone), Type: typ}, TTL: n.TTL, Native: n}
	if rdata.IsTXT(typ) {
		r.Value, _ = rdata.Canonical(typ, n.Target)
		return r
	}
	pres := n.presentation(typ)
	v, err := rdata.Canonical(typ, pres)
	if err != nil {
		v, r.ReadOnly = rdata.Loose(pres), rdata.ReadOnlyUnreadable
	}
	r.Value = v
	return r
}

func (p *Provider) recordsURL(zone string, id int64) string {
	u := p.base + "/2/zones/" + url.PathEscape(zone) + "/records"
	if id != 0 {
		u += "/" + strconv.FormatInt(id, 10)
	}
	return u
}

func (p *Provider) zoneError(zone, op string, err error) error {
	if restapi.Status(err) == http.StatusNotFound {
		return fmt.Errorf("%w: %s in infomaniak %s", provider.ErrZoneNotFound, zone, p.id)
	}
	return fmt.Errorf("infomaniak %s: %s of %s: %w", p.id, op, zone, err)
}

func (p *Provider) records(ctx context.Context, zone string) ([]rdata.Record[record], error) {
	var recs []rdata.Record[record]
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"with": {"records_description"}}
		if page > 1 {
			q.Set("page", strconv.Itoa(page))
		}
		var native []record
		pages, err := p.call(ctx, http.MethodGet, p.recordsURL(zone, 0)+"?"+q.Encode(), nil, &native)
		if err != nil {
			return nil, err
		}
		for _, n := range native {
			recs = append(recs, canonical(zone, n))
		}
		if len(native) == 0 || page >= pages {
			break
		}
	}
	return recs, nil
}

// ReadZone returns the records of the zone as RRsets. The apex NS and the
// SOA are read-only "server_managed".
func (p *Provider) ReadZone(ctx context.Context, zone string) (*dns.Zone, error) {
	name := dns.NormalizeZone(zone)
	recs, err := p.records(ctx, name)
	if err != nil {
		return nil, p.zoneError(name, "list records", err)
	}
	return &dns.Zone{Name: name, Provider: p.id, RRsets: rdata.Group(recs)}, nil
}

// wire converts a canonical value to the target Infomaniak stores: the
// content of a TXT record, names without their trailing dot.
func wire(typ, v string) string {
	switch typ {
	case "CNAME", "NS", "PTR", "MX", "SRV":
		f := strings.Fields(v)
		f[len(f)-1] = rdata.TrimDot(f[len(f)-1])
		return strings.Join(f, " ")
	}
	return v
}

func source(host string) string {
	if host == dns.Apex {
		return apexSource
	}
	return host
}

type step struct {
	key  dns.Key
	ttl  int
	diff rdata.Diff[record]
}

// Apply writes changes record by record. Before any write the zone is read
// again: a create whose RRset exists, or an update or delete whose TTL or
// values differ from Old, is provider.ErrConflict and nothing is written.
// Records are then deleted, rewritten in place and created in this order. A
// failure after the first write leaves the zone partially changed.
func (p *Provider) Apply(ctx context.Context, zone string, _ *dns.Zone, changes []dns.Change) error {
	if len(changes) == 0 {
		return nil
	}
	name := dns.NormalizeZone(zone)
	all, err := p.records(ctx, name)
	if err != nil {
		return p.zoneError(name, "list records", err)
	}
	steps := make([]step, 0, len(changes))
	for _, c := range changes {
		s, err := p.prepare(name, all, c)
		if err != nil {
			return err
		}
		steps = append(steps, s)
	}
	wrote := false
	fail := func(key dns.Key, err error) error {
		st := restapi.Status(err)
		switch {
		case wrote:
			return fmt.Errorf("infomaniak %s: write %s of %s: %w; the zone is partially changed", p.id, key, name, err)
		case st == http.StatusBadRequest || st == http.StatusUnprocessableEntity:
			return &provider.RejectedError{Message: fmt.Sprintf("infomaniak rejected %s: %v", key, err)}
		case st != 0:
			return fmt.Errorf("%w: infomaniak %s: write %s of %s: %v", provider.ErrNotApplied, p.id, key, name, err)
		}
		return fmt.Errorf("infomaniak %s: write %s of %s: %w", p.id, key, name, err)
	}
	body := func(s step, v string) record {
		return record{Source: source(s.key.Host), Type: s.key.Type, TTL: s.ttl, Target: wire(s.key.Type, v)}
	}
	for _, s := range steps {
		for _, old := range s.diff.Delete {
			if _, err := p.call(ctx, http.MethodDelete, p.recordsURL(name, old.ID), nil, nil); err != nil && restapi.Status(err) != http.StatusNotFound {
				return fail(s.key, err)
			}
			wrote = true
		}
	}
	for _, s := range steps {
		for _, u := range s.diff.Update {
			if _, err := p.call(ctx, http.MethodPut, p.recordsURL(name, u.Old.ID), body(s, u.Value), nil); err != nil {
				return fail(s.key, err)
			}
			wrote = true
		}
	}
	for _, s := range steps {
		for _, v := range s.diff.Create {
			if _, err := p.call(ctx, http.MethodPost, p.recordsURL(name, 0), body(s, v), nil); err != nil {
				return fail(s.key, err)
			}
			wrote = true
		}
	}
	return nil
}

func (p *Provider) prepare(zone string, all []rdata.Record[record], c dns.Change) (step, error) {
	key := dns.Key{Host: dns.NormalizeHost(c.Key.Host, zone), Type: strings.ToUpper(strings.TrimSpace(c.Key.Type))}
	bad := func(msg string) (step, error) { return step{}, &provider.InvalidError{Key: key, Message: msg} }
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
	s := step{key: key}
	var want []string
	if c.New != nil {
		n, err := p.Normalize(zone, *c.New)
		if err != nil {
			return step{}, err
		}
		if n.Key != key {
			return bad("the desired RRset has another key (" + n.Key.String() + ")")
		}
		want, s.ttl = n.Values, n.TTL
	} else if !rules.Types[key.Type] {
		return bad("type " + key.Type + " is not supported by the infomaniak provider")
	}
	var have []rdata.Record[record]
	for _, r := range all {
		if r.Key == key {
			have = append(have, r)
		}
	}
	sets := rdata.Group(have)
	switch {
	case c.Op == dns.OpCreate && len(sets) > 0:
		return step{}, fmt.Errorf("%w: %s already exists in %s", provider.ErrConflict, key, zone)
	case c.Op == dns.OpCreate:
	case len(sets) == 1 && sets[0].ReadOnly != "":
		return bad("read-only RRset (" + sets[0].ReadOnly + ")")
	case len(sets) != 1 || sets[0].TTL != c.Old.TTL || !rdata.SameValues(sets[0].Values, c.Old.Values):
		return step{}, fmt.Errorf("%w: %s of %s differs from the zone read", provider.ErrConflict, key, zone)
	}
	s.diff = rdata.Plan(have, want, s.ttl)
	return s, nil
}
