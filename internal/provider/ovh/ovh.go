// Package ovh is the OVHcloud DNS provider adapter. One Provider fronts the
// DNS zones of one OVHcloud account (/domain/zone of the OVHcloud API).
//
// A zone is read in one call, from its export as a zone file. OVHcloud
// stores one record per value and has no RRset operation: Apply reads the
// records of each changed RRset, refuses the write when they differ from the
// RRset the change was computed against, then rewrites, creates and deletes
// records one by one and refreshes the zone. A write is therefore not
// atomic.
package ovh

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/provider/rdata"
	"github.com/KamorionLabs/dns-gate/internal/provider/restapi"
)

// Kind is the adapter kind of OVHcloud providers.
const Kind = "ovh"

// DefaultEndpoint is the API endpoint used when none is configured.
const DefaultEndpoint = "ovh-eu"

type endpoint struct{ api, token string }

var endpoints = map[string]endpoint{
	"ovh-eu": {"https://eu.api.ovh.com/1.0", "https://www.ovh.com/auth/oauth2/token"},
	"ovh-ca": {"https://ca.api.ovh.com/1.0", "https://ca.ovh.com/auth/oauth2/token"},
	"ovh-us": {"https://api.us.ovhcloud.com/1.0", "https://us.ovhcloud.com/auth/oauth2/token"},
}

// Endpoints returns the names of the known API endpoints, sorted.
func Endpoints() []string {
	out := make([]string, 0, len(endpoints))
	for n := range endpoints {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

const (
	minTTL         = 60
	defaultRetries = 3
	timeDeltaTTL   = time.Hour
)

var rules = rdata.Rules{
	Provider: Kind,
	Types: map[string]bool{
		"A": true, "AAAA": true, "CAA": true, "CNAME": true, "DNAME": true, "MX": true,
		"NS": true, "PTR": true, "SRV": true, "SSHFP": true, "TLSA": true, "TXT": true,
	},
	MinTTL: minTTL,
	MaxTTL: rdata.MaxTTL,
}

// txtFieldTypes are the OVHcloud field types published as TXT records.
var txtFieldTypes = []string{"TXT", "SPF", "DKIM", "DMARC"}

// Config is the configuration of one OVHcloud provider instance. It
// authenticates either with an application (ApplicationKey,
// ApplicationSecret, ConsumerKey) or with a service account (ClientID,
// ClientSecret, OAuth2 client credentials).
type Config struct {
	// Endpoint is ovh-eu (default), ovh-ca or ovh-us.
	Endpoint          string
	ApplicationKey    string
	ApplicationSecret string
	ConsumerKey       string
	ClientID          string
	ClientSecret      string
	// BaseURL and TokenURL replace the URLs of Endpoint (tests).
	BaseURL  string
	TokenURL string
	// MaxRetries of a request that may be sent again; 3 when nil.
	MaxRetries *int
	UserAgent  string
	HTTP       *http.Client
}

// Provider is the OVHcloud implementation of provider.Provider.
type Provider struct {
	id   string
	cfg  Config
	base string
	api  *restapi.Client

	token *restapi.Token

	mu      sync.Mutex
	delta   time.Duration
	deltaAt time.Time
}

var _ provider.Provider = (*Provider)(nil)

// New returns the OVHcloud provider instance id. It makes no API call.
func New(id string, cfg Config) (*Provider, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("ovh: provider id is empty")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	ep, ok := endpoints[cfg.Endpoint]
	if !ok {
		return nil, fmt.Errorf("ovh %s: unknown endpoint %q (expected %s)", id, cfg.Endpoint, strings.Join(Endpoints(), ", "))
	}
	if cfg.BaseURL != "" {
		ep.api = strings.TrimRight(cfg.BaseURL, "/")
	}
	if cfg.TokenURL != "" {
		ep.token = cfg.TokenURL
	}
	app := cfg.ApplicationKey != "" || cfg.ApplicationSecret != "" || cfg.ConsumerKey != ""
	oauth := cfg.ClientID != "" || cfg.ClientSecret != ""
	switch {
	case app && oauth:
		return nil, fmt.Errorf("ovh %s: application keys and service account credentials are both set, keep one", id)
	case app && (cfg.ApplicationKey == "" || cfg.ApplicationSecret == "" || cfg.ConsumerKey == ""):
		return nil, fmt.Errorf("ovh %s: application key, application secret and consumer key are all required", id)
	case oauth && (cfg.ClientID == "" || cfg.ClientSecret == ""):
		return nil, fmt.Errorf("ovh %s: client id and client secret are both required", id)
	case !app && !oauth:
		return nil, fmt.Errorf("ovh %s: no credentials", id)
	}
	retries := defaultRetries
	if cfg.MaxRetries != nil {
		retries = *cfg.MaxRetries
	}
	p := &Provider{id: id, cfg: cfg, base: ep.api}
	p.api = &restapi.Client{HTTP: cfg.HTTP, UserAgent: cfg.UserAgent, MaxRetries: retries, Auth: p.sign}
	if oauth {
		p.token = &restapi.Token{Fetch: func(ctx context.Context) (string, time.Time, error) {
			return p.fetchToken(ctx, ep.token)
		}}
		p.api.Auth = p.bearer
	}
	return p, nil
}

func (p *Provider) fetchToken(ctx context.Context, tokenURL string) (string, time.Time, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"scope":         {"all"},
	}
	c := &restapi.Client{HTTP: p.cfg.HTTP, UserAgent: p.cfg.UserAgent}
	raw, _, err := c.Do(ctx, http.MethodPost, tokenURL,
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ovh %s: service account token: HTTP %d", p.id, restapi.Status(err))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("ovh %s: service account token: %w", p.id, err)
	}
	return out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn) * time.Second), nil
}

func (p *Provider) bearer(ctx context.Context, req *http.Request, _ []byte) error {
	t, err := p.token.Get(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t)
	return nil
}

// timeDelta is the difference between the OVHcloud clock and the local one,
// read from /auth/time (signatures carry the OVHcloud time).
func (p *Provider) timeDelta(ctx context.Context) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.deltaAt.IsZero() && time.Since(p.deltaAt) < timeDeltaTTL {
		return p.delta, nil
	}
	c := &restapi.Client{HTTP: p.cfg.HTTP, UserAgent: p.cfg.UserAgent, MaxRetries: 1}
	raw, _, err := c.Do(ctx, http.MethodGet, p.base+"/auth/time", nil, nil)
	if err != nil {
		return 0, fmt.Errorf("ovh %s: read the API time: %w", p.id, err)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ovh %s: read the API time: %w", p.id, err)
	}
	p.delta, p.deltaAt = time.Until(time.Unix(ts, 0)), time.Now()
	return p.delta, nil
}

func (p *Provider) sign(ctx context.Context, req *http.Request, body []byte) error {
	delta, err := p.timeDelta(ctx)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Add(delta).Unix(), 10)
	h := sha1.New()
	fmt.Fprintf(h, "%s+%s+%s+%s+%s+%s", p.cfg.ApplicationSecret, p.cfg.ConsumerKey, req.Method, req.URL.String(), body, ts)
	req.Header.Set("X-Ovh-Application", p.cfg.ApplicationKey)
	req.Header.Set("X-Ovh-Consumer", p.cfg.ConsumerKey)
	req.Header.Set("X-Ovh-Timestamp", ts)
	req.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(h.Sum(nil)))
	return nil
}

// ID returns the instance id from the configuration.
func (p *Provider) ID() string { return p.id }

// Kind returns "ovh".
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

func (p *Provider) zoneURL(zone string, parts ...string) string {
	u := p.base + "/domain/zone/" + url.PathEscape(zone)
	for _, s := range parts {
		u += "/" + s
	}
	return u
}

// call sends one API request; a 404 on the zone is ErrZoneNotFound.
func (p *Provider) call(ctx context.Context, method, u string, in, out any) error {
	_, err := p.api.JSON(ctx, method, u, nil, in, out)
	if err != nil && restapi.Status(err) == http.StatusUnauthorized && p.token != nil {
		p.token.Forget()
	}
	return err
}

func (p *Provider) zoneError(zone, op string, err error) error {
	if restapi.Status(err) == http.StatusNotFound {
		return fmt.Errorf("%w: %s in ovh %s", provider.ErrZoneNotFound, zone, p.id)
	}
	return fmt.Errorf("ovh %s: %s of %s: %w", p.id, op, zone, err)
}

// ListZones returns the DNS zones of the account.
func (p *Provider) ListZones(ctx context.Context) ([]string, error) {
	var names []string
	if err := p.call(ctx, http.MethodGet, p.base+"/domain/zone", nil, &names); err != nil {
		return nil, fmt.Errorf("ovh %s: list zones: %w", p.id, err)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if z := dns.NormalizeZone(n); z != "" {
			out = append(out, z)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// record is an OVHcloud zone record (domain.zone.Record).
type record struct {
	ID        int64  `json:"id,omitempty"`
	FieldType string `json:"fieldType,omitempty"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int64  `json:"ttl"`
}

// keyType is the DNS type of an OVHcloud field type.
func keyType(fieldType string) string {
	ft := strings.ToUpper(fieldType)
	if ft != "TXT" && slices.Contains(txtFieldTypes, ft) {
		return "TXT"
	}
	return ft
}

func fieldTypes(typ string) []string {
	if typ == "TXT" {
		return txtFieldTypes
	}
	return []string{typ}
}

func subDomain(host string) string {
	if host == dns.Apex {
		return ""
	}
	return host
}

// ReadZone returns the zone as OVHcloud exports it (the records as stored,
// refreshed or not). Records without TTL carry the default TTL of the zone.
// The apex NS and the SOA are read-only "server_managed".
func (p *Provider) ReadZone(ctx context.Context, zone string) (*dns.Zone, error) {
	name := dns.NormalizeZone(zone)
	var text string
	if err := p.call(ctx, http.MethodGet, p.zoneURL(name, "export"), nil, &text); err != nil {
		return nil, p.zoneError(name, "export", err)
	}
	recs, perr := parseExport(name, text)
	if perr != nil {
		// A zone file the parser refuses is read record by record instead.
		var err error
		if recs, err = p.readRecords(ctx, name); err != nil {
			return nil, fmt.Errorf("ovh %s: zone file of %s: %v; record by record: %w", p.id, name, perr, err)
		}
	}
	sets := rdata.Group(recs)
	for i := range sets {
		sets[i].Native = nil
	}
	return &dns.Zone{Name: name, Provider: p.id, RRsets: sets}, nil
}

func parseExport(zone, text string) ([]rdata.Record[record], error) {
	zp := mdns.NewZoneParser(strings.NewReader(text), zone+".", "")
	var recs []rdata.Record[record]
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		if h.Class != mdns.ClassINET {
			continue
		}
		fq := strings.ToLower(h.Name)
		if fq != zone+"." && !strings.HasSuffix(fq, "."+zone+".") {
			continue
		}
		typ := mdns.TypeToString[h.Rrtype]
		if typ == "" {
			typ = "TYPE" + strconv.Itoa(int(h.Rrtype))
		}
		r := rdata.Record[record]{Key: dns.Key{Host: dns.NormalizeHost(fq, zone), Type: typ}, TTL: int(h.Ttl)}
		v, err := rdata.CanonicalRR(rr)
		if err != nil {
			v, r.ReadOnly = rdata.Loose(strings.TrimPrefix(rr.String(), h.String())), rdata.ReadOnlyUnreadable
		}
		r.Value = v
		recs = append(recs, r)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return recs, nil
}

func (p *Provider) readRecords(ctx context.Context, zone string) ([]rdata.Record[record], error) {
	var soa struct {
		TTL int64 `json:"ttl"`
	}
	if err := p.call(ctx, http.MethodGet, p.zoneURL(zone, "soa"), nil, &soa); err != nil {
		return nil, err
	}
	var ids []int64
	if err := p.call(ctx, http.MethodGet, p.zoneURL(zone, "record"), nil, &ids); err != nil {
		return nil, err
	}
	recs := make([]rdata.Record[record], 0, len(ids))
	for _, id := range ids {
		r, ok, err := p.getRecord(ctx, zone, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if r.TTL == 0 {
			r.TTL = int(soa.TTL)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func (p *Provider) getRecord(ctx context.Context, zone string, id int64) (rdata.Record[record], bool, error) {
	var n record
	if err := p.call(ctx, http.MethodGet, p.zoneURL(zone, "record", strconv.FormatInt(id, 10)), nil, &n); err != nil {
		if restapi.Status(err) == http.StatusNotFound {
			return rdata.Record[record]{}, false, nil
		}
		return rdata.Record[record]{}, false, err
	}
	typ := keyType(n.FieldType)
	r := rdata.Record[record]{Key: dns.Key{Host: dns.NormalizeHost(n.SubDomain, zone), Type: typ}, TTL: int(n.TTL), Native: n}
	v, err := rdata.CanonicalIn(zone, typ, n.Target)
	if err != nil {
		v, r.ReadOnly = rdata.Loose(n.Target), rdata.ReadOnlyUnreadable
	}
	r.Value = v
	return r, true, nil
}

// current returns the records of an RRset as stored by OVHcloud.
func (p *Provider) current(ctx context.Context, zone string, key dns.Key) ([]rdata.Record[record], error) {
	var recs []rdata.Record[record]
	seen := map[int64]bool{}
	for _, ft := range fieldTypes(key.Type) {
		q := url.Values{"fieldType": {ft}, "subDomain": {subDomain(key.Host)}}
		var ids []int64
		if err := p.call(ctx, http.MethodGet, p.zoneURL(zone, "record")+"?"+q.Encode(), nil, &ids); err != nil {
			return nil, err
		}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			r, ok, err := p.getRecord(ctx, zone, id)
			if err != nil {
				return nil, err
			}
			// The filters of the listing are patterns: keep exact matches.
			if ok && r.Key == key {
				recs = append(recs, r)
			}
		}
	}
	return recs, nil
}

func wire(typ, canonical string) (string, error) {
	if rdata.IsTXT(typ) {
		return rdata.TXTPresentation(typ, canonical)
	}
	return canonical, nil
}

type step struct {
	key  dns.Key
	ttl  int
	diff rdata.Diff[record]
}

// Apply writes changes record by record, then refreshes the zone. Before
// any write, the records of every changed RRset are read again: a create
// whose RRset exists, or an update or delete whose values differ from Old,
// is provider.ErrConflict and nothing is written (TTLs are not compared:
// OVHcloud does not return the default TTL of a record). Records are then
// deleted, rewritten in place and created in this order. A failure after the
// first write leaves the zone partially changed; the zone is still
// refreshed, so that what is stored is what is served.
func (p *Provider) Apply(ctx context.Context, zone string, _ *dns.Zone, changes []dns.Change) error {
	if len(changes) == 0 {
		return nil
	}
	name := dns.NormalizeZone(zone)
	steps := make([]step, 0, len(changes))
	for _, c := range changes {
		s, err := p.prepare(ctx, name, c)
		if err != nil {
			return err
		}
		steps = append(steps, s)
	}
	wrote := false
	fail := func(key dns.Key, err error) error {
		if !wrote {
			if st := restapi.Status(err); st == http.StatusBadRequest {
				return &provider.RejectedError{Message: fmt.Sprintf("ovh rejected %s: %v", key, err)}
			} else if st != 0 {
				return fmt.Errorf("%w: ovh %s: write %s of %s: %v", provider.ErrNotApplied, p.id, key, name, err)
			}
			return fmt.Errorf("ovh %s: write %s of %s: %w", p.id, key, name, err)
		}
		msg := "the zone is partially changed"
		if rerr := p.refresh(ctx, name); rerr != nil {
			msg += " and was not refreshed (" + rerr.Error() + ")"
		}
		return fmt.Errorf("ovh %s: write %s of %s: %w; %s", p.id, key, name, err, msg)
	}
	for _, s := range steps {
		for _, old := range s.diff.Delete {
			if err := p.call(ctx, http.MethodDelete, p.zoneURL(name, "record", strconv.FormatInt(old.ID, 10)), nil, nil); err != nil && restapi.Status(err) != http.StatusNotFound {
				return fail(s.key, err)
			}
			wrote = true
		}
	}
	for _, s := range steps {
		for _, u := range s.diff.Update {
			target, err := wire(s.key.Type, u.Value)
			if err != nil {
				return fail(s.key, err)
			}
			body := record{SubDomain: u.Old.SubDomain, Target: target, TTL: int64(s.ttl)}
			if err := p.call(ctx, http.MethodPut, p.zoneURL(name, "record", strconv.FormatInt(u.Old.ID, 10)), body, nil); err != nil {
				return fail(s.key, err)
			}
			wrote = true
		}
	}
	for _, s := range steps {
		for _, v := range s.diff.Create {
			target, err := wire(s.key.Type, v)
			if err != nil {
				return fail(s.key, err)
			}
			body := record{FieldType: s.key.Type, SubDomain: subDomain(s.key.Host), Target: target, TTL: int64(s.ttl)}
			if err := p.call(ctx, http.MethodPost, p.zoneURL(name, "record"), body, nil); err != nil {
				return fail(s.key, err)
			}
			wrote = true
		}
	}
	if !wrote {
		return nil
	}
	if err := p.refresh(ctx, name); err != nil {
		return fmt.Errorf("ovh %s: the records of %s are written but the zone was not refreshed: %w", p.id, name, err)
	}
	return nil
}

func (p *Provider) refresh(ctx context.Context, zone string) error {
	return p.call(ctx, http.MethodPost, p.zoneURL(zone, "refresh"), nil, nil)
}

func (p *Provider) prepare(ctx context.Context, zone string, c dns.Change) (step, error) {
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
		return bad("type " + key.Type + " is not supported by the ovh provider")
	}
	have, err := p.current(ctx, zone, key)
	if err != nil {
		return step{}, p.zoneError(zone, "read "+key.String(), err)
	}
	vals := make([]string, len(have))
	for i, r := range have {
		if r.ReadOnly != "" {
			return bad("read-only RRset (" + r.ReadOnly + ")")
		}
		vals[i] = r.Value
	}
	if c.Op == dns.OpCreate {
		if len(have) > 0 {
			return step{}, fmt.Errorf("%w: %s already exists in %s", provider.ErrConflict, key, zone)
		}
	} else if !rdata.SameValues(vals, c.Old.Values) {
		return step{}, fmt.Errorf("%w: %s of %s differs from the zone read", provider.ErrConflict, key, zone)
	}
	s.diff = rdata.Plan(have, want, s.ttl)
	return s, nil
}
