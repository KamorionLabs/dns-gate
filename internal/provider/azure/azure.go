// Package azure is the Azure DNS provider adapter (public zones, Azure
// Resource Manager API 2018-05-01). One Provider fronts the DNS zones of one
// subscription, optionally of one resource group.
//
// Azure DNS stores record sets: an RRset is one record set, read with its
// etag. Apply writes each changed RRset with one conditional request (create
// only if absent, update and delete only if the etag is the one read), so a
// record set changed upstream in between is provider.ErrConflict. The
// changes of one Apply are separate requests: a write is not atomic.
package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	mdns "github.com/miekg/dns"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	"github.com/KamorionLabs/dns-gate/internal/provider/rdata"
	"github.com/KamorionLabs/dns-gate/internal/provider/restapi"
)

// Kind is the adapter kind of Azure DNS providers.
const Kind = "azure"

const (
	// DefaultBaseURL is Azure Resource Manager (public cloud).
	DefaultBaseURL = "https://management.azure.com"
	// DefaultAuthorityURL is Microsoft Entra ID (public cloud).
	DefaultAuthorityURL = "https://login.microsoftonline.com"
	defaultIMDSURL      = "http://169.254.169.254"

	apiVersion     = "2018-05-01"
	zonesProvider  = "/providers/Microsoft.Network/dnszones"
	defaultRetries = 3
	maxPages       = 1000
)

var rules = rdata.Rules{
	Provider: Kind,
	Types: map[string]bool{
		"A": true, "AAAA": true, "CAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SRV": true, "TXT": true,
	},
	MinTTL: 1,
	MaxTTL: rdata.MaxTTL,
}

// Config is the configuration of one Azure DNS provider instance. The
// identity is, in this order: a client secret, a federated token file
// (workload identity federation), or the managed identity of the host.
type Config struct {
	SubscriptionID string
	// ResourceGroup, when set, limits the provider to the zones of one
	// resource group (needed when two groups hold a zone of the same name).
	ResourceGroup string
	TenantID      string
	ClientID      string
	ClientSecret  string
	// FederatedTokenFile holds a token of an identity provider trusted by
	// the application (read at every token renewal).
	FederatedTokenFile string
	// ManagedIdentity uses the managed identity of the host (ClientID
	// selects a user-assigned one).
	ManagedIdentity bool
	// BaseURL, AuthorityURL and IMDSURL replace the public cloud endpoints.
	BaseURL      string
	AuthorityURL string
	IMDSURL      string
	// MaxRetries of a request that may be sent again; 3 when nil.
	MaxRetries *int
	UserAgent  string
	HTTP       *http.Client
}

// Provider is the Azure DNS implementation of provider.Provider.
type Provider struct {
	id    string
	cfg   Config
	base  string
	api   *restapi.Client
	token *restapi.Token

	mu  sync.Mutex
	ids map[string]string // zone name to resource id
}

var _ provider.Provider = (*Provider)(nil)

// New returns the Azure DNS provider instance id. It makes no API call.
func New(id string, cfg Config) (*Provider, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("azure: provider id is empty")
	}
	if cfg.SubscriptionID == "" {
		return nil, fmt.Errorf("azure %s: subscription_id is required", id)
	}
	switch {
	case cfg.ClientSecret != "" || cfg.FederatedTokenFile != "":
		if cfg.TenantID == "" || cfg.ClientID == "" {
			return nil, fmt.Errorf("azure %s: tenant_id and client_id are required with a client secret or a federated token", id)
		}
	case !cfg.ManagedIdentity:
		return nil, fmt.Errorf("azure %s: no identity (client secret, federated token file or managed_identity)", id)
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.AuthorityURL == "" {
		cfg.AuthorityURL = DefaultAuthorityURL
	}
	if cfg.IMDSURL == "" {
		cfg.IMDSURL = defaultIMDSURL
	}
	retries := defaultRetries
	if cfg.MaxRetries != nil {
		retries = *cfg.MaxRetries
	}
	p := &Provider{id: id, cfg: cfg, base: strings.TrimRight(cfg.BaseURL, "/"), ids: map[string]string{}}
	p.token = &restapi.Token{Fetch: p.fetchToken}
	p.api = &restapi.Client{HTTP: cfg.HTTP, UserAgent: cfg.UserAgent, MaxRetries: retries,
		Auth: func(ctx context.Context, req *http.Request, _ []byte) error {
			t, err := p.token.Get(ctx)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+t)
			return nil
		}}
	return p, nil
}

// ID returns the instance id from the configuration.
func (p *Provider) ID() string { return p.id }

// Kind returns "azure".
func (p *Provider) Kind() string { return Kind }

// Capabilities: conditional writes (etag) of one record set per request,
// not atomic across the RRsets of an Apply, any TTL from 1 second.
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

func (p *Provider) scope() string {
	s := "/subscriptions/" + url.PathEscape(p.cfg.SubscriptionID)
	if p.cfg.ResourceGroup != "" {
		s += "/resourceGroups/" + url.PathEscape(p.cfg.ResourceGroup)
	}
	return s
}

// call sends one Resource Manager request.
func (p *Provider) call(ctx context.Context, method, u string, hdr http.Header, in, out any) error {
	_, err := p.api.JSON(ctx, method, u, hdr, in, out)
	if restapi.Status(err) == http.StatusUnauthorized {
		p.token.Forget()
	}
	return err
}

// next validates the link to the next page of a listing: the token is only
// ever sent to the Resource Manager endpoint.
func (p *Provider) next(link string) (string, error) {
	if link == "" {
		return "", nil
	}
	if !strings.HasPrefix(link, p.base+"/") {
		return "", fmt.Errorf("azure %s: next page outside %s", p.id, p.base)
	}
	return link, nil
}

type zoneResource struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ZoneType string `json:"zoneType"`
	} `json:"properties"`
}

// ListZones returns the public DNS zones of the subscription (of the
// resource group when one is configured). A name held by two resource
// groups is an error: set resource_group.
func (p *Provider) ListZones(ctx context.Context) ([]string, error) {
	ids := map[string]string{}
	u := p.base + p.scope() + zonesProvider + "?api-version=" + apiVersion
	for page := 0; u != "" && page < maxPages; page++ {
		var resp struct {
			Value    []zoneResource `json:"value"`
			NextLink string         `json:"nextLink"`
		}
		if err := p.call(ctx, http.MethodGet, u, nil, nil, &resp); err != nil {
			return nil, fmt.Errorf("azure %s: list zones: %w", p.id, err)
		}
		for _, z := range resp.Value {
			name := dns.NormalizeZone(z.Name)
			if name == "" || z.ID == "" || (z.Properties.ZoneType != "" && !strings.EqualFold(z.Properties.ZoneType, "Public")) {
				continue
			}
			if other, dup := ids[name]; dup && !strings.EqualFold(other, z.ID) {
				return nil, fmt.Errorf("azure %s: two zones named %s (%s, %s); set resource_group", p.id, name, other, z.ID)
			}
			ids[name] = z.ID
		}
		var err error
		if u, err = p.next(resp.NextLink); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	p.ids = ids
	p.mu.Unlock()
	names := make([]string, 0, len(ids))
	for n := range ids {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}

func (p *Provider) zoneID(ctx context.Context, name string) (string, error) {
	if p.cfg.ResourceGroup != "" {
		return p.scope() + zonesProvider + "/" + url.PathEscape(name), nil
	}
	p.mu.Lock()
	id, ok := p.ids[name]
	p.mu.Unlock()
	if !ok {
		if _, err := p.ListZones(ctx); err != nil {
			return "", err
		}
		p.mu.Lock()
		id, ok = p.ids[name]
		p.mu.Unlock()
	}
	if !ok || !strings.HasPrefix(id, "/subscriptions/") {
		return "", fmt.Errorf("%w: %s in azure %s", provider.ErrZoneNotFound, name, p.id)
	}
	return id, nil
}

func (p *Provider) forget(name string) {
	p.mu.Lock()
	delete(p.ids, name)
	p.mu.Unlock()
}

// recordSet is an Azure DNS record set.
type recordSet struct {
	Name       string     `json:"name,omitempty"`
	Type       string     `json:"type,omitempty"`
	Etag       string     `json:"etag,omitempty"`
	Properties properties `json:"properties"`
}

type properties struct {
	TTL            int64             `json:"TTL"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	TargetResource *struct {
		ID string `json:"id"`
	} `json:"targetResource,omitempty"`
	A     []aRecord    `json:"ARecords,omitempty"`
	AAAA  []aaaaRecord `json:"AAAARecords,omitempty"`
	MX    []mxRecord   `json:"MXRecords,omitempty"`
	NS    []nsRecord   `json:"NSRecords,omitempty"`
	PTR   []ptrRecord  `json:"PTRRecords,omitempty"`
	SRV   []srvRecord  `json:"SRVRecords,omitempty"`
	TXT   []txtRecord  `json:"TXTRecords,omitempty"`
	CNAME *cnameRecord `json:"CNAMERecord,omitempty"`
	SOA   *soaRecord   `json:"SOARecord,omitempty"`
	CAA   []caaRecord  `json:"caaRecords,omitempty"`
}

type (
	aRecord struct {
		IPv4Address string `json:"ipv4Address"`
	}
	aaaaRecord struct {
		IPv6Address string `json:"ipv6Address"`
	}
	mxRecord struct {
		Preference uint16 `json:"preference"`
		Exchange   string `json:"exchange"`
	}
	nsRecord struct {
		NSDName string `json:"nsdname"`
	}
	ptrRecord struct {
		PTRDName string `json:"ptrdname"`
	}
	srvRecord struct {
		Priority uint16 `json:"priority"`
		Weight   uint16 `json:"weight"`
		Port     uint16 `json:"port"`
		Target   string `json:"target"`
	}
	txtRecord struct {
		Value []string `json:"value"`
	}
	cnameRecord struct {
		CNAME string `json:"cname"`
	}
	soaRecord struct {
		Host         string `json:"host"`
		Email        string `json:"email"`
		SerialNumber int64  `json:"serialNumber"`
		RefreshTime  int64  `json:"refreshTime"`
		RetryTime    int64  `json:"retryTime"`
		ExpireTime   int64  `json:"expireTime"`
		MinimumTTL   int64  `json:"minimumTTL"`
	}
	caaRecord struct {
		Flags uint8  `json:"flags"`
		Tag   string `json:"tag"`
		Value string `json:"value"`
	}
)

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// values returns the records of a record set in presentation form.
func (rs recordSet) values() []string {
	pr := rs.Properties
	var out []string
	for _, r := range pr.A {
		out = append(out, r.IPv4Address)
	}
	for _, r := range pr.AAAA {
		out = append(out, r.IPv6Address)
	}
	for _, r := range pr.MX {
		out = append(out, fmt.Sprintf("%d %s", r.Preference, r.Exchange))
	}
	for _, r := range pr.NS {
		out = append(out, r.NSDName)
	}
	for _, r := range pr.PTR {
		out = append(out, r.PTRDName)
	}
	for _, r := range pr.SRV {
		out = append(out, fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target))
	}
	if pr.CNAME != nil && pr.CNAME.CNAME != "" {
		out = append(out, pr.CNAME.CNAME)
	}
	if s := pr.SOA; s != nil {
		out = append(out, fmt.Sprintf("%s %s %d %d %d %d %d", s.Host, s.Email, s.SerialNumber, s.RefreshTime, s.RetryTime, s.ExpireTime, s.MinimumTTL))
	}
	for _, r := range pr.CAA {
		out = append(out, fmt.Sprintf("%d %s %s", r.Flags, r.Tag, quote(r.Value)))
	}
	return out
}

// rrsetOf converts a record set; ok is false for an empty record set.
func rrsetOf(zone string, rs recordSet) (dns.RRset, bool) {
	typ := strings.ToUpper(rs.Type[strings.LastIndex(rs.Type, "/")+1:])
	s := dns.RRset{Key: dns.Key{Host: dns.NormalizeHost(rs.Name, zone), Type: typ}, TTL: int(rs.Properties.TTL), Native: rs}
	switch {
	case rs.Properties.TargetResource != nil && rs.Properties.TargetResource.ID != "":
		s.Values, s.ReadOnly = []string{rs.Properties.TargetResource.ID}, rdata.ReadOnlyAlias
	case typ == "TXT":
		for _, r := range rs.Properties.TXT {
			s.Values = append(s.Values, strings.Join(r.Value, ""))
		}
	default:
		for _, v := range rs.values() {
			c, err := rdata.Canonical(typ, v)
			if err != nil {
				c, s.ReadOnly = rdata.Loose(v), rdata.ReadOnlyUnreadable
			}
			s.Values = append(s.Values, c)
		}
	}
	if len(s.Values) == 0 {
		return s, false
	}
	slices.Sort(s.Values)
	s.Values = slices.Compact(s.Values)
	if s.ReadOnly == "" && (typ == "SOA" || (typ == "NS" && s.Key.Host == dns.Apex)) {
		s.ReadOnly = rdata.ReadOnlyServerManaged
	}
	return s, true
}

func (p *Provider) zoneError(zone, op string, err error) error {
	if restapi.Status(err) == http.StatusNotFound {
		p.forget(zone)
		return fmt.Errorf("%w: %s in azure %s", provider.ErrZoneNotFound, zone, p.id)
	}
	return fmt.Errorf("azure %s: %s of %s: %w", p.id, op, zone, err)
}

type zoneNative struct{ id string }

// ReadZone returns the record sets of the zone as RRsets, each with its
// record set (and etag) in Native. The apex NS and the SOA are read-only
// "server_managed", alias record sets (targetResource) "alias" with the
// resource id as value. Empty record sets are not returned.
func (p *Provider) ReadZone(ctx context.Context, zone string) (*dns.Zone, error) {
	name := dns.NormalizeZone(zone)
	id, err := p.zoneID(ctx, name)
	if err != nil {
		return nil, err
	}
	z := &dns.Zone{Name: name, Provider: p.id, Native: zoneNative{id: id}}
	u := p.base + id + "/recordsets?api-version=" + apiVersion + "&$top=500"
	for page := 0; u != "" && page < maxPages; page++ {
		var resp struct {
			Value    []recordSet `json:"value"`
			NextLink string      `json:"nextLink"`
		}
		if err := p.call(ctx, http.MethodGet, u, nil, nil, &resp); err != nil {
			return nil, p.zoneError(name, "list record sets", err)
		}
		for _, rs := range resp.Value {
			if s, ok := rrsetOf(name, rs); ok {
				z.RRsets = append(z.RRsets, s)
			}
		}
		if u, err = p.next(resp.NextLink); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(z.RRsets, func(a, b dns.RRset) int {
		switch {
		case a.Key.Less(b.Key):
			return -1
		case b.Key.Less(a.Key):
			return 1
		}
		return 0
	})
	return z, nil
}

// propertiesOf converts a normalized RRset to record set properties.
func propertiesOf(n dns.RRset) (properties, error) {
	pr := properties{TTL: int64(n.TTL)}
	for _, v := range n.Values {
		if n.Key.Type == "TXT" {
			pr.TXT = append(pr.TXT, txtRecord{Value: rdata.TXTChunks(v)})
			continue
		}
		rr, err := rdata.Parse("", n.Key.Type, v)
		if err != nil {
			return pr, err
		}
		switch r := rr.(type) {
		case *mdns.A:
			pr.A = append(pr.A, aRecord{IPv4Address: v})
		case *mdns.AAAA:
			pr.AAAA = append(pr.AAAA, aaaaRecord{IPv6Address: v})
		case *mdns.CNAME:
			pr.CNAME = &cnameRecord{CNAME: rdata.TrimDot(r.Target)}
		case *mdns.MX:
			pr.MX = append(pr.MX, mxRecord{Preference: r.Preference, Exchange: rdata.TrimDot(r.Mx)})
		case *mdns.NS:
			pr.NS = append(pr.NS, nsRecord{NSDName: rdata.TrimDot(r.Ns)})
		case *mdns.PTR:
			pr.PTR = append(pr.PTR, ptrRecord{PTRDName: rdata.TrimDot(r.Ptr)})
		case *mdns.SRV:
			pr.SRV = append(pr.SRV, srvRecord{Priority: r.Priority, Weight: r.Weight, Port: r.Port, Target: rdata.TrimDot(r.Target)})
		case *mdns.CAA:
			pr.CAA = append(pr.CAA, caaRecord{Flags: r.Flag, Tag: r.Tag, Value: unescape(r.Value)})
		default:
			return pr, fmt.Errorf("type %s is not supported", n.Key.Type)
		}
	}
	return pr, nil
}

// unescape decodes the zone file escapes (\" \\ \DDD) of a CAA value.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if i+3 < len(s) {
			if n, err := strconv.Atoi(s[i+1 : i+4]); err == nil && n <= 255 {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

func (p *Provider) setURL(zoneID string, key dns.Key) string {
	return p.base + zoneID + "/" + url.PathEscape(key.Type) + "/" + url.PathEscape(key.Host) + "?api-version=" + apiVersion
}

type step struct {
	op   dns.Op
	key  dns.Key
	etag string
	body recordSet
}

// Apply writes each change with one conditional request, deletes first:
// a create only if the record set does not exist (If-None-Match: *), an
// update or a delete only if its etag is the one read (If-Match). The etag
// is the one of Old.Native, or of the RRset of cur with the content of Old,
// or else of the record set read again when its content is the one of Old.
// A record set changed upstream is provider.ErrConflict. An update keeps
// the metadata of the record set. A failure after the first write leaves
// the zone partially changed.
func (p *Provider) Apply(ctx context.Context, zone string, cur *dns.Zone, changes []dns.Change) error {
	if len(changes) == 0 {
		return nil
	}
	name := dns.NormalizeZone(zone)
	id := ""
	if cur != nil {
		if zn, ok := cur.Native.(zoneNative); ok {
			id = zn.id
		}
	}
	if id == "" {
		var err error
		if id, err = p.zoneID(ctx, name); err != nil {
			return err
		}
	}
	steps := make([]step, 0, len(changes))
	for _, c := range changes {
		s, err := p.prepare(ctx, name, id, cur, c)
		if err != nil {
			return err
		}
		steps = append(steps, s)
	}
	slices.SortStableFunc(steps, func(a, b step) int {
		return rank(a.op) - rank(b.op)
	})
	wrote := false
	for _, s := range steps {
		if err := p.write(ctx, id, s); err != nil {
			st := restapi.Status(err)
			partial := ""
			if wrote {
				partial = "; the zone is partially changed"
			}
			switch {
			case st == http.StatusPreconditionFailed || st == http.StatusConflict || (st == http.StatusNotFound && s.op == dns.OpDelete):
				return fmt.Errorf("%w: %s of %s changed in azure %s%s", provider.ErrConflict, s.key, name, p.id, partial)
			case st == http.StatusNotFound && !wrote:
				return p.zoneError(name, "write "+s.key.String(), err)
			case st == http.StatusBadRequest && !wrote:
				return &provider.RejectedError{Message: fmt.Sprintf("azure rejected %s: %v", s.key, err)}
			case st != 0 && !wrote:
				return fmt.Errorf("%w: azure %s: write %s of %s: %v", provider.ErrNotApplied, p.id, s.key, name, err)
			}
			return fmt.Errorf("azure %s: write %s of %s: %w%s", p.id, s.key, name, err, partial)
		}
		wrote = true
	}
	return nil
}

func rank(op dns.Op) int {
	switch op {
	case dns.OpDelete:
		return 0
	case dns.OpUpdate:
		return 1
	}
	return 2
}

func (p *Provider) write(ctx context.Context, zoneID string, s step) error {
	u := p.setURL(zoneID, s.key)
	switch s.op {
	case dns.OpDelete:
		return p.call(ctx, http.MethodDelete, u, http.Header{"If-Match": {s.etag}}, nil, nil)
	case dns.OpUpdate:
		return p.call(ctx, http.MethodPut, u, http.Header{"If-Match": {s.etag}}, s.body, nil)
	}
	err := p.call(ctx, http.MethodPut, u, http.Header{"If-None-Match": {"*"}}, s.body, nil)
	if restapi.Status(err) != http.StatusPreconditionFailed {
		return err
	}
	// The record set exists: it is only replaced when it is empty.
	var rs recordSet
	if gerr := p.call(ctx, http.MethodGet, u, nil, nil, &rs); gerr != nil {
		return err
	}
	if _, filled := rrsetOf("", rs); filled || rs.Etag == "" {
		return err
	}
	s.body.Properties.Metadata = rs.Properties.Metadata
	return p.call(ctx, http.MethodPut, u, http.Header{"If-Match": {rs.Etag}}, s.body, nil)
}

func (p *Provider) prepare(ctx context.Context, zone, zoneID string, cur *dns.Zone, c dns.Change) (step, error) {
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
	s := step{op: c.Op, key: key}
	if c.New != nil {
		n, err := p.Normalize(zone, *c.New)
		if err != nil {
			return step{}, err
		}
		if n.Key != key {
			return bad("the desired RRset has another key (" + n.Key.String() + ")")
		}
		if s.body.Properties, err = propertiesOf(n); err != nil {
			return bad(err.Error())
		}
	} else if !rules.Types[key.Type] {
		return bad("type " + key.Type + " is not supported by the azure provider")
	}
	if c.Op == dns.OpCreate {
		return s, nil
	}
	old, err := p.oldNative(ctx, zone, zoneID, cur, *c.Old)
	if err != nil {
		return step{}, err
	}
	s.etag = old.Etag
	s.body.Properties.Metadata = old.Properties.Metadata
	return s, nil
}

func (p *Provider) oldNative(ctx context.Context, zone, zoneID string, cur *dns.Zone, old dns.RRset) (recordSet, error) {
	readOnly := func(reason string) (recordSet, error) {
		return recordSet{}, &provider.InvalidError{Key: old.Key, Message: "read-only RRset (" + reason + ")"}
	}
	if old.ReadOnly != "" {
		return readOnly(old.ReadOnly)
	}
	if rs, ok := old.Native.(recordSet); ok && rs.Etag != "" {
		return rs, nil
	}
	conflict := fmt.Errorf("%w: %s of %s differs from the zone read", provider.ErrConflict, old.Key, zone)
	if cur != nil {
		if s, ok := cur.Set(old.Key); ok {
			if s.ReadOnly != "" {
				return readOnly(s.ReadOnly)
			}
			if dns.ContentHash(s) != dns.ContentHash(old) {
				return recordSet{}, conflict
			}
			if rs, ok := s.Native.(recordSet); ok && rs.Etag != "" {
				return rs, nil
			}
		}
	}
	var rs recordSet
	if err := p.call(ctx, http.MethodGet, p.setURL(zoneID, old.Key), nil, nil, &rs); err != nil {
		if restapi.Status(err) == http.StatusNotFound {
			return recordSet{}, conflict
		}
		return recordSet{}, fmt.Errorf("azure %s: read %s of %s: %w", p.id, old.Key, zone, err)
	}
	if rs.Name == "" {
		rs.Name = old.Key.Host
	}
	if rs.Type == "" {
		rs.Type = old.Key.Type
	}
	s, ok := rrsetOf(zone, rs)
	switch {
	case ok && s.ReadOnly != "":
		return readOnly(s.ReadOnly)
	case !ok || rs.Etag == "" || dns.ContentHash(s) != dns.ContentHash(old):
		return recordSet{}, conflict
	}
	return rs, nil
}
