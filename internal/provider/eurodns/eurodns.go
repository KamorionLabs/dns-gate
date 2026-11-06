// Package eurodns is the EuroDNS provider adapter. It converts EuroDNS zones
// (records grouped by host and type) to the provider-neutral model and writes
// changes with a full-zone save, through one rate-limited transport shared
// by every call of the account (zone reads and writes, checks, snapshots,
// the domain listing and the EuroDNS API passthrough).
//
// EuroDNS behaviours handled here (observed against the live API):
//   - SOA and locked records (apex SOA and NS) are managed by EuroDNS; the SOA
//     serial changes on every write. Their RRsets are read-only
//     ("server_managed") and a save always keeps them as read.
//   - CNAME, MX, NS, SRV, PTR and APEX targets without an ending dot are
//     stored relative to the zone (EuroDNS only warns at check time). On
//     read, an RRset holding such a value is read-only ("relative_target"):
//     the gate cannot write it back without changing its meaning, so it can
//     neither be changed nor adopted until fixed at EuroDNS. On write,
//     Normalize reads a desired target the way Route53 and the dnsgate
//     Terraform provider do: a name with several labels is absolute (the
//     ending dot is added), a single label ("mail") is ambiguous and refused.
//     Stored values and their content hashes are never rewritten.
//   - EuroDNS keeps only the last 5 zone snapshots: the snapshot id recorded
//     in the audit soon disappears.
//   - URL forwards are part of the zone document (urlForwards). Each one is
//     the RRset of key {host, URLFWD} carrying a dns.Forward; a write
//     changes only the entries of the forwards it targets, every other
//     entry is saved back byte for byte. URL and MAIL pseudo records, if
//     EuroDNS lists any, are read-only ("forward_record"). Mail forwards are
//     kept as read and are not modelled.
//   - A forward answers HTTPS requests only with an HTTPS redirect
//     subscription on the domain (a paid EuroDNS product, see
//     HTTPSRedirect); the forward entry itself has no HTTPS setting.
package eurodns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	api "github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/rrset"
	"github.com/KamorionLabs/eurodns-go/zonediff"
)

// Kind is the provider kind of this adapter.
const Kind = "eurodns"

// ReadOnlyServerManaged marks the RRsets holding SOA or locked records.
const ReadOnlyServerManaged = "server_managed"

// CodeRelativeTarget is the read-only reason of an RRset holding a target
// stored relative to the zone, and the InvalidError code of an ambiguous
// single-label target.
const CodeRelativeTarget = "relative_target"

// Types are the record types the EuroDNS API accepts.
var Types = []string{"A", "AAAA", "APEX", "CAA", "CNAME", "DS", "HTTPS", "MX", "NS", "PTR", "SPF", "SRV", "SVCB", "TLSA", "TXT"}

// Config configures a EuroDNS account.
type Config struct {
	BaseURL    string
	AppID      string
	APIKey     string
	RateEvery  time.Duration
	RateBurst  int
	MaxRetries int
	UserAgent  string
}

// Provider is a EuroDNS account.
type Provider struct {
	id        string
	baseURL   string
	client    *api.Client
	transport http.RoundTripper
	https     httpsCache
}

var (
	_ provider.Provider    = (*Provider)(nil)
	_ provider.Checker     = (*Provider)(nil)
	_ provider.Snapshotter = (*Provider)(nil)
)

// New builds the provider and its shared transport (API key, rate limit,
// retries).
func New(id string, cfg Config) (*Provider, error) {
	t := api.NewTransport(
		api.WithAuth(api.APIKeyAuth{AppID: cfg.AppID, APIKey: cfg.APIKey}),
		api.WithRateLimit(cfg.RateEvery, cfg.RateBurst),
		api.WithMaxRetries(cfg.MaxRetries),
		api.WithUserAgent(cfg.UserAgent),
	)
	c, err := api.New(api.WithBaseURL(cfg.BaseURL), api.WithTransport(t), api.WithUserAgent(cfg.UserAgent))
	if err != nil {
		return nil, err
	}
	return NewWithClient(id, cfg.BaseURL, c), nil
}

// NewWithClient builds the provider on an existing client; baseURL is the
// client's base URL.
func NewWithClient(id, baseURL string, c *api.Client) *Provider {
	return &Provider{id: id, baseURL: baseURL, client: c, transport: c.Transport()}
}

func (p *Provider) ID() string   { return p.id }
func (p *Provider) Kind() string { return Kind }

// Client is the EuroDNS client of the account.
func (p *Provider) Client() *api.Client { return p.client }

// BaseURL is the EuroDNS API base URL.
func (p *Provider) BaseURL() string { return p.baseURL }

// Transport is the shared transport (API key, rate limit, retries).
func (p *Provider) Transport() http.RoundTripper { return p.transport }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{FullZoneWrite: true, AtomicBatch: true, Forwards: true, Types: slices.Clone(Types), TTLs: slices.Clone(api.AllowedTTLs)}
}

func (p *Provider) ListZones(ctx context.Context) ([]string, error) {
	names, err := (&lister{BaseURL: p.baseURL, Transport: p.transport}).ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, dns.NormalizeZone(n))
	}
	return out, nil
}

func (p *Provider) ReadZone(ctx context.Context, zone string) (*dns.Zone, error) {
	z, err := p.client.GetZone(ctx, zone)
	if err != nil {
		return nil, wrap("get zone", err)
	}
	return FromNative(p.id, zone, z), nil
}

// FromNative converts a EuroDNS zone. RRsets holding a SOA or a locked
// record are read-only; Values are the sorted rdata and Native the records
// of the RRset, so that dns.ContentHash equals rrset.ContentHash.
func FromNative(id, zone string, z *api.Zone) *dns.Zone {
	zone = dns.NormalizeZone(zone)
	out := &dns.Zone{Name: zone, Provider: id, Native: z, RRsets: []dns.RRset{}}
	if z == nil {
		return out
	}
	managed := map[rrset.Key]bool{}
	for _, r := range z.Records {
		if rrset.ServerManaged(r) {
			managed[rrset.KeyOf(zone, r)] = true
		}
	}
	groups := rrset.Group(zone, z.Records)
	for _, k := range rrset.SortedKeys(groups) {
		g := groups[k]
		s := dns.RRset{Key: dns.Key{Host: k.Host, Type: k.Type}, TTL: g.TTL, Values: slices.Clone(g.Values), Native: slices.Clone(g.Records)}
		switch {
		case managed[k] || k.Type == "SOA":
			s.ReadOnly = ReadOnlyServerManaged
		case k.Type == "URL" || k.Type == "MAIL":
			s.ReadOnly = ReadOnlyForwardRecord
		case hasRelativeTarget(k.Type, s.Values):
			s.ReadOnly = CodeRelativeTarget
		}
		out.RRsets = append(out.RRsets, s)
	}
	out.RRsets = append(out.RRsets, forwardRRsets(zone, z.URLForwards)...)
	sort.SliceStable(out.RRsets, func(i, j int) bool { return out.RRsets[i].Key.Less(out.RRsets[j].Key) })
	return out
}

// Native returns the EuroDNS zone a dns.Zone was read from.
func Native(z *dns.Zone) (*api.Zone, error) {
	if z == nil {
		return nil, errors.New("eurodns: no zone")
	}
	n, ok := z.Native.(*api.Zone)
	if !ok || n == nil {
		return nil, fmt.Errorf("eurodns: zone %s was not read from EuroDNS", z.Name)
	}
	return n, nil
}

// Records returns the EuroDNS records carried by an RRset (nil when the
// RRset was built from values only).
func Records(s *dns.RRset) []api.Record {
	if s == nil {
		return nil
	}
	recs, _ := s.Native.([]api.Record)
	return recs
}

func (p *Provider) Normalize(zone string, s dns.RRset) (dns.RRset, error) {
	s.Key = dns.Key{Host: dns.NormalizeHost(s.Key.Host, zone), Type: strings.ToUpper(strings.TrimSpace(s.Key.Type))}
	invalid := func(code, format string, a ...any) (dns.RRset, error) {
		return dns.RRset{}, &provider.InvalidError{Key: s.Key, Code: code, Message: fmt.Sprintf(format, a...)}
	}
	if s.Key.IsForward() {
		s.Key.Type = dns.TypeURLForward
		return normalizeForward(s)
	}
	if s.Forward != nil {
		return invalid("", "a forward is only valid on type %s", dns.TypeURLForward)
	}
	if s.Alias != nil {
		return invalid("", "alias records are not supported by EuroDNS")
	}
	if s.Key.Type == "" {
		return invalid("", "type is required")
	}
	if len(s.Values) == 0 {
		return invalid("", "at least one value is required")
	}
	if !slices.Contains(api.AllowedTTLs, s.TTL) {
		return invalid("", "TTL %d is not accepted by EuroDNS (allowed: %v)", s.TTL, api.AllowedTTLs)
	}
	values := make([]string, 0, len(s.Values))
	for _, v := range s.Values {
		abs, ok := absoluteTarget(s.Key.Type, v)
		if !ok {
			return invalid(CodeRelativeTarget, "target of %q is a single label: write it fully qualified (%s.%s.)", v, rrset.TargetOf(s.Key.Type, v), dns.NormalizeZone(zone))
		}
		values = append(values, abs)
	}
	sort.Strings(values)
	s.Values = slices.Compact(values)
	if recs := Records(&s); len(recs) > 0 {
		out := make([]api.Record, 0, len(recs))
		for _, r := range recs {
			r.RData, _ = absoluteTarget(s.Key.Type, r.RData)
			out = append(out, r)
		}
		s.Native = out
	}
	return s, nil
}

// hasRelativeTarget reports whether a stored value has a target EuroDNS
// reads relative to the zone (no ending dot).
func hasRelativeTarget(typ string, values []string) bool {
	if !rrset.NeedsFQDN(typ) {
		return false
	}
	for _, v := range values {
		if t := rrset.TargetOf(typ, v); t != "" && !strings.HasSuffix(t, ".") {
			return true
		}
	}
	return false
}

// absoluteTarget returns a desired value with its target fully qualified:
// a target of several labels without an ending dot gets one; a single-label
// target is ambiguous (false).
func absoluteTarget(typ, v string) (string, bool) {
	t := rrset.TargetOf(typ, v)
	if t == "" || strings.HasSuffix(t, ".") {
		return v, true
	}
	if !strings.Contains(t, ".") {
		return v, false
	}
	if strings.EqualFold(strings.TrimSpace(typ), "MX") || strings.EqualFold(strings.TrimSpace(typ), "SRV") {
		f := strings.Fields(v)
		f[len(f)-1] += "."
		return strings.Join(f, " "), true
	}
	return t + ".", true
}

// Desired returns the EuroDNS zone that Apply would save: cur with changes
// applied, every other record and the forwards kept as read.
func Desired(zone string, cur *dns.Zone, changes []dns.Change) (*api.Zone, error) {
	n, err := Native(cur)
	if err != nil {
		return nil, err
	}
	zone = dns.NormalizeZone(zone)
	diff := make([]zonediff.Change, 0, len(changes))
	var forwards []dns.Change
	for _, c := range changes {
		if c.Key.IsForward() {
			forwards = append(forwards, c)
			continue
		}
		diff = append(diff, zonediff.Change{Op: zonediff.Op(c.Op), Key: rrset.Key{Host: c.Key.Host, Type: c.Key.Type}, Old: toSet(c.Old), New: toSet(c.New)})
	}
	out := zonediff.Apply(zone, n, diff)
	if len(forwards) > 0 {
		out.URLForwards = applyForwards(zone, n.URLForwards, forwards)
	}
	return out, nil
}

func toSet(s *dns.RRset) *rrset.Set {
	if s == nil {
		return nil
	}
	return &rrset.Set{Key: rrset.Key{Host: s.Key.Host, Type: s.Key.Type}, TTL: s.TTL, Values: slices.Clone(s.Values), Records: Records(s)}
}

func (p *Provider) Apply(ctx context.Context, zone string, cur *dns.Zone, changes []dns.Change) error {
	desired, err := Desired(zone, cur, changes)
	if err != nil {
		return err
	}
	return wrap("save zone", p.client.SaveZone(ctx, zone, desired))
}

// Check runs the EuroDNS check on the zone as it would be after changes.
// Errors block the write, and so do warnings on an RRset the changes touch.
func (p *Provider) Check(ctx context.Context, zone string, cur *dns.Zone, changes []dns.Change) ([]provider.Problem, error) {
	desired, err := Desired(zone, cur, changes)
	if err != nil {
		return nil, err
	}
	checked, err := p.client.CheckZone(ctx, zone, desired)
	if err != nil {
		return nil, wrap("check zone", err)
	}
	if checked == nil {
		return nil, nil
	}
	changed := make(map[dns.Key]bool, len(changes))
	for _, c := range changes {
		changed[c.Key] = true
	}
	return Problems(zone, checked.Report, changed), nil
}

// Problems converts a validation report: errors are blocking, warnings only
// on a changed RRset.
func Problems(zone string, rep *api.ValidationReport, changed map[dns.Key]bool) []provider.Problem {
	if rep == nil {
		return nil
	}
	out := forwardProblems(zone, rep.URLForwardErrors, changed)
	blocking := slices.ContainsFunc(out, func(p provider.Problem) bool { return p.Blocking })
	others := *rep
	others.URLForwardErrors = nil
	for _, pb := range others.Problems() {
		p := provider.Problem{Message: pb.String(), Blocking: pb.Severity != api.SeverityWarning}
		if pb.Host != "" || pb.Type != "" {
			k := dns.Key{Host: dns.NormalizeHost(pb.Host, zone), Type: strings.ToUpper(strings.TrimSpace(pb.Type))}
			p.Key = &k
			if changed[k] {
				p.Blocking = true
			}
		}
		blocking = blocking || p.Blocking
		out = append(out, p)
	}
	if !blocking && rep.IsValid != nil && !*rep.IsValid {
		out = append(out, provider.Problem{Message: "zone rejected by EuroDNS validation", Blocking: true})
	}
	return out
}

// LatestSnapshot returns the id of the most recent EuroDNS snapshot.
func (p *Provider) LatestSnapshot(ctx context.Context, zone string) (string, error) {
	snaps, err := p.client.ListSnapshots(ctx, zone)
	if err != nil {
		return "", wrap("list snapshots", err)
	}
	if len(snaps) == 0 {
		return "", nil
	}
	best := snaps[0]
	for _, sn := range snaps[1:] {
		if sn.CreatedAt > best.CreatedAt || (sn.CreatedAt == best.CreatedAt && sn.ID > best.ID) {
			best = sn
		}
	}
	return strconv.FormatInt(best.ID, 10), nil
}

// Wrap maps a EuroDNS client error to the provider errors: 404 is
// provider.ErrZoneNotFound, 400 a *provider.RejectedError with the
// validation report, any other 4xx provider.ErrNotApplied.
func Wrap(op string, err error) error { return wrap(op, err) }

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var ae *api.APIError
	if errors.As(err, &ae) {
		switch {
		case ae.StatusCode == http.StatusNotFound:
			return fmt.Errorf("eurodns %s: %w (%w)", op, provider.ErrZoneNotFound, err)
		case ae.StatusCode == http.StatusBadRequest:
			re := &provider.RejectedError{Message: op + ": rejected by EuroDNS"}
			if ae.Report != nil {
				re.Details = ae.Report
			}
			return re
		case ae.StatusCode >= 400 && ae.StatusCode < 500:
			return fmt.Errorf("eurodns %s: %w (%w)", op, provider.ErrNotApplied, err)
		}
	}
	return fmt.Errorf("eurodns %s: %w", op, err)
}
