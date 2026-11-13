// Package rdata holds what the record-based provider adapters (OVH,
// Scaleway, Infomaniak, Azure DNS) share: the canonical form of hosts and
// values, the validation of a desired RRset, and the grouping of flat
// provider records into RRsets.
//
// The canonical form is the one of the Route53 adapter, so that an RRset
// reads the same whatever its provider:
//   - host relative to the zone, lowercase, "@" for the apex;
//   - A and AAAA: addresses as printed by Go;
//   - CNAME, NS, PTR, MX, SRV targets: lowercase absolute names with a
//     trailing dot;
//   - CAA: `<flags> <tag lowercase> "<value>"`;
//   - TXT: the unquoted content, one value per record.
package rdata

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

// Read-only reasons shared by the record-based adapters.
const (
	ReadOnlyServerManaged = "server_managed"
	ReadOnlyRoutingPolicy = "routing_policy"
	ReadOnlyAlias         = "alias"
	ReadOnlyUnreadable    = "unreadable"
)

// MaxTTL is the largest TTL of the DNS (RFC 2181).
const MaxTTL = 2147483647

// FQDN is the absolute name of a host of zone, with a trailing dot.
func FQDN(zone, host string) string {
	if host == dns.Apex || host == "" {
		return zone + "."
	}
	return host + "." + zone + "."
}

// IsTXT reports whether values of typ are free text (TXT, SPF).
func IsTXT(typ string) bool { return typ == "TXT" || typ == "SPF" }

// CanonName returns name lowercase, absolute, with a trailing dot. A name
// without trailing dot is absolute.
func CanonName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", errors.New("empty name")
	}
	if !mdns.IsFqdn(n) {
		n += "."
	}
	buf := make([]byte, 256)
	end, err := mdns.PackDomainName(n, buf, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("bad name %q: %v", name, err)
	}
	out, _, err := mdns.UnpackDomainName(buf[:end], 0)
	if err != nil {
		return "", fmt.Errorf("bad name %q: %v", name, err)
	}
	return strings.ToLower(out), nil
}

// TrimDot returns an absolute name without its trailing dot (the root
// stays ".").
func TrimDot(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

// CanonHost returns host relative to zone in canonical form.
func CanonHost(zone, host string) (string, error) {
	h := dns.NormalizeHost(host, zone)
	if strings.ContainsAny(h, "\n\r") {
		return h, errors.New("line breaks are not allowed in a host")
	}
	n, err := CanonName(FQDN(zone, h))
	if err != nil {
		return h, err
	}
	h = dns.NormalizeHost(n, zone)
	if h != dns.Apex {
		for i, label := range mdns.SplitDomainName(h) {
			if strings.Contains(label, "*") && (i != 0 || label != "*") {
				return h, errors.New("a wildcard is only allowed as the whole leftmost label")
			}
		}
	}
	return h, nil
}

func rdataOf(rr mdns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}

// Parse parses the presentation form of one value of typ. Names without a
// trailing dot are relative to origin ("." when empty: they are absolute).
func Parse(origin, typ, value string) (mdns.RR, error) {
	if _, ok := mdns.StringToType[typ]; !ok {
		return nil, fmt.Errorf("unknown type %s", typ)
	}
	if strings.ContainsAny(value, "\n\r") {
		return nil, errors.New("line breaks are not allowed")
	}
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("empty value")
	}
	if origin == "" {
		origin = "."
	}
	zp := mdns.NewZoneParser(strings.NewReader("@ 0 IN "+typ+" "+value+"\n"), mdns.Fqdn(origin), "")
	rr, ok := zp.Next()
	if err := zp.Err(); err != nil {
		return nil, err
	}
	if !ok || rr == nil {
		return nil, errors.New("empty value")
	}
	return rr, nil
}

func canonicalRR(rr mdns.RR) (string, error) {
	var err error
	switch r := rr.(type) {
	case *mdns.CNAME:
		r.Target, err = CanonName(r.Target)
	case *mdns.DNAME:
		r.Target, err = CanonName(r.Target)
	case *mdns.NS:
		r.Ns, err = CanonName(r.Ns)
	case *mdns.PTR:
		r.Ptr, err = CanonName(r.Ptr)
	case *mdns.MX:
		r.Mx, err = CanonName(r.Mx)
	case *mdns.SRV:
		r.Target, err = CanonName(r.Target)
	case *mdns.CAA:
		r.Tag = strings.ToLower(r.Tag)
	}
	if err != nil {
		return "", err
	}
	return rdataOf(rr), nil
}

// CanonicalRR returns the canonical value of a parsed record.
func CanonicalRR(rr mdns.RR) (string, error) {
	typ := mdns.TypeToString[rr.Header().Rrtype]
	if IsTXT(typ) {
		return txtOfRR(rr)
	}
	return canonicalRR(rr)
}

func txtOfRR(rr mdns.RR) (string, error) {
	buf := make([]byte, mdns.Len(rr)+16)
	off, err := mdns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return "", err
	}
	rd := buf[off-int(rr.Header().Rdlength) : off]
	var b strings.Builder
	for len(rd) > 0 {
		n := int(rd[0])
		if 1+n > len(rd) {
			return "", errors.New("truncated character string")
		}
		b.Write(rd[1 : 1+n])
		rd = rd[1+n:]
	}
	return b.String(), nil
}

// TXTContent returns the content of a TXT value written as quoted strings
// (`"a" "b"`): their concatenation, escapes decoded.
func TXTContent(typ, presentation string) (string, error) {
	rr, err := Parse("", typ, presentation)
	if err != nil {
		return "", err
	}
	return txtOfRR(rr)
}

// TXTChunks cuts the content of a TXT value in character strings of at most
// 255 bytes (one empty string for an empty content).
func TXTChunks(content string) []string {
	var out []string
	for i := 0; i == 0 || i < len(content); i += 255 {
		out = append(out, content[i:min(i+255, len(content))])
	}
	return out
}

// TXTPresentation returns the content of a TXT value as quoted strings of at
// most 255 bytes, special bytes escaped as in a zone file.
func TXTPresentation(typ, content string) (string, error) {
	var rd []byte
	for _, chunk := range TXTChunks(content) {
		rd = append(rd, byte(len(chunk)))
		rd = append(rd, chunk...)
	}
	if len(rd) > 65535 {
		return "", errors.New("value too long")
	}
	h := mdns.RR_Header{Name: ".", Rrtype: mdns.StringToType[typ], Class: mdns.ClassINET, Rdlength: uint16(len(rd))}
	rr, _, err := mdns.UnpackRRWithHeader(h, rd, 0)
	if err != nil {
		return "", err
	}
	return rdataOf(rr), nil
}

// txtValue reads a TXT value as providers and clients write it: quoted
// strings are decoded, anything else is the content itself.
func txtValue(typ, v string) string {
	t := strings.TrimSpace(v)
	if len(t) >= 2 && t[0] == '"' && t[len(t)-1] == '"' {
		if c, err := TXTContent(typ, t); err == nil {
			return c
		}
	}
	return v
}

// Canonical returns the canonical form of a value of typ whose names are
// absolute.
func Canonical(typ, v string) (string, error) { return CanonicalIn("", typ, v) }

// CanonicalIn is Canonical for a value whose names without trailing dot are
// relative to origin (as stored by OVH or in a zone file).
func CanonicalIn(origin, typ, v string) (string, error) {
	if IsTXT(typ) {
		return txtValue(typ, v), nil
	}
	rr, err := Parse(origin, typ, v)
	if err != nil {
		return "", err
	}
	return canonicalRR(rr)
}

// Loose is the value kept for a record the adapter cannot parse: its text
// with single spaces.
func Loose(v string) string { return strings.Join(strings.Fields(v), " ") }

// Rules are the limits of a provider on desired RRsets.
type Rules struct {
	// Provider is the adapter kind, for messages.
	Provider string
	// Types are the writable types.
	Types  map[string]bool
	MinTTL int
	MaxTTL int
}

// TypeList returns the writable types, sorted.
func (r Rules) TypeList() []string {
	out := make([]string, 0, len(r.Types))
	for t := range r.Types {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// Normalize validates a desired RRset and returns it in canonical form,
// values sorted and deduplicated. Refused: SOA, the apex NS, CNAME, DNAME and
// DS at the apex, wildcard NS, aliases, forwards, types outside r.Types and
// TTLs outside [r.MinTTL, r.MaxTTL].
func (r Rules) Normalize(zone string, set dns.RRset) (dns.RRset, error) {
	zone = dns.NormalizeZone(zone)
	typ := strings.ToUpper(strings.TrimSpace(set.Key.Type))
	host, herr := CanonHost(zone, set.Key.Host)
	key := dns.Key{Host: host, Type: typ}
	bad := func(format string, args ...any) (dns.RRset, error) {
		return dns.RRset{}, &provider.InvalidError{Key: key, Message: fmt.Sprintf(format, args...)}
	}
	if herr != nil {
		return bad("%v", herr)
	}
	apex := host == dns.Apex
	switch {
	case set.Forward != nil || key.IsForward():
		return bad("the %s provider has no URL forwards", r.Provider)
	case set.Alias != nil:
		return bad("the %s provider has no alias records", r.Provider)
	case typ == "SOA":
		return bad("the SOA record is managed by the provider")
	case typ == "NS" && apex:
		return bad("the apex NS records are managed by the provider")
	case !r.Types[typ]:
		return bad("type %s is not supported by the %s provider", typ, r.Provider)
	case (typ == "CNAME" || typ == "DNAME" || typ == "DS") && apex:
		return bad("%s is not allowed at the zone apex", typ)
	case typ == "NS" && strings.HasPrefix(host, "*"):
		return bad("wildcard NS records are not allowed")
	}
	if set.TTL < r.MinTTL || set.TTL > r.MaxTTL {
		return bad("TTL %d out of range [%d, %d]", set.TTL, r.MinTTL, r.MaxTTL)
	}
	if len(set.Values) == 0 {
		return bad("no values")
	}
	vals := make([]string, 0, len(set.Values))
	for _, v := range set.Values {
		c, err := Canonical(typ, v)
		if err != nil {
			return bad("value %q: %v", v, err)
		}
		if IsTXT(typ) {
			if _, err := TXTPresentation(typ, c); err != nil {
				return bad("value %q: %v", v, err)
			}
		}
		vals = append(vals, c)
	}
	slices.Sort(vals)
	vals = slices.Compact(vals)
	if (typ == "CNAME" || typ == "DNAME") && len(vals) != 1 {
		return bad("a %s RRset has exactly one value", typ)
	}
	return dns.RRset{Key: key, TTL: set.TTL, Values: vals}, nil
}

// Record is one provider record in canonical form, with its provider
// payload.
type Record[N any] struct {
	Key   dns.Key
	TTL   int
	Value string
	// ReadOnly, when set, makes the whole RRset of the record read-only.
	ReadOnly string
	Native   N
}

// Group builds the RRsets of flat records, sorted by key. The TTL of an
// RRset is the lowest of its records; its Native is the []N of its records.
// The apex NS and any SOA are read-only "server_managed".
func Group[N any](recs []Record[N]) []dns.RRset {
	idx := map[dns.Key]int{}
	var sets []dns.RRset
	natives := map[dns.Key][]N{}
	for _, r := range recs {
		i, ok := idx[r.Key]
		if !ok {
			i = len(sets)
			idx[r.Key] = i
			sets = append(sets, dns.RRset{Key: r.Key, TTL: r.TTL})
		}
		s := &sets[i]
		s.TTL = min(s.TTL, r.TTL)
		s.Values = append(s.Values, r.Value)
		if s.ReadOnly == "" {
			s.ReadOnly = r.ReadOnly
		}
		natives[r.Key] = append(natives[r.Key], r.Native)
	}
	for i := range sets {
		s := &sets[i]
		slices.Sort(s.Values)
		s.Values = slices.Compact(s.Values)
		s.Native = natives[s.Key]
		if s.ReadOnly == "" && (s.Key.Type == "SOA" || (s.Key.Type == "NS" && s.Key.Host == dns.Apex)) {
			s.ReadOnly = ReadOnlyServerManaged
		}
	}
	slices.SortFunc(sets, func(a, b dns.RRset) int {
		switch {
		case a.Key.Less(b.Key):
			return -1
		case b.Key.Less(a.Key):
			return 1
		}
		return 0
	})
	return sets
}

// SameValues reports whether got holds exactly the values of want, order
// and duplicates ignored.
func SameValues(got, want []string) bool {
	a, b := slices.Clone(got), slices.Clone(want)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// Diff pairs the records an RRset currently has with the values it must
// hold, to write as few records as possible: records already right are
// kept, the others are updated in place while there are values left, then
// values are created or records deleted.
type Diff[N any] struct {
	Update []Pair[N]
	Create []string
	Delete []N
}

// Pair is a record to rewrite with a value.
type Pair[N any] struct {
	Old   N
	Value string
}

// Plan computes the Diff from cur to the values want at ttl. A record is
// right when its value is wanted and its TTL is ttl.
func Plan[N any](cur []Record[N], want []string, ttl int) Diff[N] {
	left := slices.Clone(want)
	var stale []N
	for _, r := range cur {
		if i := slices.Index(left, r.Value); i >= 0 && r.TTL == ttl {
			left = slices.Delete(left, i, i+1)
			continue
		}
		stale = append(stale, r.Native)
	}
	var d Diff[N]
	for i, n := range stale {
		if i < len(left) {
			d.Update = append(d.Update, Pair[N]{Old: n, Value: left[i]})
		} else {
			d.Delete = append(d.Delete, n)
		}
	}
	if len(left) > len(stale) {
		d.Create = left[len(stale):]
	}
	return d
}
