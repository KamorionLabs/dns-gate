package route53

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

const (
	minTTL = 0
	maxTTL = 2147483647

	readOnlyServerManaged = "server_managed"
	readOnlyRoutingPolicy = "routing_policy"
)

var writable = map[string]bool{
	"A": true, "AAAA": true, "CAA": true, "CNAME": true, "DS": true, "MX": true,
	"NS": true, "PTR": true, "SPF": true, "SRV": true, "TXT": true,
}

func writableTypes() []string {
	out := make([]string, 0, len(writable))
	for t := range writable {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

var hostedZoneIDPattern = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

func fqdn(zone, host string) string {
	if host == dns.Apex {
		return zone + "."
	}
	return host + "." + zone + "."
}

func canonHost(zone, host string) (string, error) {
	h := dns.NormalizeHost(host, zone)
	if strings.ContainsAny(h, "\n\r") {
		return h, fmt.Errorf("line breaks are not allowed in a host")
	}
	n, err := canonName(fqdn(zone, h))
	if err != nil {
		return h, err
	}
	h = dns.NormalizeHost(n, zone)
	if h != dns.Apex {
		for i, label := range mdns.SplitDomainName(h) {
			if strings.Contains(label, "*") && (i != 0 || label != "*") {
				return h, fmt.Errorf("a wildcard is only allowed as the whole leftmost label")
			}
		}
	}
	return h, nil
}

// Normalize validates a desired RRset and returns it in the canonical form
// ReadZone returns:
//   - host relative, lowercase, Route53 escapes decoded ("*" for \052);
//   - A and AAAA: addresses as printed by Go (IPv6 compressed lowercase);
//   - CNAME, NS, PTR, MX, SRV targets: lowercase absolute names with a
//     trailing dot (a value without trailing dot is absolute, as in Route53);
//   - CAA: "<flags> <tag lowercase> \"<value>\"";
//   - DS: digest uppercase hexadecimal;
//   - TXT and SPF: the unquoted content, one value per record. A value
//     written as quoted strings ("a" "b") is read as their concatenation;
//     the 255-byte chunking happens at write time;
//   - alias: A and AAAA only, TTL 0, no values, lowercase absolute target,
//     hosted zone id uppercase without the /hostedzone/ prefix;
//   - values sorted, duplicates removed.
//
// The apex NS and SOA belong to Route53 and are refused, as are CNAME and DS
// at the apex and types outside Capabilities.Types.
func (p *Provider) Normalize(zone string, set dns.RRset) (dns.RRset, error) {
	zone = dns.NormalizeZone(zone)
	typ := strings.ToUpper(strings.TrimSpace(set.Key.Type))
	host, herr := canonHost(zone, set.Key.Host)
	key := dns.Key{Host: host, Type: typ}
	bad := func(format string, args ...any) error {
		return &provider.InvalidError{Key: key, Message: fmt.Sprintf(format, args...)}
	}
	if herr != nil {
		return dns.RRset{}, bad("%v", herr)
	}
	apex := host == dns.Apex
	switch {
	case typ == "SOA":
		return dns.RRset{}, bad("the SOA record is managed by Route53")
	case typ == "NS" && apex:
		return dns.RRset{}, bad("the apex NS records are managed by Route53")
	case !writable[typ]:
		return dns.RRset{}, bad("type %s is not supported by the route53 provider", typ)
	case (typ == "CNAME" || typ == "DS") && apex:
		return dns.RRset{}, bad("%s is not allowed at the zone apex", typ)
	case typ == "NS" && strings.HasPrefix(host, "*"):
		return dns.RRset{}, bad("wildcard NS records are not allowed")
	}
	if set.Alias != nil {
		return p.normalizeAlias(key, set, bad)
	}
	if set.TTL < minTTL || set.TTL > maxTTL {
		return dns.RRset{}, bad("TTL %d out of range [%d, %d]", set.TTL, minTTL, maxTTL)
	}
	if len(set.Values) == 0 {
		return dns.RRset{}, bad("no values")
	}
	vals := make([]string, 0, len(set.Values))
	for _, v := range set.Values {
		c, err := canonicalValue(typ, v)
		if err != nil {
			return dns.RRset{}, bad("value %q: %v", v, err)
		}
		w, err := wireValue(typ, c)
		if err != nil {
			return dns.RRset{}, bad("value %q: %v", v, err)
		}
		if len(w) > maxValueLen {
			return dns.RRset{}, bad("value %q is %d characters once encoded, over the Route53 limit of %d", v, len(w), maxValueLen)
		}
		vals = append(vals, c)
	}
	slices.Sort(vals)
	vals = slices.Compact(vals)
	if typ == "CNAME" && len(vals) != 1 {
		return dns.RRset{}, bad("a CNAME RRset has exactly one value")
	}
	return dns.RRset{Key: key, TTL: set.TTL, Values: vals}, nil
}

func (p *Provider) normalizeAlias(key dns.Key, set dns.RRset, bad func(string, ...any) error) (dns.RRset, error) {
	if key.Type != "A" && key.Type != "AAAA" {
		return dns.RRset{}, bad("alias records are supported for A and AAAA only")
	}
	if len(set.Values) > 0 {
		return dns.RRset{}, bad("an alias RRset has no values")
	}
	target, err := canonName(set.Alias.Target)
	if err != nil || target == "." {
		return dns.RRset{}, bad("invalid alias target %q", set.Alias.Target)
	}
	zid := zoneIDOf(set.Alias.HostedZoneID)
	if !hostedZoneIDPattern.MatchString(zid) {
		return dns.RRset{}, bad("invalid alias hosted zone id %q", set.Alias.HostedZoneID)
	}
	return dns.RRset{Key: key, Alias: &dns.Alias{Target: target, HostedZoneID: zid, EvaluateTargetHealth: set.Alias.EvaluateTargetHealth}}, nil
}
