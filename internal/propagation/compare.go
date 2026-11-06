package propagation

import (
	"slices"
	"strings"

	mdns "github.com/miekg/dns"
)

func isTXT(qtype uint16) bool { return qtype == mdns.TypeTXT || qtype == mdns.TypeSPF }

// fqdn is the absolute name of a host of zone, lowercase with a trailing dot.
func fqdn(zone, host string) string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if host == "" || host == "@" {
		return zone + "."
	}
	return strings.ToLower(host) + "." + zone + "."
}

// absName returns a target name as an absolute lowercase name: a name
// without trailing dot is relative to zone, as EuroDNS stores it.
func absName(zone, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "@" {
		return fqdn(zone, "@")
	}
	if strings.HasSuffix(n, ".") {
		return n
	}
	return n + "." + strings.TrimSuffix(strings.ToLower(zone), ".") + "."
}

// rdata is the presentation of the data of rr, without its header.
func rdata(rr mdns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// txtContent is the content of a TXT or SPF record: its character strings
// concatenated, unescaped.
func txtContent(rr mdns.RR) (string, bool) {
	buf := make([]byte, mdns.Len(rr)+16)
	off, err := mdns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return "", false
	}
	rd := buf[off-int(rr.Header().Rdlength) : off]
	var b strings.Builder
	for len(rd) > 0 {
		n := int(rd[0])
		if 1+n > len(rd) {
			return "", false
		}
		b.Write(rd[1 : 1+n])
		rd = rd[1+n:]
	}
	return b.String(), true
}

// lowerNames lowercases the domain names an RR carries in its data, which
// compare case-insensitively.
func lowerNames(rr mdns.RR) {
	switch r := rr.(type) {
	case *mdns.CNAME:
		r.Target = strings.ToLower(r.Target)
	case *mdns.NS:
		r.Ns = strings.ToLower(r.Ns)
	case *mdns.PTR:
		r.Ptr = strings.ToLower(r.Ptr)
	case *mdns.MX:
		r.Mx = strings.ToLower(r.Mx)
	case *mdns.SRV:
		r.Target = strings.ToLower(r.Target)
	case *mdns.DNAME:
		r.Target = strings.ToLower(r.Target)
	case *mdns.SVCB:
		r.Target = strings.ToLower(r.Target)
	case *mdns.HTTPS:
		r.Target = strings.ToLower(r.Target)
	case *mdns.CAA:
		r.Tag = strings.ToLower(r.Tag)
	}
}

// canonicalRR is the comparison form of a record received from a server.
func canonicalRR(rr mdns.RR) string {
	if isTXT(rr.Header().Rrtype) {
		if c, ok := txtContent(rr); ok {
			return c
		}
	}
	rr = mdns.Copy(rr)
	lowerNames(rr)
	return rdata(rr)
}

// canonicalValue is the comparison form of a value read from the provider:
// the record is parsed relative to zone, packed and unpacked so that hex,
// base64 and address forms print as a server answer does. A TXT value is
// raw content unless written as quoted strings.
func canonicalValue(zone string, qtype uint16, v string) string {
	v = strings.TrimSpace(v)
	if isTXT(qtype) && !(len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"') {
		return v
	}
	rr, err := parseValue(zone, qtype, v)
	if err != nil {
		if isTXT(qtype) {
			return v
		}
		return strings.ToLower(strings.Join(strings.Fields(v), " "))
	}
	return canonicalRR(rr)
}

func parseValue(zone string, qtype uint16, v string) (mdns.RR, error) {
	if strings.ContainsAny(v, "\n\r") {
		return nil, errInvalidValue
	}
	zp := mdns.NewZoneParser(strings.NewReader("@ 0 IN "+mdns.TypeToString[qtype]+" "+v+"\n"), fqdn(zone, "@"), "")
	rr, ok := zp.Next()
	if err := zp.Err(); err != nil {
		return nil, err
	}
	if !ok || rr == nil {
		return nil, errInvalidValue
	}
	buf := make([]byte, mdns.Len(rr)+16)
	off, err := mdns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	out, _, err := mdns.UnpackRR(buf[:off], 0)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// canonicalSet sorts and deduplicates values.
func canonicalSet(vals []string) []string {
	out := slices.Clone(vals)
	slices.Sort(out)
	return slices.Compact(out)
}

func intersects(a, b []string) bool {
	for _, v := range a {
		if slices.Contains(b, v) {
			return true
		}
	}
	return false
}
