package route53

import (
	"errors"
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

const maxValueLen = 4000

func isTXT(typ string) bool { return typ == "TXT" || typ == "SPF" }

func rdataOf(rr mdns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}

func parseRR(typ, rdata string) (mdns.RR, error) {
	if _, ok := mdns.StringToType[typ]; !ok {
		return nil, fmt.Errorf("unknown type %s", typ)
	}
	if strings.ContainsAny(rdata, "\n\r") {
		return nil, errors.New("line breaks are not allowed")
	}
	if strings.TrimSpace(rdata) == "" {
		return nil, errors.New("empty value")
	}
	rr, err := mdns.NewRR(". 0 IN " + typ + " " + rdata)
	if err != nil {
		return nil, err
	}
	if rr == nil {
		return nil, errors.New("empty value")
	}
	return rr, nil
}

func canonName(name string) (string, error) {
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

func canonicalRData(typ, rdata string) (string, error) {
	rr, err := parseRR(typ, rdata)
	if err != nil {
		return "", err
	}
	switch r := rr.(type) {
	case *mdns.CNAME:
		r.Target, err = canonName(r.Target)
	case *mdns.NS:
		r.Ns, err = canonName(r.Ns)
	case *mdns.PTR:
		r.Ptr, err = canonName(r.Ptr)
	case *mdns.MX:
		r.Mx, err = canonName(r.Mx)
	case *mdns.SRV:
		r.Target, err = canonName(r.Target)
	case *mdns.CAA:
		r.Tag = strings.ToLower(r.Tag)
	}
	if err != nil {
		return "", err
	}
	return rdataOf(rr), nil
}

func txtContentOf(typ, presentation string) (string, error) {
	rr, err := parseRR(typ, presentation)
	if err != nil {
		return "", err
	}
	buf := make([]byte, mdns.Len(rr))
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

func txtPresentation(typ, content string) (string, error) {
	var rd []byte
	for i := 0; i == 0 || i < len(content); i += 255 {
		chunk := content[i:min(i+255, len(content))]
		rd = append(rd, byte(len(chunk)))
		rd = append(rd, chunk...)
	}
	h := mdns.RR_Header{Name: ".", Rrtype: mdns.StringToType[typ], Class: mdns.ClassINET, Rdlength: uint16(len(rd))}
	rr, _, err := mdns.UnpackRRWithHeader(h, rd, 0)
	if err != nil {
		return "", err
	}
	return rdataOf(rr), nil
}

func txtContent(typ, v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		if c, err := txtContentOf(typ, v); err == nil {
			return c
		}
	}
	return v
}

func canonicalValue(typ, v string) (string, error) {
	if isTXT(typ) {
		return txtContent(typ, v), nil
	}
	return canonicalRData(typ, v)
}

func wireValue(typ, canonical string) (string, error) {
	if isTXT(typ) {
		p, err := txtPresentation(typ, canonical)
		if err != nil {
			return "", err
		}
		return toRoute53(p, false), nil
	}
	return toRoute53(canonical, false), nil
}

func readValue(typ, raw string) string {
	pres := fromRoute53(raw)
	if isTXT(typ) {
		if c, err := txtContentOf(typ, pres); err == nil {
			return c
		}
		return raw
	}
	if c, err := canonicalRData(typ, pres); err == nil {
		return c
	}
	return strings.Join(strings.Fields(raw), " ")
}

func readName(raw string) string {
	if n, err := canonName(fromRoute53(raw)); err == nil {
		return n
	}
	return strings.ToLower(raw)
}

func wireName(fqdn string) string { return toRoute53(fqdn, true) }

func isOctal(c byte) bool   { return c >= '0' && c <= '7' }
func isDecimal(c byte) bool { return c >= '0' && c <= '9' }

func fromRoute53(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		if i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := int(s[i+1]-'0')<<6 | int(s[i+2]-'0')<<3 | int(s[i+3]-'0')
			fmt.Fprintf(&b, `\%03d`, v)
			i += 3
			continue
		}
		b.WriteByte(c)
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

func toRoute53(s string, name bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		if i+3 < len(s) && isDecimal(s[i+1]) && isDecimal(s[i+2]) && isDecimal(s[i+3]) {
			v := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if v <= 255 {
				fmt.Fprintf(&b, `\%03o`, v)
				i += 3
				continue
			}
		}
		if name {
			fmt.Fprintf(&b, `\%03o`, s[i+1])
		} else {
			b.WriteByte(c)
			b.WriteByte(s[i+1])
		}
		i++
	}
	return b.String()
}
