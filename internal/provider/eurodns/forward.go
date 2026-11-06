package eurodns

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	api "github.com/KamorionLabs/eurodns-go"
)

// Read-only reasons of URL forwards and forward pseudo records.
const (
	// ReadOnlyUnsupportedForward marks a forward the gate cannot read
	// (unknown forwardType, no URL, unparseable entry).
	ReadOnlyUnsupportedForward = "unsupported_forward"
	// ReadOnlyDuplicateForward marks a host holding several forwards.
	ReadOnlyDuplicateForward = "duplicate_forward"
	// ReadOnlyForwardRecord marks the URL and MAIL pseudo records EuroDNS
	// may list with the records of a zone: they follow the forwards.
	ReadOnlyForwardRecord = "forward_record"
)

// nativeForward mirrors the UrlForward schema of the EuroDNS API.
type nativeForward struct {
	ID          *int64  `json:"id,omitempty"`
	ForwardType string  `json:"forwardType"`
	Host        *string `json:"host"`
	URL         *string `json:"url"`
	Title       *string `json:"title,omitempty"`
	Keywords    *string `json:"keywords,omitempty"`
	Description *string `json:"description,omitempty"`
}

var (
	modeOf = map[string]string{"HTTP301": dns.ForwardPermanent, "HTTP302": dns.ForwardTemporary, "FRAME": dns.ForwardFrame}
	typeOf = map[string]string{dns.ForwardPermanent: "HTTP301", dns.ForwardTemporary: "HTTP302", dns.ForwardFrame: "FRAME"}
)

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// forwardRRsets converts the URL forwards of a zone. Each RRset keeps its
// raw EuroDNS entry as Native, so that a write changes only the forwards
// it targets.
func forwardRRsets(zone string, raws []json.RawMessage) []dns.RRset {
	byHost := map[string]int{}
	var out []dns.RRset
	for _, raw := range raws {
		var nf nativeForward
		err := json.Unmarshal(raw, &nf)
		host := dns.NormalizeHost(str(nf.Host), zone)
		s := dns.RRset{Key: dns.ForwardKey(host), Native: raw,
			Forward: &dns.Forward{Mode: strings.ToLower(nf.ForwardType), URL: str(nf.URL), Title: str(nf.Title), Keywords: str(nf.Keywords), Description: str(nf.Description)}}
		if mode, ok := modeOf[strings.ToUpper(nf.ForwardType)]; ok {
			s.Forward.Mode = mode
		}
		switch {
		case err != nil:
			s.Forward = &dns.Forward{Mode: "unknown", URL: string(raw)}
			s.ReadOnly = ReadOnlyUnsupportedForward
		case modeOf[strings.ToUpper(nf.ForwardType)] == "" || s.Forward.URL == "":
			s.ReadOnly = ReadOnlyUnsupportedForward
		}
		if i, dup := byHost[host]; dup {
			out[i].ReadOnly = ReadOnlyDuplicateForward
			continue
		}
		byHost[host] = len(out)
		out = append(out, s)
	}
	return out
}

// normalizeForward validates a desired forward: a known mode, an absolute
// http or https URL, frame fields only on a frame forward. TTL is 0.
func normalizeForward(s dns.RRset) (dns.RRset, error) {
	invalid := func(format string, a ...any) (dns.RRset, error) {
		return dns.RRset{}, &provider.InvalidError{Key: s.Key, Code: "invalid_forward", Message: fmt.Sprintf(format, a...)}
	}
	if s.Forward == nil {
		return invalid("a forward is required")
	}
	if len(s.Values) > 0 || s.Alias != nil {
		return invalid("a forward has no values nor alias")
	}
	f := *s.Forward
	f.Mode = strings.ToLower(strings.TrimSpace(f.Mode))
	f.URL = strings.TrimSpace(f.URL)
	f.Title, f.Keywords, f.Description = strings.TrimSpace(f.Title), strings.TrimSpace(f.Keywords), strings.TrimSpace(f.Description)
	if typeOf[f.Mode] == "" {
		return invalid("type %q is not one of %s", f.Mode, strings.Join(dns.ForwardModes, ", "))
	}
	u, err := url.Parse(f.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(f.URL, " \t\r\n") {
		return invalid("url %q must be an absolute http:// or https:// URL", f.URL)
	}
	if f.Mode != dns.ForwardFrame && (f.Title != "" || f.Keywords != "" || f.Description != "") {
		return invalid("title, keywords and description only apply to frame forwards")
	}
	s.Forward, s.TTL = &f, 0
	return s, nil
}

// forwardEntry returns the EuroDNS entry of a desired forward: the raw entry
// of the old forward (id and unknown fields kept) with the forward fields
// replaced, or a new entry.
func forwardEntry(host string, old json.RawMessage, f dns.Forward) json.RawMessage {
	m := map[string]any{}
	if len(old) > 0 {
		var prev map[string]any
		if json.Unmarshal(old, &prev) == nil && prev != nil {
			m = prev
		}
	}
	if _, ok := m["host"]; !ok {
		m["host"] = host
	}
	delete(m, "updated")
	m["forwardType"], m["url"] = typeOf[f.Mode], f.URL
	for k, v := range map[string]string{"title": f.Title, "keywords": f.Keywords, "description": f.Description} {
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// applyForwards returns the URL forwards of a zone with changes applied,
// every other entry kept byte for byte and in place. Every entry of a
// changed host is replaced by its new forward (or removed).
func applyForwards(zone string, cur []json.RawMessage, changes []dns.Change) []json.RawMessage {
	byHost := map[string]*dns.Change{}
	for i := range changes {
		byHost[changes[i].Key.Host] = &changes[i]
	}
	out := make([]json.RawMessage, 0, len(cur)+len(changes))
	done := map[string]bool{}
	for _, raw := range cur {
		var nf nativeForward
		_ = json.Unmarshal(raw, &nf)
		host := dns.NormalizeHost(str(nf.Host), zone)
		c, changed := byHost[host]
		if !changed {
			out = append(out, raw)
			continue
		}
		if done[host] {
			continue
		}
		done[host] = true
		if c.New != nil && c.New.Forward != nil {
			out = append(out, forwardEntry(host, raw, *c.New.Forward))
		}
	}
	for _, c := range changes {
		if done[c.Key.Host] || c.New == nil || c.New.Forward == nil {
			continue
		}
		done[c.Key.Host] = true
		out = append(out, forwardEntry(c.Key.Host, nil, *c.New.Forward))
	}
	return out
}

// forwardProblems converts the URL forward errors of a validation report:
// errors block, warnings only on a changed forward.
func forwardProblems(zone string, raws []json.RawMessage, changed map[dns.Key]bool) []provider.Problem {
	var out []provider.Problem
	for _, raw := range raws {
		var e struct {
			Messages   []string      `json:"messages"`
			Message    string        `json:"message"`
			Severity   api.Severity  `json:"severity"`
			URLForward nativeForward `json:"urlForward"`
		}
		if json.Unmarshal(raw, &e) != nil {
			out = append(out, provider.Problem{Message: string(raw), Blocking: true})
			continue
		}
		msg := e.Message
		if len(e.Messages) > 0 {
			msg = strings.Join(e.Messages, "; ")
		}
		k := dns.ForwardKey(dns.NormalizeHost(str(e.URLForward.Host), zone))
		out = append(out, provider.Problem{Key: &k, Message: string(orError(e.Severity)) + ": " + msg + " (" + k.Host + "/" + k.Type + ")",
			Blocking: e.Severity != api.SeverityWarning || changed[k]})
	}
	return out
}

func orError(s api.Severity) api.Severity {
	if s == "" {
		return api.SeverityError
	}
	return s
}
