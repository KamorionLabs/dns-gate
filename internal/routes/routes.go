// Package routes maps EuroDNS API requests to operations and gate actions.
// The operation table is generated from api/openapi.json; every operation is
// denied unless explicitly mapped below, so new upstream endpoints stay
// closed until reviewed.
package routes

//go:generate go run ./gen -spec ../../api/openapi.json -out zz_generated.go

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/policy"
)

// Operation is one upstream API operation.
type Operation struct {
	ID     string
	Method string
	Path   string // OpenAPI template, e.g. /dns-zones/{domain-name}
}

// Kind tells the server how to handle an operation.
type Kind int

const (
	Deny        Kind = iota // refused (default)
	Engine                  // handled by the zone write engine
	Passthrough             // proxied upstream after authorization
)

// Rule is the gate mapping of an operation.
type Rule struct {
	Action string
	Kind   Kind
}

// mapping opens operations explicitly; anything absent is denied.
var mapping = map[string]Rule{
	"getDnsZone":           {policy.ActionDNSRead, Engine},
	"saveDnsZone":          {policy.ActionRecordWrite, Engine},
	"checkDnsZone":         {policy.ActionDNSRead, Engine},
	"addDnsRecords":        {policy.ActionRecordWrite, Engine},
	"deleteDnsRecord":      {policy.ActionRecordWrite, Engine},
	"listDnsZoneSnapshots": {policy.ActionDNSRead, Passthrough},
	"getSnapShot":          {policy.ActionDNSRead, Passthrough},
	"getDnssecStatus":      {policy.ActionDNSRead, Passthrough},
	"getDomain":            {policy.ActionDomainRead, Passthrough},
}

// Match is a resolved request.
type Match struct {
	Operation Operation
	Rule      Rule
	Params    map[string]string
	Zone      string // normalized domain-name parameter, if any
	Path      string // upstream path rebuilt from the template and validated params
}

// Errors returned by Resolve.
var (
	ErrBadPath     = errors.New("malformed path")
	ErrNotFound    = errors.New("unknown operation")
	ErrMethod      = errors.New("method not allowed")
	ErrBadParam    = errors.New("invalid path parameter")
	ErrQuery       = errors.New("query parameters are not allowed")
	ErrDenied      = errors.New("operation not allowed by the gate")
	ErrZoneUnknown = errors.New("zone not managed by the gate")
)

var (
	idParam    = regexp.MustCompile(`^[0-9]{1,19}$`)
	otherParam = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Table resolves requests against the generated operations.
type Table struct {
	ops     []Operation
	managed func(zone string) bool
}

// New builds a table for a fixed list of managed zones.
func New(zones []string) *Table {
	set := map[string]bool{}
	for _, z := range zones {
		set[strings.ToLower(z)] = true
	}
	return NewDynamic(func(z string) bool { return set[z] })
}

// NewDynamic builds a table whose managed zones are decided per request
// (they follow the active policy). managed receives a normalized zone.
func NewDynamic(managed func(zone string) bool) *Table {
	return &Table{ops: operations, managed: managed}
}

// Operations returns the generated table (read-only).
func Operations() []Operation { return operations }

// RuleFor returns the mapping of an operation id (Deny when absent).
func RuleFor(id string) Rule {
	r, ok := mapping[id]
	if !ok {
		return Rule{Kind: Deny}
	}
	return r
}

// Resolve validates the raw request target and finds the operation. On
// ErrDenied and ErrZoneUnknown the returned Match is filled for auditing.
func (t *Table) Resolve(r *http.Request) (*Match, error) {
	raw := r.URL.EscapedPath()
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return nil, ErrQuery
	}
	if err := checkPath(raw, r.URL.Path); err != nil {
		return nil, err
	}
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")

	var best *Operation
	var bestParams map[string]string
	bestStatic := -1
	methodMismatch := false
	for i := range t.ops {
		op := &t.ops[i]
		params, static, ok := matchTemplate(op.Path, segs)
		if !ok {
			continue
		}
		if op.Method != r.Method {
			methodMismatch = true
			continue
		}
		if static > bestStatic {
			best, bestParams, bestStatic = op, params, static
		}
	}
	if best == nil {
		if methodMismatch {
			return nil, ErrMethod
		}
		return nil, ErrNotFound
	}
	m := &Match{Operation: *best, Rule: RuleFor(best.ID), Params: map[string]string{}}
	path := best.Path
	for name, v := range bestParams {
		switch {
		case name == "domain-name":
			v = strings.TrimSuffix(strings.ToLower(v), ".")
			if !config.ValidFQDN(v) {
				return nil, ErrBadParam
			}
			m.Zone = v
		case name == "id" || strings.HasSuffix(name, "-id"):
			if !idParam.MatchString(v) {
				return nil, ErrBadParam
			}
		default:
			if !otherParam.MatchString(v) {
				return nil, ErrBadParam
			}
		}
		m.Params[name] = v
		path = strings.Replace(path, "{"+name+"}", v, 1)
	}
	m.Path = path
	if m.Rule.Kind == Deny {
		return m, ErrDenied
	}
	if m.Zone == "" || !t.managed(m.Zone) {
		return m, ErrZoneUnknown
	}
	return m, nil
}

// checkPath refuses encoded separators, dot segments, empty segments and
// trailing slashes, so that the decoded path cannot differ from what the
// gate authorized.
func checkPath(escaped, decoded string) error {
	if !strings.HasPrefix(decoded, "/") || len(escaped) > 512 {
		return ErrBadPath
	}
	low := strings.ToLower(escaped)
	for _, bad := range []string{"%2f", "%5c", "%2e", "%00", "\\", ";"} {
		if strings.Contains(low, bad) {
			return ErrBadPath
		}
	}
	if escaped != decoded {
		return ErrBadPath
	}
	if decoded != "/" && strings.HasSuffix(decoded, "/") {
		return ErrBadPath
	}
	for _, s := range strings.Split(decoded[1:], "/") {
		if s == "" || s == "." || s == ".." {
			return ErrBadPath
		}
	}
	return nil
}

func matchTemplate(tmpl string, segs []string) (map[string]string, int, bool) {
	ts := strings.Split(strings.TrimPrefix(tmpl, "/"), "/")
	if len(ts) != len(segs) {
		return nil, 0, false
	}
	params := map[string]string{}
	static := 0
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			params[t[1:len(t)-1]] = segs[i]
			continue
		}
		if t != segs[i] {
			return nil, 0, false
		}
		static++
	}
	return params, static, true
}
