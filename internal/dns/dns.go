// Package dns is the provider-neutral model of the gate: zones made of
// RRsets, and RRset-level changes. Every provider adapter converts its own
// records to and from this model; the core (RBAC, ownership, audit, UI, MCP,
// REST API) only sees these types.
package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Apex is the host of the zone apex.
const Apex = "@"

// TypeURLForward is the pseudo type of the URL forward (HTTP redirect) of a
// host: an RRset of this type carries a Forward and no values. It is never
// a DNS record type, so it cannot collide with one.
const TypeURLForward = "URLFWD"

// Forward modes.
const (
	ForwardPermanent = "301"   // HTTP 301 redirect
	ForwardTemporary = "302"   // HTTP 302 redirect
	ForwardFrame     = "frame" // the target shown in a frame
)

// ForwardModes are the forward modes, in display order.
var ForwardModes = []string{ForwardPermanent, ForwardTemporary, ForwardFrame}

// Key identifies an RRset in a zone. Host is relative to the zone, lowercase,
// without trailing dot, Apex for the apex. Type is uppercase.
type Key struct {
	Host string `json:"host"`
	Type string `json:"type"`
}

func (k Key) String() string { return k.Host + "/" + k.Type }

// IsForward reports whether the key is the URL forward of a host.
func (k Key) IsForward() bool { return strings.EqualFold(k.Type, TypeURLForward) }

// ForwardKey is the key of the URL forward of a host.
func ForwardKey(host string) Key { return Key{Host: host, Type: TypeURLForward} }

// Less orders keys by host then type.
func (k Key) Less(o Key) bool {
	if k.Host != o.Host {
		return k.Host < o.Host
	}
	return k.Type < o.Type
}

// Alias is a provider alias target (Route53 alias records). An RRset with an
// Alias has no Values.
type Alias struct {
	Target               string `json:"target"`
	HostedZoneID         string `json:"hosted_zone_id"`
	EvaluateTargetHealth bool   `json:"evaluate_target_health"`
}

// Forward is a URL forward: the provider answers HTTP requests for the host
// with a redirect to URL (or a page framing it). Title, Keywords and
// Description only apply to frame forwards.
type Forward struct {
	Mode        string `json:"type"`
	URL         string `json:"url"`
	Title       string `json:"title,omitempty"`
	Keywords    string `json:"keywords,omitempty"`
	Description string `json:"description,omitempty"`
}

// RRset is the unit of ownership: every record of one host and type, or the
// URL forward of a host (Key.Type TypeURLForward, Forward set, TTL 0).
type RRset struct {
	Key     Key      `json:"key"`
	TTL     int      `json:"ttl"`
	Values  []string `json:"values,omitempty"`
	Alias   *Alias   `json:"alias,omitempty"`
	Forward *Forward `json:"forward,omitempty"`
	// ReadOnly, when set, is the reason the gate never writes this RRset
	// (for example "server_managed", "routing_policy", "locked").
	ReadOnly string `json:"read_only,omitempty"`
	// Native is the provider payload of the RRset, opaque to the core.
	Native any `json:"-"`
}

// Zone is the content of a zone as read from its provider.
type Zone struct {
	Name     string  `json:"name"`
	Provider string  `json:"provider"`
	RRsets   []RRset `json:"rrsets"`
	// Native is the provider payload of the whole zone, opaque to the core
	// (the EuroDNS zone, with forwards and other fields, for EuroDNS).
	Native any `json:"-"`
}

// Set returns the RRset of a key.
func (z *Zone) Set(k Key) (RRset, bool) {
	for _, s := range z.RRsets {
		if s.Key == k {
			return s, true
		}
	}
	return RRset{}, false
}

// Op is the kind of an RRset change.
type Op string

const (
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
)

// Change is one RRset-level change. Old is nil on create, New nil on delete.
type Change struct {
	Op  Op
	Key Key
	Old *RRset
	New *RRset
}

// NormalizeZone lowercases a zone name and strips its trailing dot.
func NormalizeZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

// NormalizeHost returns host relative to zone, lowercase, without trailing
// dot, Apex for the apex.
func NormalizeHost(host, zone string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	z := NormalizeZone(zone)
	if z != "" {
		if h == z {
			return Apex
		}
		h = strings.TrimSuffix(h, "."+z)
	}
	if h == "" || h == Apex {
		return Apex
	}
	return h
}

// ContentHash identifies the content of an RRset (TTL and values, order
// insensitive). For RRsets without alias nor forward it is byte for byte the
// hash of eurodns-go rrset.ContentHash, so ownership entries written before
// the provider-neutral model stay valid.
//
// A forward hashes as the RRset of TTL 0 holding the single value
// "forward <mode> <n>:<url> <n>:<title> <n>:<keywords> <n>:<description>"
// (each field prefixed by its length in bytes), mode lowercase and every
// field as written by the provider: changing any field changes the hash.
func ContentHash(s RRset) string {
	vals := append([]string(nil), s.Values...)
	switch {
	case s.Forward != nil:
		vals = []string{forwardValue(*s.Forward)}
	case s.Alias != nil:
		vals = []string{fmt.Sprintf("alias %s %s %t", strings.ToLower(s.Alias.HostedZoneID),
			strings.TrimSuffix(strings.ToLower(s.Alias.Target), "."), s.Alias.EvaluateTargetHealth)}
	}
	sort.Strings(vals)
	h := sha256.New()
	fmt.Fprintf(h, "ttl=%d\n", s.TTL)
	for _, v := range vals {
		fmt.Fprintf(h, "%d:%s\n", len(v), v)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func forwardValue(f Forward) string {
	var b strings.Builder
	b.WriteString("forward " + strings.ToLower(f.Mode))
	for _, v := range []string{f.URL, f.Title, f.Keywords, f.Description} {
		fmt.Fprintf(&b, " %d:%s", len(v), v)
	}
	return b.String()
}
