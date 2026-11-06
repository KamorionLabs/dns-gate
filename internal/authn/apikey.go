package authn

import (
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/apikey"
	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// APIKeyIssuer is the issuer name of API key subjects ("api-key:<id>").
const APIKeyIssuer = "api-key"

// touchEvery bounds the last-use writes of a key.
const touchEvery = time.Minute

// APIKeys reads gate-issued API keys (store.APIKeyStore).
type APIKeys interface {
	GetAPIKey(ctx context.Context, id string) (*store.APIKey, error)
	TouchAPIKey(ctx context.Context, id string, at time.Time, ip string) error
}

// SetAPIKeys enables gate-issued API keys (dgk_...); failures are audited
// to log when not nil.
func (a *Authenticator) SetAPIKeys(keys APIKeys, log audit.Logger) {
	a.keys, a.audit = keys, log
}

// basicAuth decodes an Authorization: Basic value.
func basicAuth(v string) (string, string, bool) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(b), ":")
}

// AuthenticateAPIKey authenticates explicit API key credentials (acme-dns
// X-Api-User / X-Api-Key): user, when set, must be the key id.
func (a *Authenticator) AuthenticateAPIKey(r *http.Request, user, key string) (*identity.Subject, error) {
	return a.authenticateAPIKey(r.Context(), user, key, a.ClientIP(r))
}

func (a *Authenticator) authenticateAPIKey(ctx context.Context, user, token string, ip netip.Addr) (*identity.Subject, error) {
	id, ok := apikey.Parse(token)
	if !ok {
		return nil, a.keyNoise(ctx, ip, unauthorized("malformed API key"))
	}
	if user != "" && user != id {
		return nil, a.keyNoise(ctx, ip, unauthorized("user name is not the id of the API key"))
	}
	if a.keys == nil {
		return nil, unauthorized("API keys are not enabled")
	}
	k, err := a.keys.GetAPIKey(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, a.keyNoise(ctx, ip, unauthorized("invalid API key"))
	}
	if err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Reason: "unavailable", Message: "API key lookup failed"}
	}
	now := a.now()
	current := apikey.Match(token, k.SecretHash)
	previous := k.PreviousHash != "" && apikey.Match(token, k.PreviousHash)
	switch {
	case !current && !previous:
		return nil, a.keyFailure(ctx, id, ip, unauthorized("invalid API key"))
	case !current && (k.PreviousExpiresAt == nil || !now.Before(*k.PreviousExpiresAt)):
		return nil, a.keyFailure(ctx, id, ip, unauthorized("API key rotated: use the new key"))
	case k.RevokedAt != nil:
		return nil, a.keyFailure(ctx, id, ip, unauthorized("API key revoked"))
	case k.ExpiresAt != nil && !now.Before(*k.ExpiresAt):
		return nil, a.keyFailure(ctx, id, ip, unauthorized("API key expired"))
	}
	if !cidrAllowed(k.AllowedCIDRs, ip) {
		return nil, a.keyFailure(ctx, id, ip, &Error{Status: http.StatusForbidden, Reason: "source_ip", Message: "API key not allowed from this address"})
	}
	snap := a.policy.Current()
	if !snap.HasRole(k.Role) || snap.RoleReserved(k.Role) {
		return nil, a.keyFailure(ctx, id, ip, &Error{Status: http.StatusForbidden, Reason: "no_binding", Message: "the role of this API key no longer exists or grants policy.* or gate.* actions"})
	}
	if snap.StrictTeams() && !snap.TeamDeclared(k.Team) {
		return nil, a.keyFailure(ctx, id, ip, &Error{Status: http.StatusForbidden, Reason: "no_binding", Message: "the team of this API key is not declared under teams"})
	}
	var issued policy.RoleGrant
	cur, _ := snap.RoleGrant(k.Role)
	if err := json.Unmarshal([]byte(k.RoleGrant), &issued); err != nil || !cur.Within(issued) {
		return nil, a.keyFailure(ctx, id, ip, &Error{Status: http.StatusForbidden, Reason: "role_widened",
			Message: "the role of this API key grants more than when the key was issued (or no grant was recorded): issue a new key"})
	}
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) >= touchEvery {
		_ = a.keys.TouchAPIKey(ctx, id, now, addrString(ip))
	}
	name := k.Name
	if name == "" {
		name = id
	}
	return &identity.Subject{
		Kind:      identity.KindAPIKey,
		Issuer:    APIKeyIssuer,
		ID:        id,
		Claims:    map[string]any{},
		Roles:     []string{k.Role},
		Teams:     []string{k.Team},
		TeamRoles: map[string][]string{k.Team: {k.Role}},
		Name:      name,
		Category:  identity.CategoryKey,
		Addr:      ip,
	}, nil
}

// noiseWindow is the period over which refusals sharing a key (source,
// or API key id and source) are counted into one audit event.
const noiseWindow = time.Minute

// defaultNoiseEntries bounds the aggregation state.
const defaultNoiseEntries = 4096

// noiseCounter aggregates refused API keys per key and minute, in a bounded
// LRU: anyone can send keys, one audit event per request would let a client
// flood the audit log. O(1) per refusal.
type noiseCounter struct {
	mu    sync.Mutex
	max   int
	order *list.List
	seen  map[string]*list.Element
}

type noiseEntry struct {
	key        string
	start      time.Time
	suppressed int
	event      audit.Event
}

// note records a refusal under key and returns the events to emit now: the
// refusal itself with the count of the previous window when it opens a
// window, and the pending count of an entry evicted to make room.
func (n *noiseCounter) note(key string, now time.Time, ev audit.Event) []audit.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen, n.order = map[string]*list.Element{}, list.New()
	}
	if n.max <= 0 {
		n.max = defaultNoiseEntries
	}
	if el, ok := n.seen[key]; ok {
		e := el.Value.(*noiseEntry)
		n.order.MoveToFront(el)
		if now.Sub(e.start) < noiseWindow {
			e.suppressed++
			return nil
		}
		count := e.suppressed + 1
		e.start, e.suppressed, e.event = now, 0, ev
		return []audit.Event{withCount(ev, count)}
	}
	var out []audit.Event
	if n.order.Len() >= n.max {
		old := n.order.Back()
		e := old.Value.(*noiseEntry)
		n.order.Remove(old)
		delete(n.seen, e.key)
		if e.suppressed > 0 {
			out = append(out, withCount(e.event, e.suppressed))
		}
	}
	n.seen[key] = n.order.PushFront(&noiseEntry{key: key, start: now, event: ev})
	return append(out, withCount(ev, 1))
}

func (n *noiseCounter) len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.order == nil {
		return 0
	}
	return n.order.Len()
}

func withCount(ev audit.Event, count int) audit.Event {
	extra := map[string]any{"count": count}
	for k, v := range ev.Extra {
		extra[k] = v
	}
	ev.Extra = extra
	return ev
}

// source is the aggregation unit of an address: the address, or its /64
// for IPv6.
func source(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	if ip.Is6() && !ip.Is4In6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.Unmap().String()
}

// keyNoise audits refusals of unknown or malformed keys, aggregated per
// source and minute, and returns e.
func (a *Authenticator) keyNoise(ctx context.Context, ip netip.Addr, e *Error) *Error {
	return a.keyRefusal(ctx, "", ip, e, "unknown or malformed API keys")
}

// keyFailure audits refusals of an existing API key, aggregated per key,
// source and minute, and returns e.
func (a *Authenticator) keyFailure(ctx context.Context, id string, ip netip.Addr, e *Error) *Error {
	return a.keyRefusal(ctx, id, ip, e, e.Message)
}

func (a *Authenticator) keyRefusal(ctx context.Context, id string, ip netip.Addr, e *Error, msg string) *Error {
	if a.audit == nil {
		return e
	}
	src := source(ip)
	subject := ""
	if id != "" {
		subject = APIKeyIssuer + ":" + id
	}
	ev := audit.Event{
		Time: a.now().UTC(), RequestID: requestid.From(ctx), Subject: subject, SubjectCategory: identity.CategoryKey,
		Action: "apikey.authenticate", Decision: "deny", Reason: e.Reason,
		Extra: map[string]any{"message": msg, "remote_addr": src},
	}
	audit.Capture(ctx, &ev)
	for _, out := range a.noise.note(subject+"|"+src, a.now(), ev) {
		a.audit.Log(ctx, out)
	}
	return e
}

func cidrAllowed(cidrs []string, ip netip.Addr) bool {
	if len(cidrs) == 0 {
		return true
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && ip.IsValid() && p.Contains(ip) {
			return true
		}
	}
	return false
}

func addrString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}
