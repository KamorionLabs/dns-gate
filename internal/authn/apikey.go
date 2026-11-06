package authn

import (
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
		Kind:     identity.KindAPIKey,
		Issuer:   APIKeyIssuer,
		ID:       id,
		Claims:   map[string]any{},
		Roles:    []string{k.Role},
		Teams:    []string{k.Team},
		Name:     name,
		Category: identity.CategoryKey,
		Addr:     ip,
	}, nil
}

// noiseWindow is the period over which refusals of unknown or malformed
// keys from one address are counted into one audit event.
const noiseWindow = time.Minute

// noiseCounter aggregates refusals of unknown or malformed API keys per
// source address: anyone can send them, one audit event each would let a
// client flood the audit log.
type noiseCounter struct {
	mu   sync.Mutex
	seen map[string]*noiseEntry
}

type noiseEntry struct {
	start      time.Time
	suppressed int
}

// note records a refusal and returns how many refusals to report now (the
// suppressed ones of the previous window plus this one), 0 to stay quiet.
func (n *noiseCounter) note(addr string, now time.Time) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]*noiseEntry{}
	}
	e := n.seen[addr]
	if e != nil && now.Sub(e.start) < noiseWindow {
		e.suppressed++
		return 0
	}
	count := 1
	if e != nil {
		count += e.suppressed
	}
	if len(n.seen) >= 4096 {
		for k, v := range n.seen {
			if now.Sub(v.start) >= noiseWindow {
				delete(n.seen, k)
			}
		}
	}
	n.seen[addr] = &noiseEntry{start: now}
	return count
}

// keyNoise audits refusals of unknown or malformed keys, at most once per
// source address and minute with a count, and returns e.
func (a *Authenticator) keyNoise(ctx context.Context, ip netip.Addr, e *Error) *Error {
	if a.audit == nil {
		return e
	}
	addr := addrString(ip)
	count := a.noise.note(addr, a.now())
	if count == 0 {
		return e
	}
	a.audit.Log(ctx, audit.Event{
		Time: a.now().UTC(), RequestID: requestid.From(ctx), SubjectCategory: identity.CategoryKey,
		Action: "apikey.authenticate", Decision: "deny", Reason: e.Reason,
		Extra: map[string]any{"message": "unknown or malformed API keys", "count": count, "remote_addr": addr},
	})
	return e
}

// keyFailure audits a refused use of an existing API key and returns e.
func (a *Authenticator) keyFailure(ctx context.Context, id string, ip netip.Addr, e *Error) *Error {
	if a.audit == nil {
		return e
	}
	subject := ""
	if id != "" {
		subject = APIKeyIssuer + ":" + id
	}
	a.audit.Log(ctx, audit.Event{
		Time: a.now().UTC(), RequestID: requestid.From(ctx), Subject: subject, SubjectCategory: identity.CategoryKey,
		Action: "apikey.authenticate", Decision: "deny", Reason: e.Reason,
		Extra: map[string]any{"message": e.Message, "remote_addr": addrString(ip)},
	})
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
