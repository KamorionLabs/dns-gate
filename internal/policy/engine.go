package policy

import (
	"strings"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/identity"
	"github.com/KamorionLabs/eurodns-go/rrset"
)

// Engine implements Authorizer on the current snapshot of a Holder. Deny by
// default: an action is allowed only if one of the subject's roles has a
// matching rule, the zone is managed, and (for writes) the RRset is not
// protected.
type Engine struct {
	h *Holder
}

var _ Authorizer = (*Engine)(nil)

// New returns an engine evaluating the holder's current policy.
func New(h *Holder) *Engine { return &Engine{h: h} }

// FromConfig builds a base-only engine (tests, tools).
func FromConfig(c *config.Config) *Engine {
	h, err := NewHolder(c)
	if err != nil {
		panic(err)
	}
	return New(h)
}

// Holder returns the policy holder.
func (e *Engine) Holder() *Holder { return e.h }

func (e *Engine) snap() *Snapshot { return e.h.Current() }

// Managed reports whether the zone is managed by the gate.
func (e *Engine) Managed(zone string) bool { return e.snap().zones[normZone(zone)] }

func normZone(z string) string { return strings.TrimSuffix(strings.ToLower(z), ".") }

func roles(s *identity.Subject) []string {
	if s == nil {
		return nil
	}
	return s.Roles
}

// Allow checks an action on a zone, ignoring record scopes. policy.*
// actions ignore the zone.
func (e *Engine) Allow(s *identity.Subject, action, zone string) bool {
	return e.snap().Decide(roles(s), action, zone, nil).Allowed
}

// AllowMeta checks a policy.* action.
func (e *Engine) AllowMeta(s *identity.Subject, action string) bool {
	return IsMeta(action) && e.snap().Decide(roles(s), action, "", nil).Allowed
}

// AllowRRset checks an action on one RRset. Protected RRsets are never
// writable nor adoptable; they stay readable.
func (e *Engine) AllowRRset(s *identity.Subject, action, zone string, key rrset.Key) bool {
	return e.snap().Decide(roles(s), action, zone, &key).Allowed
}

// IsProtected reports whether an RRset is in the protected list.
func (e *Engine) IsProtected(zone string, key rrset.Key) bool {
	_, ok := e.snap().protectedBy(normZone(zone), normKey(key))
	return ok
}

// OwnerTeam returns the first team of the subject when one of its roles can
// write records in the zone.
func (e *Engine) OwnerTeam(s *identity.Subject, zone string) (string, bool) {
	if s == nil || len(s.Teams) == 0 || !e.Allow(s, ActionRecordWrite, zone) {
		return "", false
	}
	return s.Teams[0], true
}

// MaxChangesPerRequest returns the most permissive limit among the
// subject's roles (0 means unlimited).
func (e *Engine) MaxChangesPerRequest(s *identity.Subject) int {
	sn := e.snap()
	if s == nil {
		return sn.maxChanges
	}
	best := -2
	for _, name := range s.Roles {
		cr := sn.role(name)
		if cr == nil {
			continue
		}
		v := cr.role.MaxChangesPerRequest
		switch {
		case v == -1:
			return 0
		case v == 0:
			v = sn.maxChanges
		}
		if v > best {
			best = v
		}
	}
	if best < 0 {
		return sn.maxChanges
	}
	return best
}

// RebaseOnSave is true when any role of the subject enables it.
func (e *Engine) RebaseOnSave(s *identity.Subject) bool {
	if s == nil {
		return false
	}
	sn := e.snap()
	for _, name := range s.Roles {
		if cr := sn.role(name); cr != nil && cr.role.RebaseOnSave {
			return true
		}
	}
	return false
}

// EphemeralTTL is the shortest ephemeral TTL among the subject's write
// roles, or 0 if any write role creates permanent records.
func (e *Engine) EphemeralTTL(s *identity.Subject) time.Duration {
	if s == nil {
		return 0
	}
	sn := e.snap()
	var ttl time.Duration
	for _, name := range s.Roles {
		cr := sn.role(name)
		if cr == nil {
			continue
		}
		writes := false
		for _, r := range cr.role.Rules {
			writes = writes || contains(r.Actions, ActionRecordWrite)
		}
		if !writes {
			continue
		}
		if cr.ephemeral <= 0 {
			return 0
		}
		if ttl == 0 || cr.ephemeral < ttl {
			ttl = cr.ephemeral
		}
	}
	return ttl
}

func hostMatches(patterns []string, host string) bool {
	for _, p := range patterns {
		p = strings.ToLower(p)
		if p == host || p == "**" || rrset.MatchHost(p, host) {
			return true
		}
	}
	return false
}

func typeMatches(types []string, t string) bool {
	for _, x := range types {
		if x == "*" || strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}

func normKey(k rrset.Key) rrset.Key {
	h := strings.TrimSuffix(strings.ToLower(k.Host), ".")
	if h == "" {
		h = "@"
	}
	return rrset.Key{Host: h, Type: strings.ToUpper(k.Type)}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
