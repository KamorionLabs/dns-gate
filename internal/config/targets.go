package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/glob"
)

// TargetOwner labels the targets of RRsets (CNAME, alias, MX, NS, SRV, PTR,
// EuroDNS APEX) with who runs them: a legacy provider, a production
// account, a SaaS. The first entry that matches a target wins, so specific
// entries (one distribution) go before general ones (a whole service).
type TargetOwner struct {
	// Match is a suffix ("cloudfront.net" matches the name itself and the
	// names below it) or, with "*" or "?", a glob on the whole name
	// ("d1234*.cloudfront.net"). Case-insensitive, without trailing dot.
	Match string `yaml:"match"`
	// Owner is the label shown, e.g. "NBS legacy" or "Microsoft 365".
	Owner string `yaml:"owner"`
}

// maxTargetOwners bounds the table: every listed RRset is matched against it.
const maxTargetOwners = 1024

var targetMatchRe = regexp.MustCompile(`^[a-z0-9_*?]([a-z0-9_*?.-]*[a-z0-9_*?])?$`)

// normTargetName lowers a name and drops its trailing dot.
func normTargetName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// MatchTargetOwner returns the owner of the first entry matching name, ""
// when none does.
func MatchTargetOwner(owners []TargetOwner, name string) string {
	n := normTargetName(name)
	if n == "" {
		return ""
	}
	for _, o := range owners {
		m := normTargetName(o.Match)
		if strings.ContainsAny(m, "*?") {
			if glob.Match(m, n) {
				return o.Owner
			}
		} else if n == m || strings.HasSuffix(n, "."+m) {
			return o.Owner
		}
	}
	return ""
}

func (c *Config) validateTargetOwners(add func(string, ...any)) {
	if len(c.TargetOwners) > maxTargetOwners {
		add("target_owners: at most %d entries", maxTargetOwners)
	}
	seen := map[string]bool{}
	for i, o := range c.TargetOwners {
		at := fmt.Sprintf("target_owners[%d]", i)
		m := normTargetName(o.Match)
		switch {
		case m == "":
			add("%s.match: required", at)
		case m == "*":
			add("%s.match: \"*\" would label every target", at)
		case len(m) > 253 || !targetMatchRe.MatchString(m):
			add("%s.match: %q is not a host name suffix or glob", at, o.Match)
		case seen[m]:
			add("%s.match: %q is listed twice", at, o.Match)
		}
		seen[m] = true
		if owner := strings.TrimSpace(o.Owner); owner == "" {
			add("%s.owner: required", at)
		} else if len(owner) > 64 {
			add("%s.owner: at most 64 characters", at)
		}
	}
}
