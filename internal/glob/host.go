package glob

import "strings"

const apex = "@"

// MatchHost reports whether a normalized host matches a host pattern where
// "*" matches exactly one label and "**" any number of labels (>= 1).
// Inside a label, "*" also matches any run of characters ("_*" matches
// "_acme-challenge"). "@" matches only the apex.
func MatchHost(pattern, host string) bool {
	p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if p == "" {
		p = apex
	}
	if h == "" {
		h = apex
	}
	if p == apex || h == apex {
		return p == h
	}
	return matchLabels(strings.Split(p, "."), strings.Split(h, "."))
}

func matchLabels(p, h []string) bool {
	if len(p) == 0 {
		return len(h) == 0
	}
	if p[0] == "**" {
		for i := 1; i <= len(h); i++ {
			if matchLabels(p[1:], h[i:]) {
				return true
			}
		}
		return false
	}
	if len(h) == 0 || !matchLabel(p[0], h[0]) {
		return false
	}
	return matchLabels(p[1:], h[1:])
}

func matchLabel(p, s string) bool {
	if !strings.Contains(p, "*") {
		return p == s
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last) && len(s) >= len(last)
}
