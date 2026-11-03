// Package glob implements the wildcard matching used for claims and zones:
// "*" matches any sequence of characters (including "/" and "."), "?" one
// character. Matching is exact otherwise.
package glob

// Match reports whether s matches pattern.
func Match(pattern, s string) bool {
	p, str := []rune(pattern), []rune(s)
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(str) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == str[si]):
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Any reports whether s matches at least one pattern.
func Any(patterns []string, s string) bool {
	for _, p := range patterns {
		if Match(p, s) {
			return true
		}
	}
	return false
}

// Covered reports whether every string matched by pattern is matched by one
// of the bounds, by matching the pattern text with each bound. This is sound
// for "*" wildcards only: a pattern or bound containing "?" is never
// considered covered (a "?" of the bound could match a "*" of the pattern).
func Covered(bounds []string, pattern string) bool {
	if containsRune(pattern, '?') {
		return false
	}
	for _, b := range bounds {
		if !containsRune(b, '?') && Match(b, pattern) {
			return true
		}
	}
	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
