package glob

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true},
		{"*", "arn:aws:iam::1:role/a/b", true},
		{"arn:aws:iam::*:role/ci-*", "arn:aws:iam::111:role/ci-web", true},
		{"arn:aws:iam::*:role/ci-*", "arn:aws:iam::111:role/admin", false},
		{"repo:acme/web:*", "repo:acme/web:ref:refs/heads/main", true},
		{"repo:acme/web:*", "repo:acme/website:ref:main", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"*.example.com", "a.b.example.com", true},
	}
	for _, c := range cases {
		if got := Match(c.p, c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

func TestStarAgainstLiteralStar(t *testing.T) {
	if !Match("*.example.org", "*.b.example.org") || !Match("a*", "a*") {
		t.Fatal("a pattern star must expand over a literal star")
	}
}
