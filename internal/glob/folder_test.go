package glob

import "testing"

func TestNormalizeFolder(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/": "/", " / ": "/", "ES": "/ES", "/ES/": "/ES", "/ES/Madrid": "/ES/Madrid", "ES/Madrid/": "/ES/Madrid",
	} {
		if got := NormalizeFolder(in); got != want {
			t.Errorf("NormalizeFolder(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchFolder(t *testing.T) {
	cases := []struct {
		p, f string
		want bool
	}{
		{"/ES", "/ES", true},
		{"/ES", "/ES/Madrid", false},
		{"/ES", "/es", false},
		{"/ES/**", "/ES", false},
		{"/ES/**", "/ES/Madrid", true},
		{"/ES/**", "/ES/Madrid/Centro", true},
		{"/ES/*", "/ES/Madrid", true},
		{"/ES/*", "/ES/Madrid/Centro", false},
		{"/E*", "/ES", true},
		{"/E*", "/FR", false},
		{"/", "/", true},
		{"/", "/ES", false},
		{"/**", "/", false},
		{"/**", "/ES/Madrid", true},
		{"/*", "/", false},
		{"/ES", "", false},
		{"/**", "", false},
		{"", "/", false},
	}
	for _, c := range cases {
		if got := MatchFolder(c.p, c.f); got != c.want {
			t.Errorf("MatchFolder(%q, %q) = %v", c.p, c.f, got)
		}
	}
	if !AnyFolder([]string{"/FR", "/ES/**"}, "/ES/Madrid") || AnyFolder(nil, "/ES") {
		t.Fatal("AnyFolder")
	}
}

func TestFolderCovered(t *testing.T) {
	cases := []struct {
		allowed []string
		p       string
		want    bool
	}{
		{[]string{"/ES/**"}, "/ES/Madrid", true},
		{[]string{"/ES/**"}, "/ES/**", true},
		{[]string{"/ES/**"}, "/ES/*", true},
		{[]string{"/ES/**"}, "/ES", false},
		{[]string{"/ES", "/ES/**"}, "/ES", true},
		{[]string{"/ES/*"}, "/ES/**", false},
		{[]string{"/ES/*"}, "/ES/M*", true},
		{[]string{"/**"}, "/", false},
		{[]string{"/"}, "/", true},
		{[]string{"/**"}, "/ES/**", true},
		{[]string{"/E*"}, "/ES", true},
		{[]string{"/ES/**"}, "/FR/**", false},
		{[]string{"/ES/**"}, "ES/x", false},
		{[]string{"bad"}, "/ES", false},
	}
	for _, c := range cases {
		if got := FolderCovered(c.allowed, c.p); got != c.want {
			t.Errorf("FolderCovered(%v, %q) = %v", c.allowed, c.p, got)
		}
	}
}

func TestValidFolderPattern(t *testing.T) {
	for _, p := range []string{"/", "/ES", "/ES/**", "/ES/*", "/Spain Office/Madrid", "/**"} {
		if err := ValidFolderPattern(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"", "ES", "/ES/", "//ES", "/ES//x", "/ES/a**", "/E?", "/ES/ ", "/a\x01"} {
		if ValidFolderPattern(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
}
