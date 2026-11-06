package apikey

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	id := NewID()
	if !ValidID(id) {
		t.Fatalf("id %q", id)
	}
	key := NewSecret(id)
	got, ok := Parse(key)
	if !ok || got != id || !Looks(key) {
		t.Fatalf("parse %q: %q %v", key, got, ok)
	}
	h := Hash(key)
	if !Match(key, h) || Match(key+"x", h) || Match(key, "zz") || Match(key, strings.Repeat("0", 64)) {
		t.Fatal("match")
	}
	if NewSecret(id) == key {
		t.Fatal("secrets repeat")
	}
}

func TestParseRejects(t *testing.T) {
	good := NewSecret("0123456789abcdef")
	for _, k := range []string{
		"", "dgk_", good[:len(good)-1], good + "a", strings.Replace(good, "dgk_", "dgx_", 1),
		"dgk_0123456789ABCDEF_" + good[len("dgk_0123456789abcdef_"):],
		"dgk_0123456789abcdef-" + good[len("dgk_0123456789abcdef_"):],
		"dgk_0123456789abcdef_" + strings.Repeat("!", 43),
	} {
		if _, ok := Parse(k); ok {
			t.Errorf("accepted %q", k)
		}
	}
}
