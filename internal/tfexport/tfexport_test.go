package tfexport

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sets(recs ...eurodns.Record) []dns.RRset {
	return eurodnsprov.FromNative("eurodns", "example.com", &eurodns.Zone{Records: recs}).RRsets
}

func r(typ, host string, ttl int, rdata string) eurodns.Record {
	return eurodns.Record{Type: typ, Host: host, TTL: ttl, RData: rdata}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch (run go test -update):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestRenderZone(t *testing.T) {
	locked := true
	in := sets(
		eurodns.Record{Type: "SOA", Host: "@", TTL: 86400, RData: "ns1.example.net. hostmaster.example.com. 1 2 3 4 5", Locked: &locked},
		eurodns.Record{Type: "NS", Host: "@", TTL: 86400, RData: "ns1.example.net.", Locked: &locked},
		r("A", "@", 3600, "192.0.2.10"),
		r("MX", "@", 3600, "20 mx2.example.net."),
		r("MX", "@", 3600, "10 mx1.example.net."),
		r("A", "www", 600, "192.0.2.2"),
		r("A", "www", 600, "192.0.2.1"),
		r("CNAME", "*.app", 3600, "app.example.net."),
		r("TXT", "_acme-challenge.www", 600, "token"),
		r("TXT", "@", 3600, `"v=spf1 include:_spf.example.net -all"`),
		r("TXT", "tpl", 3600, `${var.x} and %{if} \ "q"`),
		r("A", "3d", 3600, "192.0.2.3"),
		r("A", "a.b", 3600, "192.0.2.4"),
		r("A", "a-b", 3600, "192.0.2.5"),
		r("AAAA", "multi", 3600, "2001:db8::1"),
		r("AAAA", "multi", 3600, "2001:db8::2"),
		r("AAAA", "multi", 3600, "2001:db8::3"),
		r("AAAA", "multi", 3600, "2001:db8::4"),
		r("AAAA", "multi", 3600, "2001:db8::5"),
	)
	golden(t, "zone", Render("Example.com.", in, Options{Header: []string{"Team: web", "Review before applying."}}))
}

func TestRenderNoImportsAndPrefix(t *testing.T) {
	golden(t, "noimport", Render("example.com", sets(r("A", "www", 3600, "192.0.2.1")), Options{SkipImports: true, ResourcePrefix: "web_"}))
}

func TestResourceNamesUniqueAndValid(t *testing.T) {
	in := []dns.RRset{
		{Key: dns.Key{Host: "a.b", Type: "A"}, TTL: 3600, Values: []string{"192.0.2.1"}},
		{Key: dns.Key{Host: "a_b", Type: "A"}, TTL: 3600, Values: []string{"192.0.2.2"}},
		{Key: dns.Key{Host: "a..b", Type: "A"}, TTL: 3600, Values: []string{"192.0.2.3"}},
	}
	out := Render("example.com", in, Options{})
	for _, want := range []string{`"a_b_a" {`, `"a_b_a_2" {`, `"a_b_a_3" {`, "to = eurodns_record_set.a_b_a_3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	for _, tc := range []struct{ host, want string }{
		{"@", "apex_txt"}, {"*", "wildcard_txt"}, {"_dmarc", "dmarc_txt"}, {"9lives", "r_9lives_txt"}, {"--", "txt"},
	} {
		if got := resourceName("", dns.Key{Host: tc.host, Type: "TXT"}); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:           `"plain"`,
		`"q"`:             `"\"q\""`,
		`a\b`:             `"a\\b"`,
		"l1\nl2\t\x01":    `"l1\nl2\t\u0001"`,
		`${x} %{y} $ % {`: `"$${x} %%{y} $ % {"`,
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}
