package tfexport

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
)

var update = flag.Bool("update", false, "rewrite golden files")

func set(typ, host string, ttl int, values ...string) dns.RRset {
	return dns.RRset{Key: dns.Key{Host: host, Type: typ}, TTL: ttl, Values: values}
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

func zoneSets() []dns.RRset {
	soa := set("SOA", "@", 86400, "ns1.example.net. hostmaster.example.com. 1 2 3 4 5")
	ns := set("NS", "@", 86400, "ns1.example.net.")
	ns.ReadOnly = "server_managed"
	return []dns.RRset{
		soa, ns,
		set("A", "@", 3600, "192.0.2.10"),
		set("MX", "@", 3600, "20 mx2.example.net.", "10 mx1.example.net."),
		set("A", "www", 600, "192.0.2.2", "192.0.2.1"),
		set("CNAME", "*.app", 3600, "app.example.net."),
		set("TXT", "_acme-challenge.www", 600, "token"),
		set("TXT", "@", 3600, `"v=spf1 include:_spf.example.net -all"`),
		set("TXT", "tpl", 3600, `${var.x} and %{if} \ "q"`),
		set("A", "3d", 3600, "192.0.2.3"),
		set("A", "a.b", 3600, "192.0.2.4"),
		set("A", "a-b", 3600, "192.0.2.5"),
		set("AAAA", "multi", 3600, "2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4", "2001:db8::5"),
		{Key: dns.Key{Host: "cdn", Type: "AAAA"}, Alias: &dns.Alias{Target: "d1.cloudfront.net.", HostedZoneID: "Z2FDTNDATAQYW2"}},
		{Key: dns.Key{Host: "lb", Type: "A"}, TTL: 60, Alias: &dns.Alias{Target: "lb-1.eu-west-3.elb.amazonaws.com.", HostedZoneID: "Z3Q77PNBQS71R4", EvaluateTargetHealth: true}},
		set("TXT", "empty", 3600),
		{Key: dns.ForwardKey("go"), Forward: &dns.Forward{Mode: "301", URL: "https://example.net/"}},
		{Key: dns.ForwardKey("@"), Forward: &dns.Forward{Mode: "frame", URL: "https://shop.example.net/", Title: "Shop \"x\""}},
		{Key: dns.ForwardKey("odd"), Forward: &dns.Forward{Mode: "magic", URL: "x"}, ReadOnly: "unsupported_forward"},
	}
}

func TestRenderZone(t *testing.T) {
	golden(t, "zone", Render("Example.com.", zoneSets(), Options{Header: []string{"Team: web", "Review before applying."}}))
}

func TestRenderZoneEuroDNS(t *testing.T) {
	out := Render("example.com", zoneSets(), Options{Provider: ProviderEuroDNS})
	if strings.Contains(out, "alias") || strings.Contains(out, "cloudfront") {
		t.Fatalf("alias RRsets exported for the eurodns provider:\n%s", out)
	}
	golden(t, "zone_eurodns", out)
}

func TestRenderNoImportsAndPrefix(t *testing.T) {
	golden(t, "noimport", Render("example.com", []dns.RRset{set("A", "www", 3600, "192.0.2.1")}, Options{SkipImports: true, ResourcePrefix: "web_"}))
}

func TestParseProvider(t *testing.T) {
	for in, want := range map[string]Provider{"": ProviderDNSGate, "dnsgate": ProviderDNSGate, "EuroDNS": ProviderEuroDNS} {
		if got, ok := ParseProvider(in); !ok || got != want {
			t.Errorf("ParseProvider(%q) = %q %v", in, got, ok)
		}
	}
	if _, ok := ParseProvider("route53"); ok {
		t.Error("unknown provider accepted")
	}
}

func TestResourceNamesUniqueAndValid(t *testing.T) {
	in := []dns.RRset{set("A", "a.b", 3600, "192.0.2.1"), set("A", "a_b", 3600, "192.0.2.2"), set("A", "a..b", 3600, "192.0.2.3")}
	out := Render("example.com", in, Options{})
	for _, want := range []string{`"a_b_a" {`, `"a_b_a_2" {`, `"a_b_a_3" {`, "to = dnsgate_record_set.a_b_a_3"} {
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
