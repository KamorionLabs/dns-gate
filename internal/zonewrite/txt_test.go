package zonewrite

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// txtWireValues are TXT values as the web console sends them: the text
// unquoted at any length, or in presentation format when the text itself
// starts and ends with a double quote.
var txtWireValues = []string{
	"v=spf1 include:_spf.example.net -all",
	"v=DKIM1; k=rsa; p=" + strings.Repeat("A", 400),
	`say "hi"`,
	`"\"quoted\""`,
}

// The values the console sends are written to EuroDNS as sent and read back
// unchanged, with the hash the console uses as If-Match.
func TestTXTRoundTripEuroDNS(t *testing.T) {
	e := newEnv(t, eurodnstest.Options{})
	ctx := context.Background()
	for i, v := range txtWireValues {
		host := "txt" + string(rune('a'+i))
		if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, []uiapi.RRsetChange{{Host: host, Type: "TXT", TTL: 3600, Values: []string{v}, MustNotExist: true}}, 0); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if got := e.upstream(host, "TXT"); !slices.Equal(got, []string{v}) {
			t.Fatalf("stored %q, sent %q", got, v)
		}
		rs, err := e.eng.RRset(ctx, alice, zoneName, dns.Key{Host: host, Type: "TXT"})
		if err != nil {
			t.Fatal(err)
		}
		want := dns.ContentHash(dns.RRset{Key: dns.Key{Host: host, Type: "TXT"}, TTL: 3600, Values: []string{v}})
		if !slices.Equal(rs.Values, []string{v}) || rs.Hash != want {
			t.Fatalf("read back %q hash %s, want %q hash %s", rs.Values, rs.Hash, v, want)
		}
	}
}
