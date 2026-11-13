package server

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// recordsEnv is folderEnv with distinct RRsets per zone: example.com (/ES),
// example.org (no folder), new.example.net (/ES/Madrid, unmanaged) and
// other.net (/, unmanaged).
func recordsEnv(t *testing.T) *env {
	t.Helper()
	e := folderEnv(t)
	e.engine.rrsets = map[string][]uiapi.RRset{
		"example.com": {
			{Host: "@", Type: "TXT", TTL: 3600, Values: []string{`v=spf1 include:"x" ~all`}, Status: uiapi.StatusForeign, Hash: "h1"},
			{Host: "app", Type: "CNAME", TTL: 600, Values: []string{"d1.cloudfront.net."}, Status: uiapi.StatusManaged, Owner: "web", Hash: "h2", LastRequestID: "req-1"},
			{Host: "go", Type: dns.TypeURLForward, Forward: &dns.Forward{Mode: "301", URL: "https://www.example.com/"}, Status: uiapi.StatusForeign},
			{Host: "gone", Type: "A", Values: []string{}, Status: uiapi.StatusMissing, Owner: "web"},
			{Host: "shop", Type: "CNAME", TTL: 600, Values: []string{"lb.nbs-aws.com."}, Status: uiapi.StatusForeign},
			{Host: "www", Type: "A", TTL: 600, Values: []string{"192.0.2.1", "192.0.2.2"}, Status: uiapi.StatusManaged, Owner: "web"},
		},
		"example.org":     {{Host: "legacy", Type: "CNAME", TTL: 600, Values: []string{"old.NBS-AWS.com."}, Status: uiapi.StatusForeign}},
		"new.example.net": {{Host: "@", Type: "A", TTL: 600, Alias: &dns.Alias{Target: "x.nbs-aws.com."}, Status: uiapi.StatusForeign}},
		"other.net":       {{Host: "mail", Type: "MX", TTL: 600, Values: []string{"10 mx.other.net."}, Status: uiapi.StatusForeign}},
	}
	return e
}

func TestRecordFilter(t *testing.T) {
	rs := uiapi.RRset{Host: "App", Type: "CNAME", Values: []string{"D1.cloudfront.net."}}
	for _, c := range []struct {
		f    recordFilter
		want bool
	}{
		{recordFilter{}, true},
		{recordFilter{Value: "*.cloudfront.net."}, true},
		{recordFilter{Value: "cloudfront"}, false}, // a glob, not a substring
		{recordFilter{Host: "app", Type: "c*"}, true},
		{recordFilter{Type: "A"}, false},
		{recordFilter{Host: "www"}, false},
	} {
		if got := c.f.normalize().match(rs); got != c.want {
			t.Errorf("%+v: %v", c.f, got)
		}
	}
	fwd := uiapi.RRset{Host: "go", Type: dns.TypeURLForward, Forward: &dns.Forward{URL: "https://shop.example.com/"}}
	if !(recordFilter{Value: "*shop.example.com*"}).normalize().match(fwd) {
		t.Error("forward URL not matched")
	}
}

func TestSearchAndExportRender(t *testing.T) {
	e := recordsEnv(t)
	res := scanResult{Zones: []*uiapi.ZoneInventory{{Zone: "example.com", RRsets: e.engine.rrsets["example.com"]}}, Skipped: []SkippedZone{{Zone: "x.net", Reason: "timeout"}}}

	out := searchRecords(res, recordFilter{}, 3)
	if !out.Truncated || len(out.Records) != 3 || out.ZonesScanned != 1 || len(out.ZonesSkipped) != 1 {
		t.Fatalf("search: %+v", out)
	}
	for _, r := range searchRecords(res, recordFilter{}, 100).Records {
		if r.Status == uiapi.StatusMissing {
			t.Fatal("missing RRsets are not records")
		}
	}

	tsv, sum := exportRecords(res, recordFilter{}, exportTSV)
	lines := strings.Split(strings.TrimSuffix(tsv, "\n"), "\n")
	if sum.Records != 5 || len(lines) != 7 || lines[0] != "zone\thost\ttype\tttl\tvalue\tstatus\towner" {
		t.Fatalf("tsv: %+v\n%s", sum, tsv)
	}
	for _, want := range []string{
		"example.com\twww\tA\t600\t192.0.2.2\tmanaged\tweb",
		"example.com\tgo\tURLFWD\t0\t301 https://www.example.com/\tforeign\t",
	} {
		if !strings.Contains(tsv, want+"\n") {
			t.Errorf("tsv lacks %q:\n%s", want, tsv)
		}
	}

	zf, _ := exportRecords(res, recordFilter{Type: "TXT|CNAME"}, exportZone)
	if zf != "" {
		t.Fatalf("no type matches TXT|CNAME: %q", zf)
	}
	zf, _ = exportRecords(res, recordFilter{}, exportZone)
	for _, want := range []string{
		"$ORIGIN example.com.\n",
		"@\t3600\tIN\tTXT\t\"v=spf1 include:\\\"x\\\" ~all\"\t; status=foreign\n",
		"app\t600\tIN\tCNAME\td1.cloudfront.net.\t; status=managed owner=web\n",
		"; go URLFWD 301 https://www.example.com/ ; status=foreign\n",
	} {
		if !strings.Contains(zf, want) {
			t.Errorf("zone file lacks %q:\n%s", want, zf)
		}
	}
}

func TestQuoteTXT(t *testing.T) {
	long := strings.Repeat("a", 300)
	if got := quoteTXT(long); got != `"`+strings.Repeat("a", 255)+`" "`+strings.Repeat("a", 45)+`"` {
		t.Fatalf("split: %s", got)
	}
	if got := quoteTXT("é\t"); got != `"\195\169\009"` {
		t.Fatalf("escape: %s", got)
	}
}

func TestListCursor(t *testing.T) {
	h, typ, err := decodeListCursor(encodeListCursor("www", "A"))
	if err != nil || h != "www" || typ != "A" {
		t.Fatalf("%q %q %v", h, typ, err)
	}
	if _, _, err := decodeListCursor("!!"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	if !afterCursor("www", "AAAA", "www", "A") || afterCursor("app", "A", "www", "A") {
		t.Fatal("order")
	}
}

func TestScanDeadlineAndErrors(t *testing.T) {
	e := recordsEnv(t)
	old := scanTimeout
	scanTimeout = 200 * time.Millisecond
	t.Cleanup(func() { scanTimeout = old })
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	e.engine.block = map[string]chan struct{}{"other.net": block}
	e.engine.errs = map[string]error{"example.org": &zonewrite.Error{Reason: zonewrite.ReasonNotFound, Message: "zone example.org: not found upstream"}}

	cs := connect(t, e, e.token("reader"))
	var out searchResult
	start := time.Now()
	res := call(t, cs, "search_records", map[string]any{"value": "*nbs-aws.com*"}, &out)
	if res.IsError {
		t.Fatal(errText(res))
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the deadline did not stop the scan")
	}
	skipped := map[string]string{}
	for _, z := range out.ZonesSkipped {
		skipped[z.Zone] = z.Reason
	}
	if skipped["other.net"] != "timeout" || !strings.Contains(skipped["example.org"], "not found upstream") || out.ZonesScanned != 2 {
		t.Fatalf("skipped: %+v", out)
	}
	if len(out.Records) != 2 || out.Records[0].Zone != "example.com" || out.Records[1].Zone != "new.example.net" {
		t.Fatalf("records: %+v", out.Records)
	}
}

func TestMCPSearchRecords(t *testing.T) {
	e := recordsEnv(t)
	cs := connect(t, e, e.token("reader"))
	tools := toolNames(t, cs)
	for _, n := range []string{"search_records", "export_records"} {
		if tools[n] == nil || !tools[n].Annotations.ReadOnlyHint {
			t.Fatalf("%s missing or not read-only", n)
		}
	}

	var out searchResult
	if res := call(t, cs, "search_records", map[string]any{"value": "*NBS-AWS.COM*"}, &out); res.IsError || len(out.Records) != 3 || out.ZonesScanned != 4 {
		t.Fatalf("search: %s %+v", errText(res), out)
	}
	out = searchResult{}
	if res := call(t, cs, "search_records", map[string]any{"value": "*nbs-aws.com*", "folder": "/ES"}, &out); res.IsError || len(out.Records) != 1 || out.Records[0].Zone != "example.com" {
		t.Fatalf("folder: %s %+v", errText(res), out)
	}
	out = searchResult{}
	if res := call(t, cs, "search_records", map[string]any{"type": "CNAME", "zone": "example.com"}, &out); res.IsError || len(out.Records) != 2 {
		t.Fatalf("zone: %s %+v", errText(res), out)
	}
	raw := call(t, cs, "search_records", map[string]any{"host": "app"}, nil)
	if b, _ := json.Marshal(raw.StructuredContent); strings.Contains(string(b), "hash") || strings.Contains(string(b), "req-1") {
		t.Fatalf("records are not compact: %s", b)
	}
	if res := call(t, cs, "search_records", map[string]any{"limit": 9999}, nil); !res.IsError {
		t.Fatal("limit above the maximum")
	}
	if res := call(t, cs, "search_records", map[string]any{"folder": "ES"}, nil); !res.IsError {
		t.Fatal("invalid folder accepted")
	}

	es := connect(t, e, e.token("es"))
	out = searchResult{}
	if res := call(t, es, "search_records", map[string]any{"value": "*nbs-aws.com*"}, &out); res.IsError || out.ZonesScanned != 1 || len(out.Records) != 1 {
		t.Fatalf("scope of a folder reader: %s %+v", errText(res), out)
	}
	if res := call(t, es, "search_records", map[string]any{"zone": "other.net"}, nil); !res.IsError {
		t.Fatal("unreadable zone searched")
	}

	var sum exportResult
	res := call(t, cs, "export_records", map[string]any{"format": "tsv", "zone": "example.com"}, &sum)
	if res.IsError || sum.Records != 5 || sum.Format != "tsv" || !strings.HasPrefix(errText(res), "zone\thost\t") {
		t.Fatalf("export: %s %+v", errText(res), sum)
	}
	if res := call(t, cs, "export_records", map[string]any{"format": "zone", "folder": "/"}, &sum); res.IsError || !strings.Contains(errText(res), "$ORIGIN other.net.") || sum.ZonesScanned != 1 {
		t.Fatalf("zone export: %s %+v", errText(res), sum)
	}
	if res := call(t, cs, "export_records", map[string]any{"format": "csv"}, nil); !res.IsError {
		t.Fatal("unknown format accepted")
	}

	audited := map[string]bool{}
	for _, ev := range e.audit.events {
		if ev.Action == "mcp.search_records" && ev.Extra["value"] == "*NBS-AWS.COM*" && ev.Extra["records"] == 3 {
			audited["search"] = true
		}
		if ev.Action == "mcp.export_records" && ev.Extra["format"] == "zone" {
			audited["export"] = true
		}
	}
	if !audited["search"] || !audited["export"] {
		t.Fatalf("not audited: %v", audited)
	}
}

func TestMCPListRRsetsCompactPages(t *testing.T) {
	e := recordsEnv(t)
	cs := connect(t, e, e.token("reader"))

	var full listRRsetsOut
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com"}, &full); res.IsError || len(full.RRsets) != 6 || full.Records != nil || full.NextCursor != "" {
		t.Fatalf("default: %s %+v", errText(res), full)
	}

	var got []string
	cursor := ""
	for i := 0; ; i++ {
		args := map[string]any{"zone": "example.com", "compact": true, "limit": 4}
		if cursor != "" {
			args["cursor"] = cursor
		}
		raw := call(t, cs, "list_rrsets", args, nil)
		var page listRRsetsOut
		b, _ := json.Marshal(raw.StructuredContent)
		_ = json.Unmarshal(b, &page)
		if raw.IsError || len(page.RRsets) != 0 || strings.Contains(string(b), `"hash"`) {
			t.Fatalf("page %d: %s %s", i, errText(raw), b)
		}
		for _, r := range page.Records {
			got = append(got, r.Host+"/"+r.Type)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
		if i > 3 {
			t.Fatal("no end")
		}
	}
	if strings.Join(got, ",") != "@/TXT,app/CNAME,go/URLFWD,gone/A,shop/CNAME,www/A" {
		t.Fatalf("pages: %v", got)
	}
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "cursor": "%%"}, nil); !res.IsError {
		t.Fatal("bad cursor accepted")
	}
	if res := call(t, cs, "list_rrsets", map[string]any{"zone": "example.com", "limit": 5000}, nil); !res.IsError {
		t.Fatal("limit above the maximum")
	}
}

func TestRecordsAPI(t *testing.T) {
	e := recordsEnv(t)
	tok := e.token("reader")
	r := e.do(t, "GET", "/api/v1/records?value=*nbs-aws.com*&limit=2", tok, "", nil)
	var out searchResult
	_ = json.NewDecoder(r.Body).Decode(&out)
	if r.StatusCode != 200 || len(out.Records) != 2 || !out.Truncated {
		t.Fatalf("search: %d %+v", r.StatusCode, out)
	}
	if r := e.do(t, "GET", "/api/v1/records?limit=x", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("bad limit: %d", r.StatusCode)
	}

	r = e.do(t, "GET", "/api/v1/records/export?zone=example.com", tok, "", nil)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/tab-separated-values") || r.Header.Get("X-Records") != "5" ||
		!strings.Contains(string(b), "example.com\tshop\tCNAME\t600\tlb.nbs-aws.com.\tforeign\t\n") {
		t.Fatalf("export: %d %v\n%s", r.StatusCode, r.Header, b)
	}
	r = e.do(t, "GET", "/api/v1/records/export?format=zone&folder=/ES/**", tok, "", nil)
	b, _ = io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "$ORIGIN new.example.net.\n; @ A ALIAS x.nbs-aws.com.") || r.Header.Get("X-Zones-Scanned") != "1" {
		t.Fatalf("zone export: %d\n%s", r.StatusCode, b)
	}
	if r := e.do(t, "GET", "/api/v1/records/export?format=bind", tok, "", nil); r.StatusCode != 400 {
		t.Fatalf("bad format: %d", r.StatusCode)
	}
	found := false
	for _, ev := range e.audit.events {
		if ev.Action == "api.export_records" && ev.Extra["via"] == "api" {
			found = true
		}
	}
	if !found {
		t.Fatal("export not audited")
	}
}
