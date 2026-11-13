package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// Bounds of a scan across zones (search_records, export_records). Zones not
// in the cache are read upstream, so a first scan of many unmanaged zones
// can be slow: it stops at the deadline and says which zones it skipped.
var (
	scanConcurrency = 4
	scanTimeout     = 25 * time.Second
)

const (
	searchDefaultLimit = 500
	searchMaxLimit     = 5000
	exportMaxRecords   = 50000
	listMaxLimit       = 1000
)

// Record is the compact form of an RRset: no hash, actors, dates or
// request ids. Zone is empty when the zone is implied (list_rrsets).
type Record struct {
	Zone    string       `json:"zone,omitempty"`
	Host    string       `json:"host"`
	Type    string       `json:"type"`
	TTL     int          `json:"ttl,omitempty"`
	Values  []string     `json:"values,omitempty"`
	Alias   *dns.Alias   `json:"alias,omitempty"`
	Forward *dns.Forward `json:"forward,omitempty"`
	Status  string       `json:"status"`
	Owner   string       `json:"owner,omitempty"`
	// TargetOwner and Targets: see uiapi.RRset (target_owners, resolve).
	TargetOwner string                   `json:"target_owner,omitempty"`
	Targets     []uiapi.TargetResolution `json:"targets,omitempty"`
}

func compactRecord(zone string, rs uiapi.RRset) Record {
	r := Record{Zone: zone, Host: rs.Host, Type: rs.Type, TTL: rs.TTL, Alias: rs.Alias, Forward: rs.Forward, Status: rs.Status, Owner: rs.Owner,
		TargetOwner: rs.TargetOwner, Targets: rs.Targets}
	if len(rs.Values) > 0 {
		r.Values = append([]string{}, rs.Values...)
	}
	return r
}

// SkippedZone is a zone a scan could not read.
type SkippedZone struct {
	Zone   string `json:"zone"`
	Reason string `json:"reason"` // timeout, or why the zone could not be read
}

// recordFilter selects RRsets by globs (case-insensitive, * and ?). Value
// matches any value of the RRset, the target of an alias or the URL of a
// forward.
type recordFilter struct {
	Value, Host, Type string
}

func (f recordFilter) normalize() recordFilter {
	return recordFilter{Value: strings.ToLower(strings.TrimSpace(f.Value)), Host: strings.ToLower(strings.TrimSpace(f.Host)), Type: strings.ToUpper(strings.TrimSpace(f.Type))}
}

func (f recordFilter) match(rs uiapi.RRset) bool {
	if f.Host != "" && !glob.Match(f.Host, strings.ToLower(rs.Host)) {
		return false
	}
	if f.Type != "" && !glob.Match(f.Type, strings.ToUpper(rs.Type)) {
		return false
	}
	if f.Value == "" {
		return true
	}
	for _, v := range recordValues(rs) {
		if glob.Match(f.Value, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

// recordValues are the values a value glob is matched against.
func recordValues(rs uiapi.RRset) []string {
	out := append([]string{}, rs.Values...)
	if rs.Alias != nil {
		out = append(out, rs.Alias.Target)
	}
	if rs.Forward != nil {
		out = append(out, rs.Forward.URL)
	}
	return out
}

// scanResult is the inventories read by a scan, in zone order.
type scanResult struct {
	Zones   []*uiapi.ZoneInventory
	Skipped []SkippedZone
}

// scanZones lists the zones of readable matching folder (every zone when
// folder is ""), in name order.
func (s *Server) scanZones(readable map[string]bool, folder string) []string {
	snap := s.cfg.Policy.Current()
	out := make([]string, 0, len(readable))
	for z := range readable {
		if folder != "" && !glob.MatchFolder(folder, snap.Folder(z)) {
			continue
		}
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

// scan reads the inventory of zones with bounded concurrency through the
// engine and its cache, until scanTimeout. A zone not read in time, or that
// cannot be read, is skipped with its reason; a read cut by the deadline
// still completes in the background and fills the cache for the next scan.
func (s *Server) scan(ctx context.Context, subj *identity.Subject, zones []string) scanResult {
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	invs := make([]*uiapi.ZoneInventory, len(zones))
	reasons := make([]string, len(zones))
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < min(scanConcurrency, len(zones)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				invs[i], reasons[i] = s.readInventory(ctx, subj, zones[i])
			}
		}()
	}
	for i := range zones {
		if ctx.Err() != nil {
			reasons[i] = "timeout"
			continue
		}
		select {
		case next <- i:
		case <-ctx.Done():
			reasons[i] = "timeout"
		}
	}
	close(next)
	wg.Wait()
	var res scanResult
	for i, z := range zones {
		if invs[i] != nil {
			res.Zones = append(res.Zones, invs[i])
		} else {
			res.Skipped = append(res.Skipped, SkippedZone{Zone: z, Reason: reasons[i]})
		}
	}
	return res
}

// readInventory reads one zone, giving up at the deadline of ctx (the
// engine read itself is not cancelled).
func (s *Server) readInventory(ctx context.Context, subj *identity.Subject, zone string) (*uiapi.ZoneInventory, string) {
	if ctx.Err() != nil {
		return nil, "timeout"
	}
	type result struct {
		inv *uiapi.ZoneInventory
		err error
	}
	ch := make(chan result, 1)
	go func() {
		inv, err := s.cfg.Engine.Inventory(ctx, subj, zone)
		ch <- result{inv, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, scanError(r.err)
		}
		return r.inv, ""
	case <-ctx.Done():
		return nil, "timeout"
	}
}

// scanError is the reason a zone was skipped, without upstream details.
func scanError(err error) string {
	if ze, ok := zonewrite.AsError(err); ok && (ze.Reason == zonewrite.ReasonForbidden || ze.Reason == zonewrite.ReasonNotFound) {
		return ze.Message
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "inventory unavailable"
}

// searchResult is the answer of a search across zones.
type searchResult struct {
	Records      []Record      `json:"records"`
	ZonesScanned int           `json:"zones_scanned"`
	ZonesSkipped []SkippedZone `json:"zones_skipped,omitempty"`
	// Truncated is set when more records matched than limit.
	Truncated bool `json:"truncated,omitempty"`
}

// searchRecords returns the RRsets matching f in the scanned zones, up to
// limit.
func searchRecords(res scanResult, f recordFilter, limit int) searchResult {
	out := searchResult{Records: []Record{}, ZonesScanned: len(res.Zones), ZonesSkipped: res.Skipped}
	f = f.normalize()
	for _, inv := range res.Zones {
		for _, rs := range inv.RRsets {
			if rs.Status == uiapi.StatusMissing || rs.Status == uiapi.StatusPending || !f.match(rs) {
				continue
			}
			if len(out.Records) >= limit {
				out.Truncated = true
				return out
			}
			out.Records = append(out.Records, compactRecord(inv.Zone, rs))
		}
	}
	return out
}

// searchLimit clamps a requested limit.
func searchLimit(n int) (int, error) {
	switch {
	case n == 0:
		return searchDefaultLimit, nil
	case n < 0 || n > searchMaxLimit:
		return 0, fmt.Errorf("limit must be between 1 and %d", searchMaxLimit)
	}
	return n, nil
}

// Export formats.
const (
	exportTSV  = "tsv"
	exportZone = "zone"
)

// exportResult is the summary of an export; the export itself is text.
type exportResult struct {
	Format       string        `json:"format"`
	Records      int           `json:"records"`
	ZonesScanned int           `json:"zones_scanned"`
	ZonesSkipped []SkippedZone `json:"zones_skipped,omitempty"`
	Truncated    bool          `json:"truncated,omitempty"`
}

// exportRecords renders the RRsets matching f as TSV (one line per value:
// zone, host, type, ttl, value, status, owner) or as zone files (one
// $ORIGIN block per zone; URL forwards and aliases as comments).
func exportRecords(res scanResult, f recordFilter, format string) (string, exportResult) {
	sum := exportResult{Format: format, ZonesScanned: len(res.Zones), ZonesSkipped: res.Skipped}
	f = f.normalize()
	var b strings.Builder
	if format == exportTSV {
		b.WriteString("zone\thost\ttype\tttl\tvalue\tstatus\towner\n")
	}
	for _, inv := range res.Zones {
		header := false
		for _, rs := range inv.RRsets {
			if rs.Status == uiapi.StatusMissing || rs.Status == uiapi.StatusPending || !f.match(rs) {
				continue
			}
			if sum.Records >= exportMaxRecords {
				sum.Truncated = true
				return b.String(), sum
			}
			sum.Records++
			if format == exportTSV {
				writeTSV(&b, inv.Zone, rs)
				continue
			}
			if !header {
				if b.Len() > 0 {
					b.WriteString("\n")
				}
				fmt.Fprintf(&b, "$ORIGIN %s.\n", inv.Zone)
				header = true
			}
			writeZoneLines(&b, rs)
		}
	}
	return b.String(), sum
}

func tsvField(s string) string {
	return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r").Replace(s)
}

func writeTSV(b *strings.Builder, zone string, rs uiapi.RRset) {
	line := func(value string) {
		fmt.Fprintf(b, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", zone, tsvField(rs.Host), rs.Type, rs.TTL, tsvField(value), rs.Status, rs.Owner)
	}
	switch {
	case rs.Forward != nil:
		line(rs.Forward.Mode + " " + rs.Forward.URL)
	case rs.Alias != nil:
		line("ALIAS " + rs.Alias.Target)
	case len(rs.Values) == 0:
		line("")
	default:
		for _, v := range rs.Values {
			line(v)
		}
	}
}

func writeZoneLines(b *strings.Builder, rs uiapi.RRset) {
	owner := fmt.Sprintf("; status=%s", rs.Status)
	if rs.Owner != "" {
		owner += " owner=" + rs.Owner
	}
	switch {
	case rs.Forward != nil:
		fmt.Fprintf(b, "; %s URLFWD %s %s %s\n", rs.Host, rs.Forward.Mode, rs.Forward.URL, owner)
		return
	case rs.Alias != nil:
		fmt.Fprintf(b, "; %s %s ALIAS %s %s\n", rs.Host, rs.Type, rs.Alias.Target, owner)
		return
	}
	for _, v := range rs.Values {
		if strings.EqualFold(rs.Type, "TXT") || strings.EqualFold(rs.Type, "SPF") {
			v = quoteTXT(v)
		}
		fmt.Fprintf(b, "%s\t%d\tIN\t%s\t%s\t%s\n", rs.Host, rs.TTL, rs.Type, v, owner)
	}
}

// quoteTXT quotes a raw TXT value as RFC 1035 character strings of at most
// 255 bytes: " and \ escaped, other non-printable bytes as \DDD.
func quoteTXT(v string) string {
	var parts []string
	for {
		n := min(len(v), 255)
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < n; i++ {
			c := v[i]
			switch {
			case c == '"' || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			case c < 0x20 || c >= 0x7f:
				b.WriteString(fmt.Sprintf("\\%03d", c))
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('"')
		parts = append(parts, b.String())
		v = v[n:]
		if v == "" {
			break
		}
	}
	return strings.Join(parts, " ")
}

// listCursor is the opaque position of a page of list_rrsets: the last
// host and type returned.
func encodeListCursor(host, typ string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(host + "\t" + typ))
}

func decodeListCursor(c string) (string, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", "", errors.New("invalid cursor")
	}
	host, typ, ok := strings.Cut(string(b), "\t")
	if !ok {
		return "", "", errors.New("invalid cursor")
	}
	return host, typ, nil
}

// afterCursor reports whether an RRset sorts after the cursor position
// (inventories are sorted by host, then type).
func afterCursor(host, typ, cHost, cType string) bool {
	if host != cHost {
		return host > cHost
	}
	return typ > cType
}
