package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/glob"
)

type searchRecordsIn struct {
	Value  string `json:"value,omitempty" jsonschema:"glob on the values (and alias targets, forward URLs), case-insensitive, * matches any characters: *.cloudfront.net. or *nbs-aws.com*"`
	Host   string `json:"host,omitempty" jsonschema:"glob on the host relative to its zone, @ is the apex"`
	Type   string `json:"type,omitempty" jsonschema:"glob on the record type, e.g. CNAME"`
	Folder string `json:"folder,omitempty" jsonschema:"optional EuroDNS folder glob, as for list_zones: /ES, /ES/**, /"`
	Zone   string `json:"zone,omitempty" jsonschema:"optional: one zone only"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records returned, 1 to 5000, default 500"`
}

type exportRecordsIn struct {
	Format string `json:"format,omitempty" jsonschema:"tsv (default: one line per value, columns zone host type ttl value status owner) or zone (zone file per zone)"`
	Folder string `json:"folder,omitempty" jsonschema:"optional EuroDNS folder glob, as for list_zones"`
	Zone   string `json:"zone,omitempty" jsonschema:"optional: one zone only"`
	Value  string `json:"value,omitempty" jsonschema:"optional glob on the values, as for search_records"`
	Host   string `json:"host,omitempty" jsonschema:"optional glob on the host"`
	Type   string `json:"type,omitempty" jsonschema:"optional glob on the record type"`
}

// scanScope resolves the zones a search or an export covers.
func (s *Server) scanScope(readable map[string]bool, zone, folder string) ([]string, error) {
	if folder != "" {
		if err := glob.ValidFolderPattern(folder); err != nil {
			return nil, fmt.Errorf("folder: %w", err)
		}
	}
	if zone == "" {
		return s.scanZones(readable, folder), nil
	}
	zone = normZoneArg(zone)
	if !config.ValidFQDN(zone) {
		return nil, errors.New("invalid zone")
	}
	if !readable[zone] {
		return nil, fmt.Errorf("read access to %q not granted", zone)
	}
	return s.scanZones(map[string]bool{zone: true}, folder), nil
}

func exportFormat(f string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "", exportTSV:
		return exportTSV, nil
	case exportZone:
		return exportZone, nil
	}
	return "", errors.New("format must be tsv or zone")
}

func (m *mcpServer) addSearchTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "search_records",
		Description: "Search RRsets across every zone you can read (managed and unmanaged), or one folder or zone, by globs on the value, host and type; " +
			"e.g. value \"*nbs-aws.com*\" finds every record pointing there. Returns compact records (zone, host, type, ttl, values, status, owner). " +
			"Zones are read with bounded concurrency and a deadline: zones not read in time, or that cannot be read, are listed in zones_skipped with their reason; " +
			"ask again later for them, the zones already read come from the cache. truncated is set when more records matched than limit.",
		Annotations: readOnly("Search records"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in searchRecordsIn) (*mcp.CallToolResult, searchResult, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, searchResult{}, err
		}
		limit, err := searchLimit(in.Limit)
		if err != nil {
			return nil, searchResult{}, err
		}
		zones, err := m.s.scanScope(m.readable(subj), in.Zone, in.Folder)
		if err != nil {
			return nil, searchResult{}, err
		}
		out := searchRecords(m.s.scan(ctx, subj, zones), recordFilter{Value: in.Value, Host: in.Host, Type: in.Type}, limit)
		m.audit(ctx, req, subj, "search_records", normZoneArg(in.Zone), "allow", "", scanAuditExtra(in.Value, in.Host, in.Type, in.Folder, out.ZonesScanned, len(out.ZonesSkipped), len(out.Records)))
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "export_records",
		Description: "Export the RRsets of every zone you can read, or of one folder or zone, as TSV (default; one line per value: zone, host, type, ttl, value, status, owner; tabs and newlines escaped) " +
			"or as zone files (one $ORIGIN block per zone; URL forwards and aliases as comments). Optional globs on value, host and type as for search_records. " +
			"The export is the text content; the structured result counts the records and lists the zones skipped (timeout or unreadable).",
		Annotations: readOnly("Export records"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in exportRecordsIn) (*mcp.CallToolResult, exportResult, error) {
		subj, err := m.subject(ctx, req)
		if err != nil {
			return nil, exportResult{}, err
		}
		format, err := exportFormat(in.Format)
		if err != nil {
			return nil, exportResult{}, err
		}
		zones, err := m.s.scanScope(m.readable(subj), in.Zone, in.Folder)
		if err != nil {
			return nil, exportResult{}, err
		}
		text, sum := exportRecords(m.s.scan(ctx, subj, zones), recordFilter{Value: in.Value, Host: in.Host, Type: in.Type}, format)
		extra := scanAuditExtra(in.Value, in.Host, in.Type, in.Folder, sum.ZonesScanned, len(sum.ZonesSkipped), sum.Records)
		extra["format"] = format
		m.audit(ctx, req, subj, "export_records", normZoneArg(in.Zone), "allow", "", extra)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, sum, nil
	})
}

// scanAuditExtra describes a search or an export in the audit.
func scanAuditExtra(value, host, typ, folder string, scanned, skipped, records int) map[string]any {
	extra := map[string]any{"zones_scanned": scanned, "zones_skipped": skipped, "records": records}
	for k, v := range map[string]string{"value": value, "host": host, "type": typ, "folder": folder} {
		if v != "" {
			extra[k] = v
		}
	}
	return extra
}
