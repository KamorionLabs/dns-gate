package server

import (
	"net/http"
	"strconv"

	"github.com/KamorionLabs/dns-gate/internal/identity"
)

const (
	routeRecords       = "/api/v1/records"
	routeRecordsExport = "/api/v1/records/export"
)

// handleRecords serves GET /api/v1/records (search across the readable
// zones) and GET /api/v1/records/export (TSV or zone files).
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request, subj *identity.Subject, readable map[string]bool, export bool) {
	q := r.URL.Query()
	f := recordFilter{Value: q.Get("value"), Host: q.Get("host"), Type: q.Get("type")}
	zones, err := s.scanScope(readable, q.Get("zone"), q.Get("folder"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !export {
		limit := 0
		if v := q.Get("limit"); v != "" {
			if limit, err = strconv.Atoi(v); err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "limit must be an integer")
				return
			}
		}
		if limit, err = searchLimit(limit); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		out := searchRecords(s.scan(r.Context(), subj, zones), f, limit)
		s.apiAudit(r, subj, "api.search_records", normZoneArg(q.Get("zone")), "allow", "",
			scanAuditExtra(f.Value, f.Host, f.Type, q.Get("folder"), out.ZonesScanned, len(out.ZonesSkipped), len(out.Records)))
		writeJSON(w, http.StatusOK, out)
		return
	}
	format, err := exportFormat(q.Get("format"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	text, sum := exportRecords(s.scan(r.Context(), subj, zones), f, format)
	extra := scanAuditExtra(f.Value, f.Host, f.Type, q.Get("folder"), sum.ZonesScanned, len(sum.ZonesSkipped), sum.Records)
	extra["format"] = format
	s.apiAudit(r, subj, "api.export_records", normZoneArg(q.Get("zone")), "allow", "", extra)
	ct, name := "text/tab-separated-values; charset=utf-8", "records.tsv"
	if format == exportZone {
		ct, name = "text/plain; charset=utf-8", "records.zone"
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("X-Records", strconv.Itoa(sum.Records))
	h.Set("X-Zones-Scanned", strconv.Itoa(sum.ZonesScanned))
	h.Set("X-Zones-Skipped", strconv.Itoa(len(sum.ZonesSkipped)))
	if sum.Truncated {
		h.Set("X-Truncated", "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(text))
}
