// Package profiletest is an in-memory fake of the EuroDNS zone profile API
// (/zone-profiles), meant to wrap the zone fake of eurodns-go
// (eurodnstest), which does not serve it.
package profiletest

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	api "github.com/KamorionLabs/eurodns-go"
)

var validTypes = map[string]bool{"A": true, "AAAA": true, "APEX": true, "CAA": true, "CNAME": true, "DS": true, "HTTPS": true,
	"MX": true, "NAPTR": true, "NS": true, "PTR": true, "SPF": true, "SRV": true, "SVCB": true, "TLSA": true, "TXT": true}

// Fake stores zone profiles. Safe for concurrent use.
type Fake struct {
	// APIKey, when set, is the X-API-KEY every request must carry.
	APIKey string
	// MaxPageSize, when set, caps the page size of the listing.
	MaxPageSize int
	// HideCount omits the pagination-count header of the listing.
	HideCount bool

	mu       sync.Mutex
	profiles map[int64]*eurodnsprov.ZoneProfile
	nextID   int64
	nextRec  int64
	requests int
	bodies   []string
}

// New returns an empty fake.
func New() *Fake {
	return &Fake{profiles: map[int64]*eurodnsprov.ZoneProfile{}, nextID: 1, nextRec: 5000}
}

// Wrap serves the zone profile routes and hands every other request to
// next (404 when next is nil).
func (f *Fake) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zone-profiles" && !strings.HasPrefix(r.URL.Path, "/zone-profiles/") {
			if next == nil {
				writeErr(w, http.StatusNotFound, "NOT_FOUND", "Not found")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		f.serve(w, r)
	})
}

// Profile returns a copy of a stored profile, nil if absent.
func (f *Fake) Profile(id int64) *eurodnsprov.ZoneProfile {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p := f.profiles[id]; p != nil {
		return clone(p)
	}
	return nil
}

// Len returns the number of stored profiles.
func (f *Fake) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.profiles)
}

// Requests returns the number of zone profile requests served.
func (f *Fake) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// Bodies returns the request bodies received, in order.
func (f *Fake) Bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.bodies)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()
	if f.APIKey != "" && r.Header.Get("X-API-KEY") != f.APIKey {
		writeErr(w, http.StatusUnauthorized, "INVALID_API_KEY", "Invalid API key")
		return
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/zone-profiles"), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		f.list(w, r)
	case rest == "" && r.Method == http.MethodPost:
		f.write(w, r, 0, false)
	case rest == "check" && r.Method == http.MethodPost:
		f.write(w, r, 0, true)
	case rest != "" && !strings.Contains(rest, "/"):
		id, err := strconv.ParseInt(rest, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "INVALID_ID", "Invalid id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			f.get(w, id)
		case http.MethodPut:
			f.write(w, r, id, false)
		case http.MethodDelete:
			f.delete(w, id)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
	default:
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Not found")
	}
}

func (f *Fake) list(w http.ResponseWriter, r *http.Request) {
	page, perr := strconv.Atoi(r.Header.Get("pagination-page"))
	size, serr := strconv.Atoi(r.Header.Get("pagination-size"))
	if perr != nil || serr != nil || page < 1 || size < 1 {
		writeErr(w, http.StatusBadRequest, "INVALID_PAGINATION", "pagination-page and pagination-size are required")
		return
	}
	f.mu.Lock()
	if f.MaxPageSize > 0 && size > f.MaxPageSize {
		size = f.MaxPageSize
	}
	hide := f.HideCount
	all := make([]eurodnsprov.ZoneProfileSummary, 0, len(f.profiles))
	for id, p := range f.profiles {
		all = append(all, eurodnsprov.ZoneProfileSummary{ID: id, Name: p.Name})
	}
	f.mu.Unlock()
	field, order := r.Header.Get("pagination-sortfield"), r.Header.Get("pagination-sortorder")
	sort.Slice(all, func(i, j int) bool {
		less := all[i].ID < all[j].ID
		if field == "name" && all[i].Name != all[j].Name {
			less = all[i].Name < all[j].Name
		}
		if order == "desc" {
			return !less
		}
		return less
	})
	start := min((page-1)*size, len(all))
	end := min(start+size, len(all))
	w.Header().Set("pagination-page", strconv.Itoa(page))
	w.Header().Set("pagination-size", strconv.Itoa(size))
	if !hide {
		w.Header().Set("pagination-count", strconv.Itoa(len(all)))
	}
	if field != "" {
		w.Header().Set("pagination-sortfield", field)
	}
	if order != "" {
		w.Header().Set("pagination-sortorder", order)
	}
	writeJSON(w, http.StatusOK, all[start:end])
}

func (f *Fake) get(w http.ResponseWriter, id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.profiles[id]
	if p == nil {
		writeErr(w, http.StatusNotFound, "ZONE_PROFILE_NOT_FOUND", "Zone profile not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (f *Fake) delete(w http.ResponseWriter, id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.profiles[id] == nil {
		writeErr(w, http.StatusNotFound, "ZONE_PROFILE_NOT_FOUND", "Zone profile not found")
		return
	}
	delete(f.profiles, id)
	w.WriteHeader(http.StatusNoContent)
}

// write creates (id 0), replaces (id > 0) or checks a profile.
func (f *Fake) write(w http.ResponseWriter, r *http.Request, id int64, check bool) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON: "+err.Error())
		return
	}
	var in eurodnsprov.ZoneProfile
	if err := json.Unmarshal(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON: "+err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies = append(f.bodies, string(raw))
	rep := validate(&in)
	if check {
		in.Report = rep
		writeJSON(w, http.StatusOK, in)
		return
	}
	if !rep.Valid() {
		writeErr(w, http.StatusBadRequest, "INVALID_ZONE_PROFILE", firstError(rep))
		return
	}
	if id > 0 && f.profiles[id] == nil {
		writeErr(w, http.StatusNotFound, "ZONE_PROFILE_NOT_FOUND", "Zone profile not found")
		return
	}
	status := http.StatusOK
	if id == 0 {
		id = f.nextID
		f.nextID++
		status = http.StatusCreated
	}
	out := clone(&in)
	out.ID = &id
	out.Report = nil
	off := false
	out.DomainConnect = &off
	for i := range out.Records {
		n := f.nextRec
		f.nextRec++
		out.Records[i].ID = &n
		out.Records[i].Updated = nil
	}
	f.profiles[id] = out
	writeJSON(w, status, out)
}

func validate(p *eurodnsprov.ZoneProfile) *api.ValidationReport {
	var errs []json.RawMessage
	add := func(r api.Record, msg string) {
		b, _ := json.Marshal(api.RecordError{Messages: []string{msg}, Record: &r, Severity: api.SeverityError})
		errs = append(errs, b)
	}
	if strings.TrimSpace(p.Name) == "" {
		b, _ := json.Marshal(api.ZoneError{Message: "The profile name is required", Severity: api.SeverityError})
		valid := false
		return &api.ValidationReport{IsValid: &valid, ZoneErrors: []json.RawMessage{b}}
	}
	for _, r := range p.Records {
		if !validTypes[strings.ToUpper(r.Type)] {
			add(r, strconv.Quote(r.Type)+" is not a valid record type")
		}
		if !slices.Contains(api.AllowedTTLs, r.TTL) {
			add(r, strconv.Quote(strconv.Itoa(r.TTL))+" is not a valid TTL")
		}
		if strings.TrimSpace(r.RData) == "" {
			add(r, "rdata is required")
		}
	}
	valid := len(errs) == 0
	if errs == nil {
		errs = []json.RawMessage{}
	}
	empty := []json.RawMessage{}
	return &api.ValidationReport{IsValid: &valid, RecordErrors: errs, URLForwardErrors: empty, MailForwardErrors: empty, ZoneErrors: empty}
}

func firstError(rep *api.ValidationReport) string {
	if errs := rep.Errors(); len(errs) > 0 {
		return errs[0].Message
	}
	return "Invalid zone profile"
}

func writeErr(w http.ResponseWriter, code int, errCode, title string) {
	writeJSON(w, code, map[string]any{"errors": []map[string]any{{
		"status": strconv.Itoa(code), "code": errCode, "title": title, "meta": nil,
	}}})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clone(p *eurodnsprov.ZoneProfile) *eurodnsprov.ZoneProfile {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	var c eurodnsprov.ZoneProfile
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return &c
}
