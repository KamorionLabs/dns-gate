package eurodns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	api "github.com/KamorionLabs/eurodns-go"
)

// ZoneProfile mirrors the ZoneProfilePage schema: an account-wide template
// of a EuroDNS account (records, URL and mail forwards) that EuroDNS
// applies to a domain when it arrives on its nameservers, for example when
// a Premium DNS subscription is ordered with its zoneProfileId or a domain
// is transferred. A profile names no domain: hosts are relative to the
// domain it is applied to. URL and mail forwards are kept as raw JSON.
//
// eurodns-go v0.1.0 has no call for zone profiles; they are implemented
// here on the shared transport (API key, rate limit, retries).
type ZoneProfile struct {
	ID            *int64                `json:"id,omitempty"`
	Name          string                `json:"name"`
	DomainConnect *bool                 `json:"domainConnect,omitempty"`
	Records       []api.Record          `json:"records"`
	URLForwards   []json.RawMessage     `json:"urlForwards"`
	MailForwards  []json.RawMessage     `json:"mailForwards"`
	Report        *api.ValidationReport `json:"report,omitempty"`
}

// ZoneProfileSummary mirrors the ZoneProfile schema of the listing.
type ZoneProfileSummary struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ProfilePage selects a page of the zone profile listing (pagination-*
// request headers). Zero values take the defaults.
type ProfilePage struct {
	Page      int
	Size      int
	SortField string // id or name
	SortOrder string // asc or desc
}

// PaginationHeaders are the pagination headers of the EuroDNS listings.
var PaginationHeaders = []string{"pagination-page", "pagination-size", "pagination-count", "pagination-sortfield", "pagination-sortorder"}

const (
	profilePageSize = 100
	profileMaxPages = 20
	maxProfileBytes = 8 << 20
)

// Clean returns a copy of the profile without the fields EuroDNS computes
// (report, domainConnect), with empty lists instead of null.
func (z *ZoneProfile) Clean() *ZoneProfile {
	out := *z
	out.Report = nil
	out.DomainConnect = nil
	if out.Records == nil {
		out.Records = []api.Record{}
	}
	if out.URLForwards == nil {
		out.URLForwards = []json.RawMessage{}
	}
	if out.MailForwards == nil {
		out.MailForwards = []json.RawMessage{}
	}
	return &out
}

func profilePath(id int64) string { return "/zone-profiles/" + strconv.FormatInt(id, 10) }

// ListZoneProfilesPage returns one page of the zone profiles and the
// pagination headers of the response.
func (p *Provider) ListZoneProfilesPage(ctx context.Context, pg ProfilePage) ([]ZoneProfileSummary, http.Header, error) {
	if pg.Page <= 0 {
		pg.Page = 1
	}
	if pg.Size <= 0 {
		pg.Size = profilePageSize
	}
	h := http.Header{}
	h.Set("pagination-page", strconv.Itoa(pg.Page))
	h.Set("pagination-size", strconv.Itoa(pg.Size))
	if pg.SortField != "" {
		h.Set("pagination-sortfield", pg.SortField)
	}
	if pg.SortOrder != "" {
		h.Set("pagination-sortorder", pg.SortOrder)
	}
	var out []ZoneProfileSummary
	rh, err := p.profileDo(ctx, http.MethodGet, "/zone-profiles", h, nil, &out)
	if err != nil {
		return nil, nil, err
	}
	ph := http.Header{}
	for _, k := range PaginationHeaders {
		if v := rh.Get(k); v != "" {
			ph.Set(k, v)
		}
	}
	if out == nil {
		out = []ZoneProfileSummary{}
	}
	return out, ph, nil
}

// ListZoneProfiles returns every zone profile of the account, sorted by id,
// in at most profileMaxPages requests. EuroDNS may serve smaller pages than
// asked: the listing ends when pagination-count profiles are read or, when
// the header is absent, on an empty page.
func (p *Provider) ListZoneProfiles(ctx context.Context) ([]ZoneProfileSummary, error) {
	out := []ZoneProfileSummary{}
	seen := map[int64]bool{}
	for page := 1; page <= profileMaxPages; page++ {
		items, h, err := p.ListZoneProfilesPage(ctx, ProfilePage{Page: page, Size: profilePageSize, SortField: "id", SortOrder: "asc"})
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return out, nil
		}
		added := 0
		for _, it := range items {
			if !seen[it.ID] {
				seen[it.ID] = true
				out = append(out, it)
				added++
			}
		}
		if added == 0 {
			return nil, fmt.Errorf("eurodns: list zone profiles: page %d repeats earlier results", page)
		}
		if total, err := strconv.Atoi(h.Get("pagination-count")); err == nil && len(out) >= total {
			return out, nil
		}
	}
	return nil, fmt.Errorf("eurodns: more than %d pages of zone profiles, listing truncated", profileMaxPages)
}

// GetZoneProfile returns a zone profile.
func (p *Provider) GetZoneProfile(ctx context.Context, id int64) (*ZoneProfile, error) {
	var out ZoneProfile
	if _, err := p.profileDo(ctx, http.MethodGet, profilePath(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckZoneProfile validates a zone profile without saving it; the result
// carries the validation report.
func (p *Provider) CheckZoneProfile(ctx context.Context, z *ZoneProfile) (*ZoneProfile, error) {
	var out ZoneProfile
	if _, err := p.profileDo(ctx, http.MethodPost, "/zone-profiles/check", nil, z.Clean(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateZoneProfile creates a zone profile and returns it with its id.
func (p *Provider) CreateZoneProfile(ctx context.Context, z *ZoneProfile) (*ZoneProfile, error) {
	in := z.Clean()
	in.ID = nil
	var out ZoneProfile
	if _, err := p.profileDo(ctx, http.MethodPost, "/zone-profiles", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateZoneProfile replaces a zone profile.
func (p *Provider) UpdateZoneProfile(ctx context.Context, id int64, z *ZoneProfile) (*ZoneProfile, error) {
	in := z.Clean()
	in.ID = &id
	var out ZoneProfile
	if _, err := p.profileDo(ctx, http.MethodPut, profilePath(id), nil, in, &out); err != nil {
		return nil, err
	}
	if out.ID == nil {
		out.ID = &id
	}
	return &out, nil
}

// DeleteZoneProfile deletes a zone profile.
func (p *Provider) DeleteZoneProfile(ctx context.Context, id int64) error {
	_, err := p.profileDo(ctx, http.MethodDelete, profilePath(id), nil, nil, nil)
	return err
}

// profileDo sends one request on the shared transport. Non-2xx answers
// are returned as *api.APIError, with the body and the parsed report.
func (p *Provider) profileDo(ctx context.Context, method, path string, headers http.Header, in, out any) (http.Header, error) {
	base, err := url.Parse(strings.TrimRight(p.baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("eurodns: base URL: %w", err)
	}
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + path
	u.RawPath = ""
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := &http.Client{Transport: p.transport, Timeout: 60 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("eurodns: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileBytes))
	if err != nil {
		return nil, fmt.Errorf("eurodns: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, profileAPIError(method, path, resp.StatusCode, b)
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.Header, fmt.Errorf("eurodns: decode %s %s: %w", method, path, err)
		}
	}
	return resp.Header, nil
}

func profileAPIError(method, path string, status int, body []byte) *api.APIError {
	e := &api.APIError{StatusCode: status, Method: method, Path: path, Body: body}
	var parsed struct {
		Message string                `json:"message"`
		Report  *api.ValidationReport `json:"report"`
		Errors  []api.ErrorItem       `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		e.Message, e.Report, e.Errors = parsed.Message, parsed.Report, parsed.Errors
		if len(parsed.Errors) > 0 {
			e.Code = parsed.Errors[0].Code
			if e.Message == "" {
				e.Message = parsed.Errors[0].Title
			}
		}
	}
	return e
}
