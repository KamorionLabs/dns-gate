package discovery

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
)

const (
	// PageSize is the number of domains requested per page.
	PageSize = 100
	// maxPages bounds a listing (PageSize * maxPages domains).
	maxPages = 500
	// firstPage is the number of the first page of POST /domains/search.
	firstPage    = 1
	maxPageBytes = 8 << 20
)

// EuroDNSLister lists the account domains with POST /domains/search
// (searchDomains), paginated through the pagination-* headers. It is meant
// to run on the gate's shared upstream transport, which injects the API key
// and applies the rate limit: a listing costs one request per PageSize
// domains.
//
// eurodns-go v0.1.0 has no call for this operation; it is implemented here
// on the same transport.
type EuroDNSLister struct {
	BaseURL   string
	Transport http.RoundTripper
	PageSize  int
}

type domainResult struct {
	DomainName string `json:"domainName"`
}

// ListDomains returns every domain name of the account.
func (l *EuroDNSLister) ListDomains(ctx context.Context) ([]string, error) {
	size := l.PageSize
	if size <= 0 {
		size = PageSize
	}
	base, err := url.Parse(strings.TrimRight(l.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("discovery: base URL: %w", err)
	}
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + "/domains/search"
	hc := &http.Client{Transport: l.Transport, Timeout: 60 * time.Second}
	var out []string
	seen := map[string]bool{}
	for page := firstPage; page < firstPage+maxPages; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader([]byte(`{}`)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("pagination-page", strconv.Itoa(page))
		req.Header.Set("pagination-size", strconv.Itoa(size))
		req.Header.Set("pagination-sortfield", "DOMAIN_NAME")
		req.Header.Set("pagination-sortorder", "asc")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("discovery: search domains: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("discovery: search domains: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("discovery: search domains: HTTP %d", resp.StatusCode)
		}
		var items []domainResult
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("discovery: search domains: decode page %d: %w", page, err)
		}
		added := 0
		for _, it := range items {
			if it.DomainName != "" && !seen[it.DomainName] {
				seen[it.DomainName] = true
				out = append(out, it.DomainName)
				added++
			}
		}
		if len(items) > 0 && added == 0 {
			// A page with nothing new means pagination is not applied:
			// stop instead of spending the upstream budget.
			return nil, fmt.Errorf("discovery: search domains: page %d repeats earlier results", page)
		}
		total, terr := strconv.Atoi(resp.Header.Get("pagination-count"))
		if len(items) < size || (terr == nil && len(out) >= total) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("discovery: more than %d domains, listing truncated", size*maxPages)
}
