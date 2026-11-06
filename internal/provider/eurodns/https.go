package eurodns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

// httpsCacheTTL is how long the HTTPS redirect status of a zone is reused:
// it costs up to two upstream requests and changes only with an order.
const httpsCacheTTL = 10 * time.Minute

type httpsEntry struct {
	at     time.Time
	status provider.HTTPSRedirect
}

type httpsCache struct {
	mu    sync.Mutex
	zones map[string]httpsEntry
}

var _ provider.HTTPSRedirecter = (*Provider)(nil)

type subscription struct {
	ID                 int64  `json:"id"`
	SubscriptionType   string `json:"subscriptionType"`
	SubscriptionStatus string `json:"subscriptionStatus"`
	Active             bool   `json:"active"`
	DomainName         string `json:"domainName"`
	ExpirationDate     string `json:"expirationDate"`
	SSLStatus          string `json:"sslStatus"`
}

// HTTPSRedirect reads the HTTPS redirect subscription of a zone
// (GET /subscriptions filtered on HTTPS_REDIRECT and the domain, then
// GET /https-redirect-subscriptions/{id} for its certificate status). The
// gate never orders, renews nor deletes such subscriptions: they are paid
// products. A read failure (an API key without access to subscriptions)
// is the status "unknown", with the error as message; the result is cached
// for 10 minutes per zone.
func (p *Provider) HTTPSRedirect(ctx context.Context, zone string) (provider.HTTPSRedirect, error) {
	zone = dns.NormalizeZone(zone)
	now := time.Now()
	p.https.mu.Lock()
	if e, ok := p.https.zones[zone]; ok && now.Sub(e.at) < httpsCacheTTL {
		p.https.mu.Unlock()
		return e.status, nil
	}
	p.https.mu.Unlock()
	st, err := p.readHTTPSRedirect(ctx, zone)
	if err != nil {
		st = provider.HTTPSRedirect{Status: provider.HTTPSUnknown, Message: err.Error()}
	}
	p.https.mu.Lock()
	if p.https.zones == nil {
		p.https.zones = map[string]httpsEntry{}
	}
	p.https.zones[zone] = httpsEntry{at: now, status: st}
	p.https.mu.Unlock()
	return st, nil
}

func (p *Provider) readHTTPSRedirect(ctx context.Context, zone string) (provider.HTTPSRedirect, error) {
	q := url.Values{"subscription-types": {"HTTPS_REDIRECT"}, "domain-name": {zone}}
	var subs []subscription
	if err := p.getJSON(ctx, "/subscriptions", q, &subs); err != nil {
		return provider.HTTPSRedirect{}, err
	}
	var best *subscription
	for i := range subs {
		s := &subs[i]
		if !strings.EqualFold(s.SubscriptionType, "HTTPS_REDIRECT") || dns.NormalizeZone(s.DomainName) != zone {
			continue
		}
		if best == nil || (s.Active && !best.Active) {
			best = s
		}
	}
	if best == nil {
		return provider.HTTPSRedirect{Status: provider.HTTPSInactive, Message: "no HTTPS redirect subscription on " + zone + ": forwards answer plain HTTP only"}, nil
	}
	out := provider.HTTPSRedirect{Subscription: strconv.FormatInt(best.ID, 10), ExpiresAt: best.ExpirationDate}
	if !best.Active {
		out.Status, out.Message = provider.HTTPSInactive, "HTTPS redirect subscription "+out.Subscription+" is "+strings.ToLower(best.SubscriptionStatus)
		return out, nil
	}
	var detail subscription
	if err := p.getJSON(ctx, "/https-redirect-subscriptions/"+out.Subscription, nil, &detail); err != nil {
		return provider.HTTPSRedirect{}, err
	}
	switch strings.ToUpper(detail.SSLStatus) {
	case "ACTIVE":
		out.Status = provider.HTTPSActive
	case "PENDING":
		out.Status, out.Message = provider.HTTPSPending, "the HTTPS redirect certificate is being issued"
	case "NO_FORWARD":
		out.Status, out.Message = provider.HTTPSNoForward, "the HTTPS redirect subscription is active; its certificate is issued once the zone has a forward"
	default:
		out.Status, out.Message = provider.HTTPSUnknown, "unexpected HTTPS redirect status "+detail.SSLStatus
	}
	return out, nil
}

// getJSON calls a EuroDNS GET operation on the shared transport.
func (p *Provider) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	u, err := url.Parse(strings.TrimRight(p.baseURL, "/") + path)
	if err != nil {
		return fmt.Errorf("eurodns: base URL: %w", err)
	}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Transport: p.transport, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("eurodns: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("eurodns: GET %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("eurodns: GET %s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("eurodns: GET %s: %w", path, err)
	}
	return nil
}
