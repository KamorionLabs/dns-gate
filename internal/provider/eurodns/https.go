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
	"golang.org/x/sync/singleflight"
)

// httpsCacheTTL is how long the HTTPS redirect status of a zone is reused:
// it costs up to two upstream requests and changes only with an order. A
// failed read is reused for httpsErrorTTL only.
const (
	httpsCacheTTL    = 10 * time.Minute
	httpsErrorTTL    = 30 * time.Second
	httpsReadTimeout = 15 * time.Second
)

type httpsEntry struct {
	at     time.Time
	status provider.HTTPSRedirect
}

type httpsCache struct {
	mu    sync.Mutex
	zones map[string]httpsEntry
	reads singleflight.Group
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
// products. A subscription past its expiration date is inactive. A read
// failure (an API key without access to subscriptions) is the status
// "unknown", with the error as message. Results are cached per zone, 10
// minutes, or 30 seconds for a failure; concurrent reads of a zone share
// one upstream lookup, bounded by its own timeout and not cancelled with
// the request that started it.
func (p *Provider) HTTPSRedirect(ctx context.Context, zone string) (provider.HTTPSRedirect, error) {
	zone = dns.NormalizeZone(zone)
	p.https.mu.Lock()
	if e, ok := p.https.zones[zone]; ok && time.Since(e.at) < e.ttl() {
		p.https.mu.Unlock()
		return e.status, nil
	}
	p.https.mu.Unlock()
	v, _, _ := p.https.reads.Do(zone, func() (any, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpsReadTimeout)
		defer cancel()
		st, err := p.readHTTPSRedirect(rctx, zone, time.Now())
		if err != nil {
			st = provider.HTTPSRedirect{Status: provider.HTTPSUnknown, Message: err.Error()}
		}
		p.https.mu.Lock()
		if p.https.zones == nil {
			p.https.zones = map[string]httpsEntry{}
		}
		p.https.zones[zone] = httpsEntry{at: time.Now(), status: st}
		p.https.mu.Unlock()
		return st, nil
	})
	return v.(provider.HTTPSRedirect), nil
}

func (e httpsEntry) ttl() time.Duration {
	if e.status.Status == provider.HTTPSUnknown {
		return httpsErrorTTL
	}
	return httpsCacheTTL
}

func (p *Provider) readHTTPSRedirect(ctx context.Context, zone string, now time.Time) (provider.HTTPSRedirect, error) {
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
	if exp, err := time.Parse(time.RFC3339, best.ExpirationDate); err == nil && !exp.After(now) {
		out.Status, out.Message = provider.HTTPSInactive, "HTTPS redirect subscription "+out.Subscription+" expired on "+best.ExpirationDate
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
