// Package restapi is the small JSON over HTTP client of the record-based
// provider adapters: a request pace, bounded retries of the requests that
// are safe to send again, bounded bodies and a cached bearer token.
package restapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	maxBody       = 32 << 20
	maxErrorBody  = 2048
	maxRetryDelay = 30 * time.Second
	baseDelay     = 500 * time.Millisecond
	// DefaultTimeout bounds one request.
	DefaultTimeout = 30 * time.Second
)

// Client sends the requests of one provider account.
type Client struct {
	// HTTP is the client used, http.DefaultClient with DefaultTimeout when
	// nil.
	HTTP      *http.Client
	UserAgent string
	// MaxRetries is the number of retries of a request that failed with 429
	// (any method), or with a network error or 5xx (GET only).
	MaxRetries int
	// Every, when positive, is the minimum time between two requests.
	Every time.Duration
	// Auth signs a request before it is sent (each attempt).
	Auth func(ctx context.Context, req *http.Request, body []byte) error

	mu   sync.Mutex
	next time.Time
}

// Error is a response with a status outside 2xx.
type Error struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.URL, e.Status, e.Body)
}

// Status returns the HTTP status of err when it is an *Error, 0 otherwise.
func Status(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

var defaultHTTP = &http.Client{Timeout: DefaultTimeout}

func (c *Client) wait(ctx context.Context) error {
	if c.Every <= 0 {
		return nil
	}
	c.mu.Lock()
	now := time.Now()
	at := c.next
	if at.Before(now) {
		at = now
	}
	c.next = at.Add(c.Every)
	c.mu.Unlock()
	return sleep(ctx, at.Sub(now))
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func retryDelay(attempt int, h http.Header) time.Duration {
	if h != nil {
		if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s >= 0 {
			return min(time.Duration(s)*time.Second, maxRetryDelay)
		}
	}
	return min(baseDelay<<attempt, maxRetryDelay)
}

// Do sends body (nil for none) and returns the response body and headers.
// A status outside 2xx is an *Error.
func (c *Client) Do(ctx context.Context, method, url string, hdr http.Header, body []byte) ([]byte, http.Header, error) {
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	for attempt := 0; ; attempt++ {
		if err := c.wait(ctx); err != nil {
			return nil, nil, err
		}
		out, rh, status, err := c.once(ctx, hc, method, url, hdr, body)
		if err == nil && status >= 200 && status < 300 {
			return out, rh, nil
		}
		if err == nil {
			err = &Error{Method: method, URL: url, Status: status, Body: string(out[:min(len(out), maxErrorBody)])}
		}
		retry := status == http.StatusTooManyRequests ||
			(method == http.MethodGet && (status == 0 || status >= 500))
		if !retry || attempt >= c.MaxRetries || ctx.Err() != nil {
			return nil, rh, err
		}
		if serr := sleep(ctx, retryDelay(attempt, rh)); serr != nil {
			return nil, rh, err
		}
	}
}

func (c *Client) once(ctx context.Context, hc *http.Client, method, url string, hdr http.Header, body []byte) ([]byte, http.Header, int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, nil, 0, err
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Auth != nil {
		if err := c.Auth(ctx, req, body); err != nil {
			return nil, nil, 0, err
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, resp.Header, 0, err
	}
	if len(out) > maxBody {
		return nil, resp.Header, 0, fmt.Errorf("%s %s: response over %d bytes", method, url, maxBody)
	}
	return out, resp.Header, resp.StatusCode, nil
}

// JSON sends in as JSON (nil for no body) and decodes the response in out
// (nil to ignore it).
func (c *Client) JSON(ctx context.Context, method, url string, hdr http.Header, in, out any) (http.Header, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	raw, rh, err := c.Do(ctx, method, url, hdr, body)
	if err != nil {
		return rh, err
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return rh, fmt.Errorf("%s %s: decode response: %w", method, url, err)
		}
	}
	return rh, nil
}

// Token caches a bearer token and renews it shortly before it expires.
type Token struct {
	// Fetch returns a new token and its expiry.
	Fetch func(ctx context.Context) (string, time.Time, error)

	mu    sync.Mutex
	value string
	until time.Time
}

// Get returns a valid token.
func (t *Token) Get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value != "" && time.Until(t.until) > time.Minute {
		return t.value, nil
	}
	v, until, err := t.Fetch(ctx)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("empty access token")
	}
	t.value, t.until = v, until
	return v, nil
}

// Forget drops the cached token (after a 401).
func (t *Token) Forget() {
	t.mu.Lock()
	t.value = ""
	t.mu.Unlock()
}
