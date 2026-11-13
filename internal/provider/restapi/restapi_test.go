package restapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetries(t *testing.T) {
	var gets, posts, throttled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/throttled":
			if throttled.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		case r.Method == http.MethodGet:
			if gets.Add(1) < 3 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
		default:
			posts.Add(1)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := &Client{MaxRetries: 2}
	ctx := context.Background()
	var out struct{ OK bool }
	if _, err := c.JSON(ctx, http.MethodGet, srv.URL+"/x", nil, nil, &out); err != nil || !out.OK || gets.Load() != 3 {
		t.Errorf("GET: %v, %d attempts", err, gets.Load())
	}
	// A write that failed with 5xx may have been applied: it is not sent again.
	if _, err := c.JSON(ctx, http.MethodPost, srv.URL+"/x", nil, map[string]int{"a": 1}, nil); Status(err) != http.StatusBadGateway || posts.Load() != 1 {
		t.Errorf("POST: %v, %d attempts", err, posts.Load())
	}
	// A throttled write was not processed: it is.
	if _, err := c.JSON(ctx, http.MethodPost, srv.URL+"/throttled", nil, nil, nil); err != nil || throttled.Load() != 2 {
		t.Errorf("throttled POST: %v, %d attempts", err, throttled.Load())
	}
}

func TestPaceAndToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := &Client{Every: 40 * time.Millisecond}
	start := time.Now()
	for range 3 {
		if _, _, err := c.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 80*time.Millisecond {
		t.Errorf("3 requests in %s", d)
	}

	n := 0
	tok := &Token{Fetch: func(context.Context) (string, time.Time, error) {
		n++
		return "t", time.Now().Add(time.Hour), nil
	}}
	for range 3 {
		if v, err := tok.Get(context.Background()); err != nil || v != "t" {
			t.Fatal(v, err)
		}
	}
	tok.Forget()
	_, _ = tok.Get(context.Background())
	if n != 2 {
		t.Errorf("%d fetches", n)
	}
}
