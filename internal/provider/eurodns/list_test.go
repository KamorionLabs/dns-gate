package eurodns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// searchServer fakes POST /domains/search with pagination headers.
func searchServer(t *testing.T, domains []string, ignorePages bool, requests *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		if r.Method != http.MethodPost || r.URL.Path != "/domains/search" || r.Header.Get("X-API-KEY") != "k" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		page, _ := strconv.Atoi(r.Header.Get("pagination-page"))
		size, _ := strconv.Atoi(r.Header.Get("pagination-size"))
		if page < 1 || size < 1 {
			http.Error(w, "pagination", http.StatusBadRequest)
			return
		}
		if ignorePages {
			page = 1
		}
		start := min((page-1)*size, len(domains))
		end := min(start+size, len(domains))
		var out []map[string]any
		for _, d := range domains[start:end] {
			out = append(out, map[string]any{"domainName": d, "tldName": d[strings.LastIndex(d, ".")+1:]})
		}
		w.Header().Set("pagination-count", strconv.Itoa(len(domains)))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
}

type keyRT struct{}

func (keyRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-API-KEY", "k")
	return http.DefaultTransport.RoundTrip(r)
}

func TestListerPagination(t *testing.T) {
	var domains []string
	for i := range 7 {
		domains = append(domains, "d"+strconv.Itoa(i)+".example")
	}
	n := 0
	srv := searchServer(t, domains, false, &n)
	defer srv.Close()
	l := &lister{BaseURL: srv.URL + "/", Transport: keyRT{}, PageSize: 3}
	got, err := l.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(domains, ",") || n != 3 {
		t.Fatalf("got %v in %d requests", got, n)
	}
	// Exactly a multiple of the page size: pagination-count stops the loop.
	n = 0
	srv2 := searchServer(t, domains[:6], false, &n)
	defer srv2.Close()
	l.BaseURL = srv2.URL
	if got, err := l.ListDomains(context.Background()); err != nil || len(got) != 6 || n != 2 {
		t.Fatalf("got %v, %v in %d requests", got, err, n)
	}
}

func TestListerStopsWhenPaginationIgnored(t *testing.T) {
	n := 0
	srv := searchServer(t, []string{"a.example", "b.example", "c.example", "d.example"}, true, &n)
	defer srv.Close()
	l := &lister{BaseURL: srv.URL, Transport: keyRT{}, PageSize: 2}
	if _, err := l.ListDomains(context.Background()); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatalf("err = %v", err)
	}
	if n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
}

func TestListerHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	l := &lister{BaseURL: srv.URL, Transport: http.DefaultTransport}
	if _, err := l.ListDomains(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestListZoneFolders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "k" {
			http.Error(w, "no key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("pagination-count", "6")
		_, _ = w.Write([]byte(`[{"domainName":"Example.ES","folderFullPath":"/ES"},{"domainName":"madrid.example.es","folderFullPath":"/ES/Madrid/"},` +
			`{"domainName":"example.com","folderFullPath":"/"},{"domainName":"example.net","folderFullPath":null},` +
			`{"domainName":"example.org"},{"domainName":"space.example.es","folderFullPath":"ES "}]`))
	}))
	defer srv.Close()
	p, err := New("eu", Config{BaseURL: srv.URL, AppID: "app", APIKey: "k", RateEvery: time.Millisecond, RateBurst: 10})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.ListZoneFolders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"example.es": "/ES", "madrid.example.es": "/ES/Madrid", "example.com": "/", "example.net": "/", "example.org": "", "space.example.es": "/ES "}
	if len(got) != len(want) {
		t.Fatalf("folders = %v", got)
	}
	for z, f := range want {
		if got[z] != f {
			t.Errorf("%s: %q, want %q", z, got[z], f)
		}
	}
	names, err := p.ListZones(context.Background())
	if err != nil || strings.Join(names, ",") != "example.es,madrid.example.es,example.com,example.net,example.org,space.example.es" {
		t.Fatalf("zones = %v, %v", names, err)
	}
}
