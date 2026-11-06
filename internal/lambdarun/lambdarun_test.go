package lambdarun

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

const httpEvent = `{
  "version": "2.0",
  "routeKey": "$default",
  "rawPath": "/api/v1/zones/example.com/rrsets",
  "rawQueryString": "type=A&host=www%20x",
  "cookies": ["dns_gate_session=abc", "dns_gate_state=xyz"],
  "headers": {
    "host": "dns-gate.example.com",
    "content-type": "application/octet-stream",
    "x-forwarded-for": "198.51.100.7",
    "accept": "application/json, text/plain"
  },
  "requestContext": {
    "domainName": "dns-gate.example.com",
    "requestId": "req-1",
    "http": {"method": "POST", "path": "/api/v1/zones/example.com/rrsets", "protocol": "HTTP/1.1", "sourceIp": "198.51.100.7"}
  },
  "body": "AAEC/w==",
  "isBase64Encoded": true
}`

type seen struct {
	method, path, query, host, remote, cookie, accept string
	host2                                             string
	body                                              []byte
	tls                                               bool
	cookies                                           []string
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func invoke(t *testing.T, h *Handler, payload string) events.APIGatewayV2HTTPResponse {
	t.Helper()
	out, err := h.Invoke(context.Background(), []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	var resp events.APIGatewayV2HTTPResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHTTPRoundTrip(t *testing.T) {
	var got seen
	h := &Handler{Log: quiet(), HTTP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.query, got.host = r.Method, r.URL.Path, r.URL.RawQuery, r.Host
		got.host2 = r.URL.Query().Get("host")
		got.remote, got.cookie, got.accept = r.RemoteAddr, r.Header.Get("Cookie"), r.Header.Get("Accept")
		got.tls = r.TLS != nil
		for _, c := range r.Cookies() {
			got.cookies = append(got.cookies, c.Name+"="+c.Value)
		}
		got.body, _ = io.ReadAll(r.Body)
		http.SetCookie(w, &http.Cookie{Name: "dns_gate_session", Value: "new", Path: "/", HttpOnly: true, Secure: true})
		http.SetCookie(w, &http.Cookie{Name: "dns_gate_state", Value: "", Path: "/", MaxAge: -1})
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Cookie")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	resp := invoke(t, h, httpEvent)

	want := seen{
		method: "POST", path: "/api/v1/zones/example.com/rrsets", query: "type=A&host=www%20x",
		host: "dns-gate.example.com", host2: "www x", remote: "198.51.100.7:0",
		cookie: "dns_gate_session=abc; dns_gate_state=xyz", accept: "application/json, text/plain",
		body: []byte{0, 1, 2, 0xff}, tls: true,
		cookies: []string{"dns_gate_session=abc", "dns_gate_state=xyz"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request:\n got %+v\nwant %+v", got, want)
	}
	if resp.StatusCode != http.StatusCreated || resp.IsBase64Encoded || resp.Body != `{"ok":true}` {
		t.Fatalf("response: %d base64=%v %q", resp.StatusCode, resp.IsBase64Encoded, resp.Body)
	}
	if resp.Headers["Vary"] != "Origin, Cookie" || resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("headers %v", resp.Headers)
	}
	if _, ok := resp.Headers["Set-Cookie"]; ok {
		t.Error("Set-Cookie must go to the cookies array")
	}
	sort.Strings(resp.Cookies)
	if len(resp.Cookies) != 2 || !strings.HasPrefix(resp.Cookies[0], "dns_gate_session=new;") || !strings.HasPrefix(resp.Cookies[1], "dns_gate_state=;") {
		t.Errorf("cookies %q", resp.Cookies)
	}
}

func TestHTTPBinaryAndDefaults(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	cases := []struct {
		name    string
		handler http.HandlerFunc
		status  int
		base64  bool
		body    []byte
	}{
		{"sniffed binary", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(png) }, 200, true, png},
		{"gzip", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("abc"))
		}, 200, true, []byte("abc")},
		{"sniffed html", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<!doctype html><p>x")) }, 200, false, []byte("<!doctype html><p>x")},
		{"empty", func(w http.ResponseWriter, _ *http.Request) {}, 200, false, nil},
		{"status only", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }, 204, false, nil},
		{"svg", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = w.Write([]byte("<svg/>"))
		}, 200, false, []byte("<svg/>")},
	}
	ev := `{"version":"2.0","rawPath":"/x","headers":{"host":"h"},"requestContext":{"http":{"method":"GET","sourceIp":"192.0.2.1"}},"isBase64Encoded":false}`
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := invoke(t, &Handler{HTTP: c.handler, Log: quiet()}, ev)
			if resp.StatusCode != c.status || resp.IsBase64Encoded != c.base64 {
				t.Fatalf("status %d base64 %v", resp.StatusCode, resp.IsBase64Encoded)
			}
			body := []byte(resp.Body)
			if resp.IsBase64Encoded {
				var err error
				if body, err = base64.StdEncoding.DecodeString(resp.Body); err != nil {
					t.Fatal(err)
				}
			}
			if string(body) != string(c.body) {
				t.Fatalf("body %q", body)
			}
		})
	}
}

func TestHTTPRequestWithoutBodyOrQuery(t *testing.T) {
	var path, host string
	var n int64
	h := &Handler{Log: quiet(), HTTP: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		path, host, n = r.URL.String(), r.Host, r.ContentLength
	})}
	invoke(t, h, `{"version":"2.0","rawPath":"","requestContext":{"domainName":"api.example.com","http":{"method":"GET"}}}`)
	if path != "/" || host != "api.example.com" || n != 0 {
		t.Fatalf("path %q host %q length %d", path, host, n)
	}
}

func TestMaintenanceDispatch(t *testing.T) {
	calls := 0
	var fail error
	h := &Handler{Log: quiet(), HTTP: http.NotFoundHandler(), Maintenance: func(context.Context) error { calls++; return fail }}
	out, err := h.Invoke(context.Background(), []byte(`{"dns_gate_task":"maintenance"}`))
	if err != nil || calls != 1 {
		t.Fatalf("maintenance: %v calls=%d", err, calls)
	}
	var res MaintenanceResult
	if err := json.Unmarshal(out, &res); err != nil || res.Task != TaskMaintenance {
		t.Fatalf("result %s: %v", out, err)
	}
	fail = errors.New("reconcile example.com: down")
	if _, err := h.Invoke(context.Background(), []byte(`{"dns_gate_task":"maintenance"}`)); !errors.Is(err, fail) {
		t.Fatalf("maintenance error must fail the invocation, got %v", err)
	}
	if _, err := h.Invoke(context.Background(), []byte(`{"dns_gate_task":"other"}`)); err == nil || calls != 2 {
		t.Fatalf("unknown task: %v calls=%d", err, calls)
	}
	if _, err := (&Handler{}).Invoke(context.Background(), []byte(`{"dns_gate_task":"maintenance"}`)); err == nil {
		t.Fatal("maintenance without a function must fail")
	}
}

func TestUnsupportedEvents(t *testing.T) {
	h := &Handler{Log: quiet(), HTTP: http.NotFoundHandler(), Maintenance: func(context.Context) error { return nil }}
	for _, ev := range []string{
		`not json`,
		`{}`,
		`{"source":"aws.events","detail-type":"Scheduled Event"}`,
		`{"version":"1.0","httpMethod":"GET","path":"/"}`,
		`{"version":"2.0","rawPath":"/"}`,
		`[]`,
	} {
		if _, err := h.Invoke(context.Background(), []byte(ev)); !errors.Is(err, ErrUnsupportedEvent) {
			t.Errorf("%s: got %v", ev, err)
		}
	}
	bad := `{"version":"2.0","rawPath":"/","requestContext":{"http":{"method":"POST"}},"body":"%%%","isBase64Encoded":true}`
	if _, err := h.Invoke(context.Background(), []byte(bad)); err == nil {
		t.Error("invalid base64 body must fail")
	}
}

func TestInstanceID(t *testing.T) {
	t.Setenv("AWS_LAMBDA_LOG_STREAM_NAME", "2026/11/05/[$LATEST]0123abcd")
	if got := InstanceID(); got != "lambda:2026/11/05/[$LATEST]0123abcd" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("AWS_LAMBDA_LOG_STREAM_NAME", "")
	if InstanceID() != "" {
		t.Fatal("empty outside Lambda")
	}
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "127.0.0.1:9001")
	if !Enabled() {
		t.Fatal("Enabled with AWS_LAMBDA_RUNTIME_API")
	}
}
