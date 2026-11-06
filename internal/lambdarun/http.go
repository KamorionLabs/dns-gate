package lambdarun

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
)

func (h *Handler) serveHTTP(ctx context.Context, payload []byte) ([]byte, error) {
	var ev events.APIGatewayV2HTTPRequest
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, fmt.Errorf("API Gateway event: %w", err)
	}
	req, err := NewRequest(ctx, &ev)
	if err != nil {
		return nil, err
	}
	rec := newRecorder()
	h.HTTP.ServeHTTP(rec, req)
	return json.Marshal(rec.response())
}

// NewRequest converts an API Gateway HTTP API (payload 2.0) event into a
// server request: raw path and query, headers, cookies, base64 body, the
// caller address as RemoteAddr and TLS set (API Gateway is HTTPS only).
func NewRequest(ctx context.Context, ev *events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	body := []byte(ev.Body)
	if ev.IsBase64Encoded {
		b, err := base64.StdEncoding.DecodeString(ev.Body)
		if err != nil {
			return nil, fmt.Errorf("API Gateway event: body: %w", err)
		}
		body = b
	}
	path := ev.RawPath
	if path == "" {
		path = "/"
	}
	target := path
	if ev.RawQueryString != "" {
		target += "?" + ev.RawQueryString
	}
	req, err := http.NewRequestWithContext(ctx, ev.RequestContext.HTTP.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("API Gateway event: %w", err)
	}
	req.RequestURI = target
	for k, v := range ev.Headers {
		req.Header.Set(k, v)
	}
	if len(ev.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(ev.Cookies, "; "))
	}
	req.Host = req.Header.Get("Host")
	if req.Host == "" {
		req.Host = ev.RequestContext.DomainName
	}
	req.Header.Del("Host")
	if p := ev.RequestContext.HTTP.Protocol; p != "" {
		if major, minor, ok := http.ParseHTTPVersion(p); ok {
			req.Proto, req.ProtoMajor, req.ProtoMinor = p, major, minor
		}
	}
	if ip := ev.RequestContext.HTTP.SourceIP; ip != "" {
		req.RemoteAddr = net.JoinHostPort(ip, "0")
	}
	req.TLS = &tls.ConnectionState{ServerName: req.Host}
	return req, nil
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{header: http.Header{}} }

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.header.Get("Content-Type") == "" && r.body.Len() == 0 && len(b) > 0 {
		r.header.Set("Content-Type", http.DetectContentType(b))
	}
	return r.body.Write(b)
}

// Flush is a no-op: the response is sent whole when the handler returns.
func (r *recorder) Flush() {}

func (r *recorder) response() events.APIGatewayV2HTTPResponse {
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	out := events.APIGatewayV2HTTPResponse{StatusCode: status, Headers: map[string]string{}}
	for k, vs := range r.header {
		if len(vs) == 0 {
			continue
		}
		if k == "Set-Cookie" {
			out.Cookies = append(out.Cookies, vs...)
			continue
		}
		out.Headers[k] = strings.Join(vs, ", ")
	}
	b := r.body.Bytes()
	if textual(r.header, b) {
		out.Body = string(b)
	} else {
		out.Body = base64.StdEncoding.EncodeToString(b)
		out.IsBase64Encoded = true
	}
	return out
}

func textual(h http.Header, b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if h.Get("Content-Encoding") != "" || !utf8.Valid(b) {
		return false
	}
	mt, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"),
		mt == "application/json", mt == "application/xml",
		mt == "application/javascript", mt == "application/x-www-form-urlencoded":
		return true
	}
	return false
}
