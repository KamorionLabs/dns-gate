package server

import (
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

func TestForwardAPI(t *testing.T) {
	e := newEnv(t)
	tok := e.token("writer")
	r := e.do(t, "PUT", "/api/v1/zones/example.com/forwards/Go", tok, `{"type":"301","url":"https://example.net/","require_https":true}`, map[string]string{"If-None-Match": "*"})
	v := decode[forwardView](t, r)
	c := e.lastApplied(t)
	if r.StatusCode != 200 || c.Host != "go" || c.Type != dns.TypeURLForward || !c.MustNotExist || !c.RequireHTTPS || c.Forward == nil || c.Forward.URL != "https://example.net/" {
		t.Fatalf("put: %d %+v", r.StatusCode, c)
	}
	if v.Forward == nil || v.Type != dns.TypeURLForward || v.HTTPS == nil || v.HTTPS.Status != provider.HTTPSInactive || r.Header.Get("ETag") != `"`+v.Hash+`"` {
		t.Fatalf("view %+v", v)
	}
	if r := e.do(t, "DELETE", "/api/v1/zones/example.com/forwards/go", tok, "", map[string]string{"If-Match": `"abc"`}); r.StatusCode != 204 || !e.lastApplied(t).Delete || e.lastApplied(t).ExpectedHash != "abc" {
		t.Fatalf("delete: %d %+v", r.StatusCode, e.lastApplied(t))
	}
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"PUT", "/api/v1/zones/example.com/forwards/go", `{"type":"301"}`, 400},
		{"PUT", "/api/v1/zones/example.com/forwards/go", `{"type":"301","url":"https://example.net/","ttl":3600}`, 400},
		{"PUT", "/api/v1/zones/example.com/rrsets/go/URLFWD", `{"values":["x"]}`, 400},
		{"PUT", "/api/v1/zones/unmanaged.example/forwards/go", `{"type":"301","url":"https://example.net/"}`, 404},
		{"GET", "/api/v1/zones/example.com/forwards/go", "", 404},
		{"GET", "/api/v1/zones/example.com/forwards/a.*", "", 400},
	} {
		if r := e.do(t, tc.method, tc.path, tok, tc.body, nil); r.StatusCode != tc.status {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, r.StatusCode, tc.status)
		}
	}
	r = e.do(t, "GET", "/api/v1/zones/example.com/forwards", tok, "", nil)
	l := decode[forwardList](t, r)
	if r.StatusCode != 200 || l.Zone != "example.com" || l.Forwards == nil || len(l.Forwards) != 0 || l.HTTPS == nil {
		t.Fatalf("list: %d %+v", r.StatusCode, l)
	}
}
