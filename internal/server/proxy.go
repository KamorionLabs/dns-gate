package server

import (
	"context"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/routes"
	"github.com/KamorionLabs/dns-gate/internal/version"
)

type matchKey struct{}

// forwardedHeaders are the only client headers sent upstream.
var forwardedHeaders = []string{"Accept", "Content-Type"}

func (s *Server) newProxy() http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			m, _ := pr.In.Context().Value(matchKey{}).(*routes.Match)
			out := pr.Out
			out.URL.Scheme = s.upstream.Scheme
			out.URL.Host = s.upstream.Host
			out.URL.Path = strings.TrimSuffix(s.upstream.Path, "/") + m.Path
			out.URL.RawPath = ""
			out.URL.RawQuery = ""
			out.Host = s.upstream.Host
			h := http.Header{}
			for _, k := range forwardedHeaders {
				if v := pr.In.Header.Get(k); v != "" {
					h.Set(k, v)
				}
			}
			h.Set("User-Agent", "dns-gate/"+version.Version)
			out.Header = h
			out.Body = http.NoBody
			out.ContentLength = 0
		},
		Transport: s.cfg.Upstream,
		ModifyResponse: func(resp *http.Response) error {
			for _, k := range []string{"Set-Cookie", "Server", "X-Powered-By"} {
				resp.Header.Del(k)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("upstream proxy error", "request_id", requestid.From(r.Context()), "err", err)
			writeError(w, http.StatusBadGateway, "upstream", "EuroDNS is unreachable")
		},
	}
}

func (s *Server) servePassthrough(w http.ResponseWriter, r *http.Request, m *routes.Match) {
	ctx := r.Context()
	s.proxy.ServeHTTP(w, r.WithContext(contextWithMatch(ctx, m)))
}

func contextWithMatch(ctx context.Context, m *routes.Match) context.Context {
	return context.WithValue(ctx, matchKey{}, m)
}
