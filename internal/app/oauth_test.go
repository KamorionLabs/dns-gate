package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/oidctest"
)

const e2eSecret = "e2e-client-secret-0123456789abcdefghij"

var hiddenField = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// A declared client links a user signed in with OIDC, through the binary
// wiring and a SQLite store: the grant survives a restart of the gate.
func TestOAuthClientEndToEnd(t *testing.T) {
	idp := oidctest.New()
	t.Cleanup(idp.Close)
	idp.LoginClaims = map[string]any{"sub": "alice", "email": "alice@example.com"}
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signing := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	db := filepath.Join(t.TempDir(), "gate.db")
	yaml := `
providers:
  - {id: eurodns, kind: eurodns, eurodns: {base_url: "http://127.0.0.1:1", app_id: app, max_retries: 0}}
zones: [example.com]
store: {type: sqlite, sqlite: {path: ` + db + `}}
issuers:
  - {name: idp, issuer: "` + idp.URL + `", audiences: [dns-gate], category: human}
  - {name: gate, self: true, issuer: "` + srv.URL + `"}
ui:
  enabled: true
  issuer: idp
  client_id: gate-ui
  redirect_url: ` + srv.URL + `/auth/callback
roles:
  reader: {rules: [{zones: [example.com], actions: [dns.read, ui.read]}]}
bindings:
  - {role: reader, team: web, subjects: [{issuer: idp, claims: {sub: alice}}]}
oauth:
  clients:
    - id: skopea
      name: Skopea
      auth_method: client_secret_post
      redirect_uris: [https://app.skopea.example/cb]
      scopes: [dns.read]
`
	vars := map[string]string{
		"DNS_GATE_SESSION_KEY": strings.Repeat("ab", 32), "DNS_GATE_TOKEN_SIGNING_KEY": signing,
		"DNS_GATE_OAUTH_CLIENT_SKOPEA_SECRET": e2eSecret, "EURODNS_API_KEY": "k",
	}
	boot := func() {
		cfg, err := config.Parse([]byte(yaml), func(k string) string { return vars[k] })
		if err != nil {
			t.Fatal(err)
		}
		a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Holder: "t"})
		if err != nil {
			t.Fatal(err)
		}
		srv.Config.Handler = a.Handler()
		t.Cleanup(func() { _ = a.Store.(interface{ Close() error }).Close() })
	}
	boot()

	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, Transport: idp.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(u string) *http.Response {
		t.Helper()
		if strings.HasPrefix(u, "/") {
			u = srv.URL + u
		}
		resp, err := b.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	vb := make([]byte, 32)
	_, _ = rand.Read(vb)
	verifier := base64.RawURLEncoding.EncodeToString(vb)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {"skopea"}, "redirect_uri": {"https://app.skopea.example/cb"}, "state": {"s1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "scope": {"dns.read offline_access"}}

	resp := get("/oauth/authorize?" + q.Encode())
	for i := 0; i < 5 && (resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther); i++ {
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "https://app.skopea.example") {
			break
		}
		resp = get(loc)
	}
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(page), "Skopea") {
		t.Fatalf("consent page: %d %s", resp.StatusCode, page)
	}
	form := url.Values{"decision": {"allow"}}
	for _, m := range hiddenField.FindAllStringSubmatch(string(page), -1) {
		form.Set(m[1], strings.ReplaceAll(strings.ReplaceAll(m[2], "&amp;", "&"), "&#43;", "+"))
	}
	req, _ := http.NewRequest("POST", srv.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", srv.URL)
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if cb.Host != "app.skopea.example" || cb.Query().Get("iss") != srv.URL || cb.Query().Get("code") == "" {
		t.Fatalf("callback: %d %s", resp.StatusCode, cb)
	}

	token := func(f url.Values) map[string]any {
		t.Helper()
		f.Set("client_id", "skopea")
		f.Set("client_secret", e2eSecret)
		resp, err := http.PostForm(srv.URL+"/oauth/token", f)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != 200 {
			t.Fatalf("token: %d %v", resp.StatusCode, out)
		}
		return out
	}
	tr := token(url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {"https://app.skopea.example/cb"}, "code_verifier": {verifier}})
	me := func(tok string) int {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := me(tr["access_token"].(string)); code != 200 {
		t.Fatalf("me: %d", code)
	}

	boot()
	tr = token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr["refresh_token"].(string)}})
	if code := me(tr["access_token"].(string)); code != 200 {
		t.Fatalf("me after a restart: %d", code)
	}
	resp, err = http.PostForm(srv.URL+"/oauth/revoke", url.Values{"token": {tr["refresh_token"].(string)}, "client_id": {"skopea"}, "client_secret": {e2eSecret}})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("revoke: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()
	if code := me(tr["access_token"].(string)); code != 401 {
		t.Fatalf("me after revocation: %d", code)
	}
}
