package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

const (
	skopeaRedirect  = "https://app.skopea.example/api/v1/orgs/acme/dns/oauth/callback"
	copilotRedirect = "https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect"
	copilotSecret   = "copilot-secret-0123456789abcdefghijklmnop"
)

type oauthEnv struct {
	*samlEnvT
	key *ecdsa.PrivateKey
	b   *http.Client
}

func testOAuthClient(id string, mut func(*config.OAuthClient)) config.OAuthClient {
	oc := config.OAuthClient{
		ID: id, Name: id, Type: config.OAuthConfidential, Surfaces: []string{scope.SurfaceAPI},
		AccessTokenTTL: config.Duration(10 * time.Minute), RefreshIdleTTL: config.Duration(14 * 24 * time.Hour),
		RefreshMaxTTL: config.Duration(90 * 24 * time.Hour), ClaimsMaxAge: config.Duration(7 * 24 * time.Hour),
	}
	if mut != nil {
		mut(&oc)
	}
	return oc
}

func newOAuthEnv(t *testing.T, tweak func(*config.Config)) *oauthEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	e := newSAMLEnv(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
		c.OAuth.Clients = []config.OAuthClient{
			testOAuthClient("skopea-acme", func(oc *config.OAuthClient) {
				oc.Name, oc.AuthMethod, oc.KeySet = "Skopea — Acme", config.OAuthPrivateKeyJWT, set
				oc.RedirectURIs = []string{skopeaRedirect}
				oc.Scopes, oc.DefaultScopes = []string{scope.DNSRead, scope.DNSPlan, scope.DNSWrite}, []string{scope.DNSRead}
			}),
			testOAuthClient("copilot", func(oc *config.OAuthClient) {
				oc.Name, oc.AuthMethod, oc.Secret = "Microsoft 365 Copilot", config.OAuthClientSecretBasic, copilotSecret
				oc.RedirectURIs, oc.Scopes, oc.Surfaces = []string{copilotRedirect}, []string{scope.DNSRead}, []string{scope.SurfaceMCP}
			}),
		}
		if tweak != nil {
			tweak(c)
		}
	})
	return &oauthEnv{samlEnvT: e, key: key, b: browser()}
}

// authorize runs an authorization request in the signed-in browser,
// allowing on the consent page when shown, and returns the final redirect
// and whether the consent page was shown.
func (e *oauthEnv) authorize(t *testing.T, q url.Values) (*url.URL, bool) {
	t.Helper()
	resp, err := e.b.Get(e.base + oauthAuthorizePath + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		u, _ := url.Parse(resp.Header.Get("Location"))
		return u, false
	}
	if resp.StatusCode != 200 {
		t.Fatalf("authorize: %d %s", resp.StatusCode, page)
	}
	form := consentForm(t, string(page))
	form.Set("decision", "allow")
	req, _ := http.NewRequest("POST", e.base+oauthAuthorizePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.base)
	r, err := e.b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	u, _ := url.Parse(r.Header.Get("Location"))
	return u, true
}

func skopeaQuery(challenge, sc string) url.Values {
	q := url.Values{
		"response_type": {"code"}, "client_id": {"skopea-acme"}, "redirect_uri": {skopeaRedirect},
		"state": {"st-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if sc != "" {
		q.Set("scope", sc)
	}
	return q
}

func (e *oauthEnv) clientAssertion(t *testing.T, aud, jti string, life time.Duration) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: e.key, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := e.clock()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: "skopea-acme", Subject: "skopea-acme", Audience: jwt.Audience{aud}, ID: jti,
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(life)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type tokenResult struct {
	status int
	tr     tokenResponse
	err    string
	header http.Header
}

func (e *oauthEnv) tokenCall(t *testing.T, path string, f url.Values, basicUser, basicPass string) tokenResult {
	t.Helper()
	req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicPass))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var res tokenResult
	res.status, res.header = resp.StatusCode, resp.Header
	_ = json.Unmarshal(raw, &res.tr)
	var oe oauthError
	_ = json.Unmarshal(raw, &oe)
	res.err = oe.Error
	return res
}

func (e *oauthEnv) skopeaToken(t *testing.T, f url.Values) tokenResult {
	t.Helper()
	g := url.Values{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion": {e.clientAssertion(t, e.base+oauthTokenPath, randomToken(), 2*time.Minute)}}
	for k, v := range f {
		g[k] = v
	}
	return e.tokenCall(t, oauthTokenPath, g, "", "")
}

// link signs alice in and runs the whole authorization of Skopea; it
// returns the token answer.
func (e *oauthEnv) link(t *testing.T, sc string) tokenResult {
	t.Helper()
	verifier, challenge := pkcePair()
	cb, _ := e.authorize(t, skopeaQuery(challenge, sc))
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", cb)
	}
	res := e.skopeaToken(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}})
	if res.status != 200 || res.tr.RefreshToken == "" {
		t.Fatalf("code exchange: %d %s", res.status, res.err)
	}
	return res
}

func (e *oauthEnv) refresh(t *testing.T, rt string) tokenResult {
	t.Helper()
	return e.skopeaToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

func unverifiedClaims(t *testing.T, raw string) (map[string]any, string) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{}
	_ = tok.UnsafeClaimsWithoutVerification(&c)
	typ, _ := tok.Headers[0].ExtraHeaders["typ"].(string)
	return c, typ
}

func (e *oauthEnv) me(t *testing.T, tok string) (int, uiapi.Me) {
	t.Helper()
	r := e.do(t, "GET", "/api/v1/me", tok, "", nil)
	var me uiapi.Me
	_ = json.NewDecoder(r.Body).Decode(&me)
	return r.StatusCode, me
}

func (e *oauthEnv) eventsOf(action string) []audit.Event {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	var out []audit.Event
	for _, ev := range e.audit.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

func TestOAuthMetadata(t *testing.T) {
	e := newOAuthEnv(t, nil)
	var meta map[string]any
	if code := getJSON(t, http.DefaultClient, e.base+oauthMetadataPath, &meta); code != 200 {
		t.Fatalf("metadata: %d", code)
	}
	if meta["revocation_endpoint"] != e.base+oauthRevokePath || meta["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("metadata: %v", meta)
	}
	for k, want := range map[string]string{"token_endpoint_auth_methods_supported": "private_key_jwt", "scopes_supported": "dns.write", "code_challenge_methods_supported": "S256"} {
		found := false
		for _, v := range meta[k].([]any) {
			found = found || v == want
		}
		if !found {
			t.Errorf("%s without %s: %v", k, want, meta[k])
		}
	}
}

func TestOAuthClientLink(t *testing.T) {
	e := newOAuthEnv(t, nil)
	verifier, challenge := pkcePair()
	q := skopeaQuery(challenge, "dns.read offline_access")

	resp, _ := e.b.Get(e.base + oauthAuthorizePath + "?" + q.Encode())
	resp.Body.Close()
	lu, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || lu.Path != "/auth/login" {
		t.Fatalf("anonymous authorize: %d %s", resp.StatusCode, lu)
	}
	in := e.startLogin(t, e.b, "?"+lu.RawQuery)
	ar := e.post(t, e.b, e.idp.Response(e.assertion(in, "alice@example.com", "DNS-Writers")), in.RelayState)
	resp, _ = e.b.Get(e.base + ar.Header.Get("Location"))
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if resp.StatusCode != 200 || !strings.Contains(string(page), "Skopea — Acme") || !strings.Contains(string(page), scope.Label(scope.DNSRead)) ||
		!strings.Contains(string(page), "90 days") || !strings.Contains(csp, "form-action 'self' "+skopeaRedirect+";") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("consent page: %d %s\n%s", resp.StatusCode, csp, page)
	}
	cb, shown := e.authorize(t, q)
	if !shown || cb.Scheme+"://"+cb.Host+cb.Path != skopeaRedirect || cb.Query().Get("state") != "st-1" || cb.Query().Get("iss") != e.base {
		t.Fatalf("callback: %v %s", shown, cb)
	}
	code := cb.Query().Get("code")
	base := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}}

	noAuth := e.tokenCall(t, oauthTokenPath, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"skopea-acme"}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}}, "", "")
	if noAuth.status != 401 || noAuth.err != "invalid_client" {
		t.Fatalf("without client authentication: %d %s", noAuth.status, noAuth.err)
	}
	res := e.skopeaToken(t, base)
	if res.status != 200 || res.tr.TokenType != "Bearer" || res.tr.ExpiresIn != 600 || res.tr.Scope != "dns.read offline_access" {
		t.Fatalf("exchange: %d %s %+v", res.status, res.err, res.tr)
	}
	if again := e.skopeaToken(t, base); again.status != 400 || again.err != "invalid_grant" {
		t.Fatalf("code used twice: %d %s", again.status, again.err)
	}
	claims, typ := unverifiedClaims(t, res.tr.AccessToken)
	act, _ := claims["act"].(map[string]any)
	if typ != "at+jwt" || claims["client_id"] != "skopea-acme" || claims["scope"] != "dns.read" || act["sub"] != "client:skopea-acme" ||
		claims["gate_grant"] == "" || claims["auth_time"] == nil || claims["sub"] != "alice@example.com" || claims["gate_iss"] != "identity-center" {
		t.Fatalf("access token: %s %v", typ, claims)
	}
	code200, me := e.me(t, res.tr.AccessToken)
	if code200 != 200 || me.Subject != "identity-center:alice@example.com" || me.Email != "alice@example.com" || me.Client == nil || me.Client.ID != "skopea-acme" || len(me.Scopes) != 1 {
		t.Fatalf("me: %d %+v", code200, me)
	}
	if r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", res.tr.AccessToken, `{"ttl":300,"records":["192.0.2.1"]}`, nil); r.StatusCode != 403 || reason(t, r) != "scope_insufficient" {
		t.Fatalf("write without dns.write: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/api/v1/tokens", res.tr.AccessToken, "", nil); r.StatusCode != 403 || reason(t, r) != "not_delegable" {
		t.Fatalf("tokens endpoint: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/api/v1/oauth/grants", res.tr.AccessToken, "", nil); r.StatusCode != 403 {
		t.Fatalf("grants with a delegated token: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/mcp", res.tr.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, map[string]string{"Accept": "application/json, text/event-stream"}); r.StatusCode != 403 || reason(t, r) != "not_delegable" {
		t.Fatalf("mcp outside the surfaces of the client: %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/dns-zones/example.com", res.tr.AccessToken, "", nil); r.StatusCode != 403 {
		t.Fatalf("EuroDNS API: %d", r.StatusCode)
	}

	grant := claims["gate_grant"].(string)
	var found bool
	for _, ev := range e.eventsOf("oauth.authorize") {
		found = found || (ev.Decision == "allow" && ev.ClientID == "skopea-acme" && ev.Subject == "identity-center:alice@example.com" && ev.Actor != nil && ev.Actor.Name == "Skopea — Acme")
	}
	if !found {
		t.Fatal("consent not audited")
	}
	found = false
	for _, ev := range e.eventsOf("oauth.token") {
		found = found || (ev.Decision == "allow" && ev.ClientID == "skopea-acme" && ev.Extra["grant_id"] == grant && ev.Extra["via"] == "authorization_code")
	}
	if !found {
		t.Fatal("token not audited")
	}
	e.audit.mu.Lock()
	var apiEvent *audit.Event
	for i := range e.audit.events {
		if ev := e.audit.events[i]; ev.Action == "api" && ev.ClientID == "skopea-acme" {
			apiEvent = &e.audit.events[i]
		}
	}
	e.audit.mu.Unlock()
	if apiEvent == nil {
		t.Fatal("refused write not audited")
	}
	pe := *apiEvent
	audit.Prepare(context.Background(), &pe)
	if pe.AuthMethod != audit.AuthOAuthDelegated && pe.AuthMethod != "" {
		t.Fatalf("auth method: %q", pe.AuthMethod)
	}
}

func TestOAuthCodeChecks(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	verifier, challenge := pkcePair()

	evil := skopeaQuery(challenge, "")
	evil.Set("redirect_uri", "https://app.skopea.example/other")
	resp, _ := e.b.Get(e.base + oauthAuthorizePath + "?" + evil.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("unregistered redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	noPKCE := skopeaQuery(challenge, "")
	noPKCE.Del("code_challenge")
	cb, _ := e.authorize(t, noPKCE)
	if cb.Query().Get("error") != "invalid_request" || cb.Query().Get("iss") != e.base {
		t.Fatalf("without PKCE: %s", cb)
	}
	plain := skopeaQuery(challenge, "")
	plain.Set("code_challenge_method", "plain")
	if cb, _ = e.authorize(t, plain); cb.Query().Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE: %s", cb)
	}
	if cb, _ = e.authorize(t, skopeaQuery(challenge, "dns.read dns.zone.admin")); cb.Query().Get("error") != "invalid_scope" {
		t.Fatalf("unknown scope: %s", cb)
	}
	if cb, _ = e.authorize(t, skopeaQuery(challenge, "dns.adopt")); cb.Query().Get("error") != "invalid_scope" {
		t.Fatalf("scope above the client ceiling: %s", cb)
	}

	cb, _ = e.authorize(t, skopeaQuery(challenge, ""))
	code := cb.Query().Get("code")
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {skopeaRedirect}}
	if r := e.skopeaToken(t, f); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("without verifier: %d %s", r.status, r.err)
	}
	cb, _ = e.authorize(t, skopeaQuery(challenge, ""))
	code = cb.Query().Get("code")
	f = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.skopea.example/other"}, "code_verifier": {verifier}}
	if r := e.skopeaToken(t, f); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("other redirect at the token endpoint: %d %s", r.status, r.err)
	}

	cb, _ = e.authorize(t, skopeaQuery(challenge, ""))
	code = cb.Query().Get("code")
	copilot := e.tokenCall(t, oauthTokenPath, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}}, "copilot", copilotSecret)
	if copilot.status != 400 || copilot.err != "invalid_grant" {
		t.Fatalf("code of another client: %d %s", copilot.status, copilot.err)
	}

	cb, _ = e.authorize(t, skopeaQuery(challenge, ""))
	e.offset = 3 * time.Minute
	if r := e.skopeaToken(t, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}}); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("expired code: %d %s", r.status, r.err)
	}
}

func TestOAuthPrivateKeyJWT(t *testing.T) {
	e := newOAuthEnv(t, nil)
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}}
	call := func(assertion string) tokenResult {
		g := url.Values{}
		for k, v := range f {
			g[k] = v
		}
		g.Set("client_assertion", assertion)
		return e.tokenCall(t, oauthTokenPath, g, "", "")
	}
	a := e.clientAssertion(t, e.base+oauthTokenPath, "jti-1", 2*time.Minute)
	if r := call(a); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("valid assertion: %d %s", r.status, r.err)
	}
	if r := call(a); r.status != 401 || r.err != "invalid_client" {
		t.Fatalf("replayed assertion: %d %s", r.status, r.err)
	}
	if r := call(e.clientAssertion(t, e.base+oauthTokenPath, "jti-2", time.Hour)); r.status != 401 {
		t.Fatalf("assertion valid for an hour: %d", r.status)
	}
	if r := call(e.clientAssertion(t, "https://other-gate.example", "jti-3", time.Minute)); r.status != 401 {
		t.Fatalf("assertion for another audience: %d", r.status)
	}
	if r := call(e.clientAssertion(t, e.base, "jti-4", time.Minute)); r.status != 400 {
		t.Fatalf("assertion for the issuer: %d %s", r.status, r.err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e.key = other
	if r := call(e.clientAssertion(t, e.base+oauthTokenPath, "jti-5", time.Minute)); r.status != 401 {
		t.Fatalf("assertion of another key: %d", r.status)
	}
	if n := len(e.eventsOf("oauth.client_auth")); n == 0 || n > 2 {
		t.Fatalf("client authentication failures not aggregated: %d events", n)
	}
}

func TestOAuthRefreshRotation(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	first := e.link(t, "dns.read")

	second := e.refresh(t, first.tr.RefreshToken)
	if second.status != 200 || second.tr.RefreshToken == first.tr.RefreshToken || second.tr.AccessToken == first.tr.AccessToken {
		t.Fatalf("refresh: %d %s", second.status, second.err)
	}
	grace := e.refresh(t, first.tr.RefreshToken)
	if grace.status != 200 || grace.tr.RefreshToken != second.tr.RefreshToken || grace.tr.AccessToken != second.tr.AccessToken {
		t.Fatalf("grace: %d %s", grace.status, grace.err)
	}
	third := e.refresh(t, second.tr.RefreshToken)
	if third.status != 200 {
		t.Fatalf("refresh of the new token: %d %s", third.status, third.err)
	}
	e.offset = 31 * time.Second
	reuse := e.refresh(t, second.tr.RefreshToken)
	if reuse.status != 400 || reuse.err != "invalid_grant" {
		t.Fatalf("reuse: %d %s", reuse.status, reuse.err)
	}
	if r := e.refresh(t, third.tr.RefreshToken); r.status != 400 {
		t.Fatalf("family not revoked: %d", r.status)
	}
	if code, _ := e.me(t, third.tr.AccessToken); code != 401 {
		t.Fatalf("access token of a revoked grant: %d", code)
	}
	if ev := e.eventsOf("oauth.refresh_reuse"); len(ev) != 1 || ev[0].ClientID != "skopea-acme" || ev[0].Subject != "identity-center:alice@example.com" {
		t.Fatalf("reuse audit: %+v", ev)
	}
	var list uiapi.OAuthGrantList
	if code := getJSON(t, e.b, e.base+"/api/v1/oauth/grants", &list); code != 200 || len(list.Grants) != 1 || list.Grants[0].Status != uiapi.OAuthGrantRevoked {
		t.Fatalf("grants: %d %+v", code, list)
	}
}

func TestOAuthConcurrentRefresh(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	first := e.link(t, "")
	var wg sync.WaitGroup
	results := make([]tokenResult, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = e.refresh(t, first.tr.RefreshToken)
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.status != 200 || r.tr.RefreshToken != results[0].tr.RefreshToken {
			t.Fatalf("racing refresh %d: %d %s", i, r.status, r.err)
		}
	}
	if r := e.refresh(t, results[0].tr.RefreshToken); r.status != 200 {
		t.Fatalf("grant lost in the race: %d %s", r.status, r.err)
	}
}

func TestOAuthGrantExpiry(t *testing.T) {
	e := newOAuthEnv(t, func(c *config.Config) {
		c.OAuth.Clients[0].RefreshIdleTTL = config.Duration(48 * time.Hour)
		c.OAuth.Clients[0].ClaimsMaxAge = config.Duration(72 * time.Hour)
		c.OAuth.Clients[0].RefreshMaxTTL = config.Duration(30 * 24 * time.Hour)
	})
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res := e.link(t, "")
	e.offset = 49 * time.Hour
	if r := e.refresh(t, res.tr.RefreshToken); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("idle grant: %d %s", r.status, r.err)
	}
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	_, challenge := pkcePair()
	if _, shown := e.authorize(t, skopeaQuery(challenge, "")); !shown {
		t.Fatal("consent of an idle grant remembered")
	}

	e.offset = 0
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res = e.link(t, "")
	e.offset = 40 * time.Hour
	if res = e.refresh(t, res.tr.RefreshToken); res.status != 200 {
		t.Fatalf("refresh within the idle time: %d %s", res.status, res.err)
	}
	if code, me := e.me(t, res.tr.AccessToken); code != 200 || me.Email != "alice@example.com" {
		t.Fatalf("email after a refresh within claims_max_age: %d %+v", code, me)
	}
	e.offset = 73 * time.Hour
	if r := e.refresh(t, res.tr.RefreshToken); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("claims older than claims_max_age: %d %s", r.status, r.err)
	}
	if code, _ := e.me(t, res.tr.AccessToken); code != 401 {
		t.Fatalf("expired access token: %d", code)
	}

	e.server.cfg.Config.OAuth.Clients[0].ClaimsMaxAge = config.Duration(30 * 24 * time.Hour)
	e.offset = 0
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res = e.link(t, "")
	for _, h := range []time.Duration{40, 80, 120, 160, 200, 240, 280, 320, 360, 400, 440, 480, 520, 560, 600, 640, 680, 720} {
		e.offset = h * time.Hour
		if res = e.refresh(t, res.tr.RefreshToken); res.status != 200 {
			if h*time.Hour < 30*24*time.Hour {
				t.Fatalf("refresh at %dh: %d %s", h, res.status, res.err)
			}
			if res.err != "invalid_grant" {
				t.Fatalf("after refresh_max_ttl: %d %s", res.status, res.err)
			}
			return
		}
	}
	t.Fatal("grant outlived refresh_max_ttl")
}

func TestOAuthRevocation(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res := e.link(t, "")
	revoke := func(token string) tokenResult {
		return e.tokenCall(t, oauthRevokePath, url.Values{"token": {token}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion": {e.clientAssertion(t, e.base+oauthTokenPath, randomToken(), time.Minute)}}, "", "")
	}
	if r := revoke("unknown-token"); r.status != 200 {
		t.Fatalf("unknown token: %d", r.status)
	}
	if r := e.tokenCall(t, oauthRevokePath, url.Values{"token": {res.tr.RefreshToken}}, "copilot", copilotSecret); r.status != 200 {
		t.Fatalf("token of another client: %d", r.status)
	}
	if code, _ := e.me(t, res.tr.AccessToken); code != 200 {
		t.Fatalf("revoked by another client: %d", code)
	}
	if r := revoke(res.tr.AccessToken); r.status != 200 {
		t.Fatalf("revoke: %d %s", r.status, r.err)
	}
	if code, _ := e.me(t, res.tr.AccessToken); code != 401 {
		t.Fatalf("access token after revocation: %d", code)
	}
	if r := e.refresh(t, res.tr.RefreshToken); r.status != 400 {
		t.Fatalf("refresh after revocation: %d", r.status)
	}
	if ev := e.eventsOf("oauth.revoke"); len(ev) != 1 || ev[0].ClientID != "skopea-acme" {
		t.Fatalf("revoke audit: %+v", ev)
	}
	if r := e.tokenCall(t, oauthRevokePath, url.Values{"token": {"x"}, "client_id": {RelayClientID}}, "", ""); r.status != 200 {
		t.Fatalf("relay revoke: %d", r.status)
	}
}

func TestOAuthDisabledClient(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res := e.link(t, "")
	e.server.cfg.Config.OAuth.Clients[0].Disabled = true
	if code, _ := e.me(t, res.tr.AccessToken); code != 401 {
		t.Fatalf("token of a disabled client: %d", code)
	}
	if r := e.refresh(t, res.tr.RefreshToken); r.status != 401 || r.err != "invalid_client" {
		t.Fatalf("refresh of a disabled client: %d %s", r.status, r.err)
	}
	_, challenge := pkcePair()
	resp, _ := e.b.Get(e.base + oauthAuthorizePath + "?" + skopeaQuery(challenge, "").Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("authorize of a disabled client: %d", resp.StatusCode)
	}
	e.server.cfg.Config.OAuth.Clients[0].Disabled = false
	if code, _ := e.me(t, res.tr.AccessToken); code != 200 {
		t.Fatalf("enabled again: %d", code)
	}
}

func TestOAuthIncrementalConsent(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	first := e.link(t, "dns.read")
	_, challenge := pkcePair()
	if cb, shown := e.authorize(t, skopeaQuery(challenge, "dns.read")); shown || cb.Query().Get("code") == "" {
		t.Fatalf("remembered consent: %v %s", shown, cb)
	}
	forced := skopeaQuery(challenge, "dns.read")
	forced.Set("prompt", "consent")
	if _, shown := e.authorize(t, forced); !shown {
		t.Fatal("prompt=consent without the consent page")
	}
	none := skopeaQuery(challenge, "dns.read dns.write")
	none.Set("prompt", "none")
	if cb, _ := e.authorize(t, none); cb.Query().Get("error") != "consent_required" {
		t.Fatalf("prompt=none with wider scopes: %s", cb)
	}
	wider := e.link(t, "dns.write")
	claims, _ := unverifiedClaims(t, wider.tr.AccessToken)
	firstClaims, _ := unverifiedClaims(t, first.tr.AccessToken)
	if claims["scope"] != "dns.write" || wider.tr.Scope != "dns.write" || claims["gate_grant"] != firstClaims["gate_grant"] {
		t.Fatalf("token of the wider consent: %v", claims)
	}
	if again := e.link(t, "dns.read"); again.tr.Scope != "dns.read" {
		t.Fatalf("token of a remembered consent: %s", again.tr.Scope)
	} else {
		wider = again
	}
	if r := e.refresh(t, wider.tr.RefreshToken); r.status != 200 || r.tr.Scope != "dns.read dns.write" {
		t.Fatalf("refresh carries the merged grant: %d %s", r.status, r.tr.Scope)
	} else {
		wider = r
	}
	if r := e.refresh(t, first.tr.RefreshToken); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("refresh token of before the new consent: %d %s", r.status, r.err)
	}
	if r := e.refresh(t, wider.tr.RefreshToken); r.status != 200 {
		t.Fatalf("grant revoked by a stale token: %d %s", r.status, r.err)
	} else {
		wider = r
	}
	narrow := e.skopeaToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {wider.tr.RefreshToken}, "scope": {"dns.read"}})
	if c, _ := unverifiedClaims(t, narrow.tr.AccessToken); narrow.status != 200 || c["scope"] != "dns.read" {
		t.Fatalf("narrowed refresh: %d %v", narrow.status, c)
	}
	var list uiapi.OAuthGrantList
	if code := getJSON(t, e.b, e.base+"/api/v1/oauth/grants", &list); code != 200 || len(list.Grants) != 1 || strings.Join(list.Grants[0].Scopes, " ") != "dns.read dns.write" {
		t.Fatalf("one grant per client and subject: %+v", list)
	}
}

func TestOAuthPromptAndMaxAge(t *testing.T) {
	e := newOAuthEnv(t, nil)
	_, challenge := pkcePair()
	none := skopeaQuery(challenge, "")
	none.Set("prompt", "none")
	resp, _ := e.b.Get(e.base + oauthAuthorizePath + "?" + none.Encode())
	resp.Body.Close()
	if u, _ := url.Parse(resp.Header.Get("Location")); u == nil || u.Query().Get("error") != "login_required" {
		t.Fatalf("prompt=none without a session: %s", resp.Header.Get("Location"))
	}
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	login := skopeaQuery(challenge, "")
	login.Set("prompt", "login")
	resp, _ = e.b.Get(e.base + oauthAuthorizePath + "?" + login.Encode())
	resp.Body.Close()
	lu, _ := url.Parse(resp.Header.Get("Location"))
	if lu.Path != "/auth/login" || lu.Query().Get("reauth") != "1" || !strings.Contains(lu.Query().Get("return_to"), "gate_reauth=") || strings.Contains(lu.Query().Get("return_to"), "prompt=login") {
		t.Fatalf("prompt=login: %s", lu)
	}
	in := e.startLogin(t, e.b, "?"+lu.RawQuery)
	if !in.ForceAuthn {
		t.Fatal("reauth without ForceAuthn")
	}
	ar := e.post(t, e.b, e.idp.Response(e.assertion(in, "alice@example.com", "DNS-Writers")), in.RelayState)
	resp, _ = e.b.Get(e.base + ar.Header.Get("Location"))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("consent after the sign-in: %d", resp.StatusCode)
	}
	stale := skopeaQuery(challenge, "")
	stale.Set("max_age", "0")
	stale.Set("gate_reauth", "1")
	e.offset = 5 * time.Minute
	if cb, _ := e.authorize(t, stale); cb.Query().Get("error") != "login_required" {
		t.Fatalf("max_age not met after a sign-in: %s", cb)
	}
}

func TestOAuthReauthNotRenewed(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	_, challenge := pkcePair()
	login := skopeaQuery(challenge, "")
	login.Set("prompt", "login")
	e.offset = 10 * time.Minute
	resp, _ := e.b.Get(e.base + oauthAuthorizePath + "?" + login.Encode())
	resp.Body.Close()
	lu, _ := url.Parse(resp.Header.Get("Location"))
	in := e.startLogin(t, e.b, "?"+lu.RawQuery)
	a := e.samlEnvT.assertion(in, "alice@example.com", "DNS-Writers")
	a.AuthnInstant = time.Now().Add(-time.Hour)
	ar := e.post(t, e.b, e.idp.Response(a), in.RelayState)
	resp, _ = e.b.Get(e.base + ar.Header.Get("Location"))
	resp.Body.Close()
	if u, _ := url.Parse(resp.Header.Get("Location")); resp.StatusCode != 302 || u.Query().Get("error") != "login_required" {
		t.Fatalf("sign-in not renewed by the IdP: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestOAuthRevokedGrantNotRecreatedByARememberedCode(t *testing.T) {
	e := newOAuthEnv(t, nil)
	csrf := e.login(t, e.b, "alice@example.com", "DNS-Writers")
	e.link(t, "")
	verifier, challenge := pkcePair()
	cb, shown := e.authorize(t, skopeaQuery(challenge, ""))
	if shown {
		t.Fatal("consent not remembered")
	}
	var list uiapi.OAuthGrantList
	_ = getJSON(t, e.b, e.base+"/api/v1/oauth/grants", &list)
	req, _ := http.NewRequest("DELETE", e.base+"/api/v1/oauth/grants/"+list.Grants[0].ID, nil)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("Origin", e.base)
	if r, err := e.b.Do(req); err != nil || r.StatusCode != 204 {
		t.Fatalf("revoke: %v", err)
	}
	r := e.skopeaToken(t, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}})
	if r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("remembered code after the revocation: %d %s", r.status, r.err)
	}
}

func TestOAuthPublicClientRefusalsAggregated(t *testing.T) {
	e := newOAuthEnv(t, func(c *config.Config) {
		c.OAuth.Clients = append(c.OAuth.Clients, testOAuthClient("spa", func(oc *config.OAuthClient) {
			oc.Type, oc.AuthMethod, oc.RedirectURIs, oc.Scopes = config.OAuthPublic, config.OAuthNone, []string{"https://spa.example/cb"}, []string{scope.DNSRead}
		}))
	})
	for i := 0; i < 20; i++ {
		e.tokenCall(t, oauthTokenPath, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"forged"}, "client_id": {"spa"}}, "", "")
	}
	if n := len(e.eventsOf("oauth.token")); n != 1 {
		t.Fatalf("refusals of a public client: %d events", n)
	}
}

func TestOAuthWriteMaxAge(t *testing.T) {
	e := newOAuthEnv(t, func(c *config.Config) { c.OAuth.Clients[0].WriteMaxAge = config.Duration(time.Hour) })
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res := e.link(t, "dns.read dns.write")
	if r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", res.tr.AccessToken, `{"ttl":300,"records":["192.0.2.1"]}`, nil); r.StatusCode == 403 && reason(t, r) == "reauth_required" {
		t.Fatal("fresh sign-in refused")
	}
	e.offset = 2 * time.Hour
	res = e.refresh(t, res.tr.RefreshToken)
	r := e.do(t, "PUT", "/api/v1/zones/example.com/rrsets/www/A", res.tr.AccessToken, `{"ttl":300,"records":["192.0.2.1"]}`, nil)
	var b errorBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	if r.StatusCode != 403 || b.Reason != "reauth_required" || b.RequiredScope != "dns.write" {
		t.Fatalf("write after write_max_age: %d %+v", r.StatusCode, b)
	}
	if code, _ := e.me(t, res.tr.AccessToken); code != 200 {
		t.Fatalf("read after write_max_age: %d", code)
	}
}

func TestOAuthCopilotStaticClient(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	verifier, challenge := pkcePair()
	q := url.Values{
		"response_type": {"code"}, "client_id": {"copilot"}, "redirect_uri": {copilotRedirect}, "state": {"teams-state"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"dns.read offline_access"},
	}
	cb, shown := e.authorize(t, q)
	if !shown || cb.Host != "teams.microsoft.com" || cb.Query().Get("iss") != e.base {
		t.Fatalf("callback: %s", cb)
	}
	f := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {copilotRedirect}, "code_verifier": {verifier}}
	if r := e.tokenCall(t, oauthTokenPath, f, "copilot", "wrong-secret"); r.status != 401 || r.err != "invalid_client" || !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("wrong secret: %d %s", r.status, r.err)
	}
	res := e.tokenCall(t, oauthTokenPath, f, "copilot", copilotSecret)
	if res.status != 200 || res.tr.RefreshToken == "" {
		t.Fatalf("basic: %d %s", res.status, res.err)
	}
	post := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {res.tr.RefreshToken}, "client_id": {"copilot"}, "client_secret": {copilotSecret}}
	refreshed := e.tokenCall(t, oauthTokenPath, post, "", "")
	if refreshed.status != 200 {
		t.Fatalf("client_secret_post: %d %s", refreshed.status, refreshed.err)
	}
	if r := e.do(t, "GET", "/api/v1/me", refreshed.tr.AccessToken, "", nil); r.StatusCode != 403 || reason(t, r) != "not_delegable" {
		t.Fatalf("API with an MCP-only client: %d", r.StatusCode)
	}
	r := e.do(t, "POST", "/mcp", refreshed.tr.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, map[string]string{"Accept": "application/json, text/event-stream"})
	raw, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(raw), `"list_zones"`) || strings.Contains(string(raw), `"apply_rrset_change"`) || strings.Contains(string(raw), `"explain"`) {
		t.Fatalf("tools/list: %d %s", r.StatusCode, raw)
	}
}

func TestOAuthIdentityStoreGroupsAtRefresh(t *testing.T) {
	e := newOAuthEnv(t, func(c *config.Config) {
		c.UI.SAML.GroupsFromIdentityStore = &config.IdentityStoreGroups{IdentityStoreID: "d-1234567890", Region: "eu-west-1", UserAttribute: "email", UserClaim: "email"}
		c.OAuth.Clients[0].ClaimsMaxAge = config.Duration(time.Hour)
	})
	fg := &fakeGroups{groups: map[string][]string{"alice@example.com": {"DNS-Writers"}}}
	e.server.ui.groups = fg
	e.login(t, e.b, "alice@example.com")
	res := e.link(t, "")
	if code, me := e.me(t, res.tr.AccessToken); code != 200 || me.Email != "alice@example.com" {
		t.Fatalf("email of the grant: %d %+v", code, me)
	}
	e.offset = 30 * time.Minute
	if res = e.refresh(t, res.tr.RefreshToken); res.status != 200 {
		t.Fatalf("refresh within claims_max_age: %d %s", res.status, res.err)
	}
	if code, me := e.me(t, res.tr.AccessToken); code != 200 || me.Email != "alice@example.com" {
		t.Fatalf("email within claims_max_age: %d %+v", code, me)
	}
	e.offset = 2 * time.Hour
	if res = e.refresh(t, res.tr.RefreshToken); res.status != 200 {
		t.Fatalf("refresh with reloaded groups after claims_max_age: %d %s", res.status, res.err)
	}
	if len(fg.asked) != 3 {
		t.Fatalf("identity store lookups: %v", fg.asked)
	}
	if code, me := e.me(t, res.tr.AccessToken); code != 200 || me.Email != "" || me.Subject != "identity-center:alice@example.com" {
		t.Fatalf("email of claims older than claims_max_age: %d %+v", code, me)
	}
	fg.groups["alice@example.com"] = []string{"Other"}
	if r := e.refresh(t, res.tr.RefreshToken); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("refresh after the removal from the group: %d %s", r.status, r.err)
	}

	fg.groups["alice@example.com"] = []string{"DNS-Writers"}
	e.offset = 0
	res = e.link(t, "")
	delete(fg.groups, "alice@example.com")
	if r := e.refresh(t, res.tr.RefreshToken); r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("refresh of a user deleted from the identity store: %d %s", r.status, r.err)
	}
}

func TestOAuthGrantsAPI(t *testing.T) {
	e := newOAuthEnv(t, func(c *config.Config) {
		c.Roles["oauth-admin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"gate.oauth.manage", "ui.read"}}}}
		c.Bindings = append(c.Bindings, config.Binding{Role: "oauth-admin", Team: "sec", Subjects: []config.Subject{{Issuer: "identity-center", Claims: map[string]config.StringList{"groups": {"OAuth-Admins"}}}}})
	})
	csrf := e.login(t, e.b, "alice@example.com", "DNS-Writers")
	res := e.link(t, "")
	var list uiapi.OAuthGrantList
	if code := getJSON(t, e.b, e.base+"/api/v1/oauth/grants", &list); code != 200 || len(list.Grants) != 1 || list.Manage || list.Grants[0].ClientName != "Skopea — Acme" {
		t.Fatalf("own grants: %d %+v", code, list)
	}
	if code := getJSON(t, e.b, e.base+"/api/v1/oauth/grants?client=skopea-acme", &list); code != 403 {
		t.Fatalf("listing by client without gate.oauth.manage: %d", code)
	}
	del := func(b *http.Client, csrf, path string) int {
		req, _ := http.NewRequest("DELETE", e.base+path, nil)
		req.Header.Set(csrfHeader, csrf)
		req.Header.Set("Origin", e.base)
		r, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	admin := browser()
	adminCSRF := e.login(t, admin, "bob@example.com", "OAuth-Admins")
	if code := getJSON(t, admin, e.base+"/api/v1/oauth/grants?subject=identity-center:alice@example.com", &list); code != 200 || len(list.Grants) != 1 || !list.Manage {
		t.Fatalf("admin listing: %d %+v", code, list)
	}
	if code := del(admin, adminCSRF, "/api/v1/oauth/grants"); code != 403 {
		t.Fatalf("bulk revoke without filter: %d", code)
	}
	if code := del(e.b, csrf, "/api/v1/oauth/grants?client=skopea-acme"); code != 403 {
		t.Fatalf("bulk revoke by a user: %d", code)
	}
	if code := del(admin, adminCSRF, "/api/v1/oauth/grants?client=skopea-acme"); code != 200 {
		t.Fatalf("bulk revoke: %d", code)
	}
	if code, _ := e.me(t, res.tr.AccessToken); code != 401 {
		t.Fatalf("token after the admin revocation: %d", code)
	}

	res = e.link(t, "")
	_ = getJSON(t, e.b, e.base+"/api/v1/oauth/grants", &list)
	id := ""
	for _, g := range list.Grants {
		if g.Status == uiapi.OAuthGrantActive {
			id = g.ID
		}
	}
	other := browser()
	otherCSRF := e.login(t, other, "carol@example.com", "DNS-Writers")
	if code := del(other, otherCSRF, "/api/v1/oauth/grants/"+id); code != 404 {
		t.Fatalf("revoking the grant of another user: %d", code)
	}
	if code := del(e.b, "", "/api/v1/oauth/grants/"+id); code != 403 {
		t.Fatalf("revoke without CSRF: %d", code)
	}
	if code := del(e.b, csrf, "/api/v1/oauth/grants/"+id); code != 204 {
		t.Fatalf("revoke own grant: %d", code)
	}
	if code, _ := e.me(t, res.tr.AccessToken); code != 401 {
		t.Fatalf("token after the user revocation: %d", code)
	}
	var reasons []string
	for _, ev := range e.eventsOf("oauth.revoke") {
		if ev.Decision == "allow" {
			reasons = append(reasons, ev.Reason+":"+ev.Extra["client_id"].(string))
		}
	}
	if strings.Join(reasons, " ") != "admin:skopea-acme user:skopea-acme" {
		t.Fatalf("revoke audit: %v", reasons)
	}
}

func TestOAuthRelayUnchanged(t *testing.T) {
	e := newOAuthEnv(t, nil)
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	verifier, challenge := pkcePair()
	q := url.Values{
		"response_type": {"code"}, "client_id": {RelayClientID}, "redirect_uri": {"http://127.0.0.1:41234"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"openid offline_access"},
	}
	cb, _ := e.authorize(t, q)
	res := e.tokenCall(t, oauthTokenPath, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "client_id": {RelayClientID},
		"redirect_uri": {"http://127.0.0.1:41234"}, "code_verifier": {verifier}}, "", "")
	if res.status != 200 || res.tr.Scope != "openid offline_access" {
		t.Fatalf("relay: %d %s", res.status, res.err)
	}
	claims, typ := unverifiedClaims(t, res.tr.AccessToken)
	if typ != "JWT" || claims["client_id"] != nil || claims["scope"] != nil {
		t.Fatalf("relay token: %s %v", typ, claims)
	}
	if code, me := e.me(t, res.tr.AccessToken); code != 200 || me.Client != nil {
		t.Fatalf("relay subject: %d %+v", code, me)
	}
	if ev := e.eventsOf("oauth.token"); len(ev) != 0 {
		t.Fatalf("relay audited as a declared client: %+v", ev)
	}
}

func TestWriteMaxAgeCoversTransfers(t *testing.T) {
	e := newOAuthEnv(t, nil)
	old := float64(e.clock().Add(-2 * time.Hour).Unix())
	subj := &identity.Subject{Claims: map[string]any{"auth_time": old}, Client: &identity.Client{ID: "skopea-acme", WriteMaxAge: time.Hour}}
	for _, required := range [][]string{{scope.DNSWrite}, {scope.DNSTransfer}, {scope.DNSAdopt}} {
		if de := e.server.delegatedWriteAge(subj, required); de == nil || de.reason != "reauth_required" || de.required != required[0] {
			t.Errorf("%v: %+v", required, de)
		}
	}
	for _, required := range [][]string{{scope.DNSRead}, {scope.DNSPlan, scope.DNSWrite}} {
		if de := e.server.delegatedWriteAge(subj, required); de != nil {
			t.Errorf("%v: %+v", required, de)
		}
	}
}

func TestOAuthPublicClientAlwaysConsents(t *testing.T) {
	e := newOAuthEnv(t, func(c *config.Config) {
		c.OAuth.Clients = append(c.OAuth.Clients, testOAuthClient("spa", func(oc *config.OAuthClient) {
			oc.Type, oc.AuthMethod, oc.RedirectURIs, oc.Scopes = config.OAuthPublic, config.OAuthNone, []string{"https://spa.example/cb"}, []string{scope.DNSRead}
			oc.DefaultScopes = []string{scope.DNSRead}
		}))
	})
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	verifier, challenge := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {"spa"}, "redirect_uri": {"https://spa.example/cb"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	cb, shown := e.authorize(t, q)
	if !shown {
		t.Fatal("first consent of a public client")
	}
	if r := e.tokenCall(t, oauthTokenPath, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "client_id": {"spa"},
		"redirect_uri": {"https://spa.example/cb"}, "code_verifier": {verifier}}, "", ""); r.status != 200 {
		t.Fatalf("public client exchange: %d %s", r.status, r.err)
	}
	if _, shown := e.authorize(t, q); !shown {
		t.Fatal("consent of a public client remembered")
	}
	none := url.Values{}
	for k, v := range q {
		none[k] = v
	}
	none.Set("prompt", "none")
	if cb, _ := e.authorize(t, none); cb.Query().Get("error") != "consent_required" {
		t.Fatalf("prompt=none for a public client: %s", cb)
	}
}

func TestOAuthBasicSecretRawOrEncoded(t *testing.T) {
	secret := "copilot+secret%zz/0123456789abcdefghijklm"
	e := newOAuthEnv(t, func(c *config.Config) { c.OAuth.Clients[1].Secret = secret })
	call := func(header string) int {
		req, _ := http.NewRequest("POST", e.base+oauthTokenPath, strings.NewReader("grant_type=refresh_token&refresh_token=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(header)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := call("copilot:" + secret); code != 400 {
		t.Fatalf("raw secret: %d", code)
	}
	if code := call("copilot:" + url.QueryEscape(secret)); code != 400 {
		t.Fatalf("encoded secret: %d", code)
	}
	if code := call("copilot:wrong" + secret); code != 401 {
		t.Fatalf("wrong secret: %d", code)
	}
}

func TestSAMLSessionBaseGroupsOnlyWithOAuthClients(t *testing.T) {
	for _, withClients := range []bool{false, true} {
		e := newSAMLEnv(t, func(c *config.Config) {
			c.UI.SAML.GroupsFromIdentityStore = &config.IdentityStoreGroups{IdentityStoreID: "d-1234567890", Region: "eu-west-1", UserAttribute: "email", UserClaim: "email"}
			if withClients {
				c.OAuth.Clients = []config.OAuthClient{testOAuthClient("x", func(oc *config.OAuthClient) { oc.Scopes = []string{scope.DNSRead} })}
			}
		})
		e.server.ui.groups = &fakeGroups{groups: map[string][]string{"alice@example.com": {"DNS-Writers"}}}
		b := browser()
		e.login(t, b, "alice@example.com", "Assertion-Group")
		u, _ := url.Parse(e.base)
		var sess session
		for _, c := range b.Jar.Cookies(u) {
			if c.Name == e.server.ui.cookies.session {
				if err := e.server.ui.sealer.open(c.Name, c.Value, &sess); err != nil {
					t.Fatal(err)
				}
			}
		}
		if sess.StoreGroups != withClients || (len(sess.BaseGroups) > 0) != withClients {
			t.Fatalf("with clients %v: %+v", withClients, sess)
		}
	}
}

func TestOAuthRememberedCodeOutsideTheGrant(t *testing.T) {
	e := newOAuthEnv(t, nil)
	csrf := e.login(t, e.b, "alice@example.com", "DNS-Writers")
	e.link(t, "dns.read dns.write")
	verifier, challenge := pkcePair()
	cb, shown := e.authorize(t, skopeaQuery(challenge, "dns.write"))
	if shown {
		t.Fatal("consent not remembered")
	}
	var list uiapi.OAuthGrantList
	_ = getJSON(t, e.b, e.base+"/api/v1/oauth/grants", &list)
	req, _ := http.NewRequest("DELETE", e.base+"/api/v1/oauth/grants/"+list.Grants[0].ID, nil)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("Origin", e.base)
	if r, err := e.b.Do(req); err != nil || r.StatusCode != 204 {
		t.Fatalf("revoke: %v", err)
	}
	e.link(t, "dns.read")
	r := e.skopeaToken(t, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {skopeaRedirect}, "code_verifier": {verifier}})
	if r.status != 400 || r.err != "invalid_grant" {
		t.Fatalf("remembered code wider than the new grant: %d %s", r.status, r.err)
	}
}

type failingOAuth struct {
	store.OAuthStore
	fail atomic.Bool
}

func (f *failingOAuth) UpdateOAuthGrant(ctx context.Context, g store.OAuthGrant) error {
	if f.fail.Load() {
		return errors.New("store down")
	}
	return f.OAuthStore.UpdateOAuthGrant(ctx, g)
}

func TestOAuthReuseWhenTheRevocationFails(t *testing.T) {
	e := newOAuthEnv(t, nil)
	fs := &failingOAuth{OAuthStore: e.server.cfg.OAuth}
	e.server.cfg.OAuth = fs
	e.login(t, e.b, "alice@example.com", "DNS-Writers")
	first := e.link(t, "")
	if r := e.refresh(t, first.tr.RefreshToken); r.status != 200 {
		t.Fatalf("refresh: %d", r.status)
	}
	e.offset = time.Minute
	fs.fail.Store(true)
	if r := e.refresh(t, first.tr.RefreshToken); r.status != 503 {
		t.Fatalf("reuse with the store down: %d %s", r.status, r.err)
	}
	if ev := e.eventsOf("oauth.refresh_reuse"); len(ev) != 1 || ev[0].Decision != "error" {
		t.Fatalf("reuse audit: %+v", ev)
	}
	fs.fail.Store(false)
	if r := e.refresh(t, first.tr.RefreshToken); r.status != 400 {
		t.Fatalf("reuse once the store is back: %d", r.status)
	}
}
