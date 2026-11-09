package server

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
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identitystore"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/samltest"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

const samlEntityID = "dns-gate-test"

type samlEnvT struct {
	*env
	idp  *samltest.IdP
	base string
}

func signingKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newSAMLEnv(t *testing.T, tweak func(*config.Config)) *samlEnvT {
	t.Helper()
	idp := samltest.New("https://idp.example.com/saml", "https://idp.example.com/sso")
	key := signingKeyPEM(t)
	var base string
	e := newEnvWith(t, func(c *config.Config) {
		base = strings.TrimSuffix(c.UI.RedirectURL, "/auth/callback")
		c.UI.Issuer, c.UI.ClientID, c.UI.RedirectURL = "", "", ""
		c.UI.SAML = &config.UISAML{
			Issuer: "identity-center", EntityID: samlEntityID, ACSURL: base + config.SAMLACSPath,
			IDPMetadata: idp.Metadata(), NameIDFormat: "email",
		}
		c.Issuers = append(c.Issuers, config.Issuer{
			Name: "gate", Self: true, Issuer: base, Audiences: []string{base}, Category: "human",
			Algorithms: config.DefaultAlgorithms, ClockSkew: config.Duration(time.Minute), TokenTTL: config.Duration(time.Hour), SigningKey: key,
		})
		c.Roles["padmin"] = config.Role{Rules: []config.Rule{{Zones: []string{"*"}, Actions: []string{"policy.read", "policy.propose", "policy.approve"}}}}
		c.Bindings = append(c.Bindings,
			config.Binding{Role: "writer", Team: "web", Subjects: []config.Subject{{Issuer: "identity-center", Claims: map[string]config.StringList{"groups": {"DNS-Writers"}}}}},
			config.Binding{Role: "padmin", Team: "dns", Subjects: []config.Subject{{Issuer: "identity-center", Claims: map[string]config.StringList{"groups": {"DNS-Admins"}}}}},
		)
		requireApproval := false
		c.Policy = config.Policy{
			Editable: true, RequireApproval: &requireApproval, EditMaxAge: config.Duration(15 * time.Minute),
			Bounds: config.Bounds{Zones: []string{"example.com"}, Actions: []string{policy.ActionDNSRead, policy.ActionRecordWrite, policy.ActionUIRead}},
		}
		if tweak != nil {
			tweak(c)
		}
	})
	e.server.cfg.Authn.SetClock(func() time.Time { return e.clock() })
	return &samlEnvT{env: e, idp: idp, base: base}
}

// browser is a cookie-keeping client that does not follow redirects.
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// startLogin begins a SAML login and returns the request the IdP received.
func (e *samlEnvT) startLogin(t *testing.T, b *http.Client, query string) *samltest.Request {
	t.Helper()
	resp, err := b.Get(e.base + "/auth/login" + query)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, e.idp.SSOURL+"?") {
		t.Fatalf("login redirect: %d %s", resp.StatusCode, loc)
	}
	in, err := samltest.ParseRedirect(loc)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func (e *samlEnvT) assertion(in *samltest.Request, nameID string, groups ...string) samltest.Assertion {
	return samltest.Assertion{
		RequestID: in.ID, ACSURL: e.base + config.SAMLACSPath, Audience: samlEntityID, NameID: nameID,
		Attributes: map[string][]string{"email": {nameID}, "name": {"Alice Doe"}, "groups": groups},
	}
}

func (e *samlEnvT) post(t *testing.T, b *http.Client, samlResponse, relay string) *http.Response {
	t.Helper()
	resp, err := b.PostForm(e.base+config.SAMLACSPath, url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relay}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// login signs a browser in and returns its CSRF token.
func (e *samlEnvT) login(t *testing.T, b *http.Client, nameID string, groups ...string) string {
	t.Helper()
	in := e.startLogin(t, b, "")
	resp := e.post(t, b, e.idp.Response(e.assertion(in, nameID, groups...)), in.RelayState)
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("acs: %d %s", resp.StatusCode, body)
	}
	return csrfOf(b, e.base)
}

func csrfOf(b *http.Client, base string) string {
	u, _ := url.Parse(base)
	for _, c := range b.Jar.Cookies(u) {
		if c.Name == csrfCookie {
			return c.Value
		}
	}
	return ""
}

func getJSON(t *testing.T, b *http.Client, u string, out any) int {
	t.Helper()
	resp, err := b.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestSAMLLogin(t *testing.T) {
	e := newSAMLEnv(t, nil)

	r := e.do(t, "GET", config.SAMLMetadataPath, "", "", nil)
	md, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(md), `entityID="`+samlEntityID+`"`) || !strings.Contains(string(md), e.base+config.SAMLACSPath) {
		t.Fatalf("metadata: %d %s", r.StatusCode, md)
	}
	if r := e.do(t, "GET", "/auth/callback", "", "", nil); r.StatusCode != 404 {
		t.Fatalf("OIDC callback in SAML mode: %d", r.StatusCode)
	}

	b := browser()
	in := e.startLogin(t, b, "?return_to=/ui/zones/example.com")
	if in.ACSURL != e.base+config.SAMLACSPath || in.Issuer != samlEntityID || in.ForceAuthn {
		t.Fatalf("authn request: %+v", in)
	}
	resp := e.post(t, b, e.idp.Response(e.assertion(in, "alice@example.com", "DNS-Writers", "Other")), in.RelayState)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/ui/zones/example.com" {
		t.Fatalf("acs: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var me uiapi.Me
	if code := getJSON(t, b, e.base+"/api/v1/me", &me); code != 200 || me.Subject != "identity-center:alice@example.com" || me.Name != "Alice Doe" || me.Category != "human" || len(me.Roles) != 1 || me.Roles[0] != "writer" {
		t.Fatalf("me: %d %+v", code, me)
	}

	replay := e.idp.Response(e.assertion(in, "alice@example.com", "DNS-Writers"))
	if r := e.post(t, browser(), replay, in.RelayState); r.StatusCode != 400 || reason(t, r) != "login_state" {
		t.Fatalf("response without the login cookie: %d", r.StatusCode)
	}

	unsolicited := e.assertion(&samltest.Request{}, "alice@example.com", "DNS-Writers")
	if r := e.post(t, browser(), e.idp.Response(unsolicited), ""); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/auth/login" {
		t.Fatalf("IdP-initiated login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	victim := browser()
	vin := e.startLogin(t, victim, "")
	if r := e.post(t, victim, replay, vin.RelayState); r.StatusCode != 401 {
		t.Fatalf("response of another login accepted: %d", r.StatusCode)
	}
	vin = e.startLogin(t, victim, "")
	if r := e.post(t, victim, e.idp.Response(e.assertion(vin, "bob@example.com", "DNS-Writers")), "other-relay"); r.StatusCode != 400 {
		t.Fatalf("relay state mismatch: %d", r.StatusCode)
	}
	vin = e.startLogin(t, victim, "")
	bad := e.assertion(vin, "bob@example.com", "DNS-Writers")
	bad.Audience = "another-app"
	if r := e.post(t, victim, e.idp.Response(bad), vin.RelayState); r.StatusCode != 401 {
		t.Fatalf("wrong audience: %d", r.StatusCode)
	}
	vin = e.startLogin(t, victim, "")
	if r := e.post(t, victim, e.idp.Response(e.assertion(vin, "mallory@example.com", "Nobody")), vin.RelayState); r.StatusCode != 403 || reason(t, r) != "no_binding" {
		t.Fatalf("unbound user: %d", r.StatusCode)
	}

	reauth := e.startLogin(t, b, "?reauth=1")
	if !reauth.ForceAuthn {
		t.Fatal("reauth without ForceAuthn")
	}
}

type fakeGroups struct {
	groups map[string][]string
	err    error
	asked  []string
}

func (f *fakeGroups) Groups(_ context.Context, user string) ([]string, error) {
	f.asked = append(f.asked, user)
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.groups[user]
	if !ok {
		return nil, identitystore.ErrUserNotFound
	}
	return g, nil
}

func TestSAMLGroupsFromIdentityStore(t *testing.T) {
	e := newSAMLEnv(t, func(c *config.Config) {
		c.UI.SAML.GroupsFromIdentityStore = &config.IdentityStoreGroups{IdentityStoreID: "d-1234567890", Region: "eu-west-1", UserAttribute: "email", UserClaim: "email"}
	})
	fg := &fakeGroups{groups: map[string][]string{"alice@example.com": {"DNS-Writers"}}}
	e.server.ui.groups = fg

	b := browser()
	e.login(t, b, "alice@example.com")
	var me uiapi.Me
	if code := getJSON(t, b, e.base+"/api/v1/me", &me); code != 200 || len(me.Roles) != 1 || me.Roles[0] != "writer" {
		t.Fatalf("me: %d %+v", code, me)
	}
	if len(fg.asked) != 1 || fg.asked[0] != "alice@example.com" {
		t.Fatalf("lookup: %v", fg.asked)
	}
	b2 := browser()
	in := e.startLogin(t, b2, "")
	if r := e.post(t, b2, e.idp.Response(e.assertion(in, "bob@example.com", "DNS-Writers")), in.RelayState); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("unknown store user with assertion groups: %d", r.StatusCode)
	}
	fg.err = errors.New("throttled")
	in = e.startLogin(t, b2, "")
	if r := e.post(t, b2, e.idp.Response(e.assertion(in, "alice@example.com")), in.RelayState); r.StatusCode != 502 || reason(t, r) != "groups_unavailable" {
		t.Fatalf("lookup failure: %d", r.StatusCode)
	}
}

func issueToken(t *testing.T, e *samlEnvT, b *http.Client, csrf, origin string) (int, issuedToken, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.base+"/api/v1/tokens", nil)
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var tok issuedToken
	_ = json.Unmarshal(raw, &tok)
	var eb errorBody
	_ = json.Unmarshal(raw, &eb)
	return resp.StatusCode, tok, eb.Reason
}

func TestGateTokens(t *testing.T) {
	e := newSAMLEnv(t, nil)
	b := browser()
	csrf := e.login(t, b, "alice@example.com", "DNS-Writers", "DNS-Admins")

	if code, _, _ := issueToken(t, e, b, "", e.base); code != 403 {
		t.Fatalf("without CSRF: %d", code)
	}
	if code, _, _ := issueToken(t, e, b, csrf, "https://evil.example.net"); code != 403 {
		t.Fatalf("cross origin: %d", code)
	}
	code, tok, _ := issueToken(t, e, b, csrf, e.base)
	if code != 200 || tok.AccessToken == "" || tok.Issuer != e.base || tok.ExpiresIn <= 0 || tok.ExpiresIn > 3600 {
		t.Fatalf("issue: %d %+v", code, tok)
	}

	var set jose.JSONWebKeySet
	r := e.do(t, "GET", jwksPath, "", "", nil)
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil || len(set.Keys) != 1 || !set.Keys[0].IsPublic() || set.Keys[0].Algorithm != "ES256" {
		t.Fatalf("jwks: %v %+v", err, set)
	}
	parsed, err := jwt.ParseSigned(tok.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var std jwt.Claims
	claims := map[string]any{}
	if err := parsed.Claims(set.Keys[0].Key, &std, &claims); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if std.Issuer != e.base || !std.Audience.Contains(e.base) || std.Subject != "alice@example.com" || claims["gate_iss"] != "identity-center" || claims["auth_time"] == nil {
		t.Fatalf("claims: %+v %v", std, claims)
	}

	var me uiapi.Me
	r = e.do(t, "GET", "/api/v1/me", tok.AccessToken, "", nil)
	_ = json.NewDecoder(r.Body).Decode(&me)
	if r.StatusCode != 200 || me.Subject != "identity-center:alice@example.com" || me.Category != "human" || len(me.Roles) != 2 {
		t.Fatalf("bearer gate token: %d %+v", r.StatusCode, me)
	}
	if r := e.do(t, "POST", "/api/v1/tokens", tok.AccessToken, "", nil); r.StatusCode != 403 || reason(t, r) != "session_required" {
		t.Fatalf("token from a token: %d", r.StatusCode)
	}
	if r, _ := propose(t, e.env, tok.AccessToken, "", managedDoc("*.staging")); r.StatusCode != 201 {
		t.Fatalf("step-up with a fresh gate token: %d %s", r.StatusCode, r.Header.Get("X-Test-Reason"))
	}
	e.offset = 20 * time.Minute
	if r, _ := propose(t, e.env, tok.AccessToken, "", managedDoc("*.other")); r.StatusCode != 403 || r.Header.Get("X-Test-Reason") != "reauth_required" {
		t.Fatalf("step-up with an old authentication: %d", r.StatusCode)
	}
	e.offset = 2 * time.Hour
	if r := e.do(t, "GET", "/api/v1/me", tok.AccessToken, "", nil); r.StatusCode != 401 {
		t.Fatalf("expired gate token: %d", r.StatusCode)
	}
	e.offset = 0

	other := signingKeyPEM(t)
	k, _ := config.ParseTokenSigningKey(other)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k, KeyID: set.Keys[0].KeyID}}, nil)
	raw, _ := jwt.Signed(signer).Claims(map[string]any{"iss": e.base, "aud": e.base, "sub": "alice@example.com", "gate_iss": "identity-center", "groups": []string{"DNS-Admins"}, "exp": time.Now().Add(time.Hour).Unix()}).Serialize()
	if r := e.do(t, "GET", "/api/v1/me", raw, "", nil); r.StatusCode != 401 {
		t.Fatalf("forged gate token: %d", r.StatusCode)
	}

	found := false
	for _, ev := range e.audit.events {
		if ev.Action == "token.issue" && ev.Subject == "identity-center:alice@example.com" && ev.Extra["via"] == "api" && ev.Extra["jti"] != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("token issuance not audited")
	}
}

func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

var hiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

func consentForm(t *testing.T, html string) url.Values {
	t.Helper()
	v := url.Values{}
	for _, m := range hiddenRe.FindAllStringSubmatch(html, -1) {
		v.Set(m[1], strings.ReplaceAll(strings.ReplaceAll(m[2], "&amp;", "&"), "&#43;", "+"))
	}
	if v.Get("csrf") == "" {
		t.Fatalf("no consent form:\n%s", html)
	}
	return v
}

func TestGateAuthorizationServer(t *testing.T) {
	e := newSAMLEnv(t, nil)
	var meta map[string]any
	if code := getJSON(t, http.DefaultClient, e.base+oidcConfigPath, &meta); code != 200 || meta["issuer"] != e.base || meta["token_endpoint"] != e.base+oauthTokenPath {
		t.Fatalf("discovery: %d %v", code, meta)
	}

	verifier, challenge := pkcePair()
	redirect := "http://localhost:41234"
	q := url.Values{
		"response_type": {"code"}, "client_id": {RelayClientID}, "redirect_uri": {redirect},
		"state": {"st-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"openid offline_access"},
	}
	authorize := e.base + oauthAuthorizePath + "?" + q.Encode()

	b := browser()
	resp, _ := b.Get(authorize)
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, "/auth/login?") {
		t.Fatalf("anonymous authorize: %d %s", resp.StatusCode, loc)
	}
	lu, _ := url.Parse(loc)
	if next := safeNext(lu.Query().Get("return_to")); !strings.HasPrefix(next, oauthAuthorizePath+"?") {
		t.Fatalf("return_to not kept: %s", next)
	}
	in := e.startLogin(t, b, "?"+lu.RawQuery)
	ar := e.post(t, b, e.idp.Response(e.assertion(in, "alice@example.com", "DNS-Writers")), in.RelayState)
	if ar.StatusCode != http.StatusSeeOther || !strings.HasPrefix(ar.Header.Get("Location"), oauthAuthorizePath+"?") {
		t.Fatalf("back to authorize: %d %s", ar.StatusCode, ar.Header.Get("Location"))
	}

	resp, _ = b.Get(e.base + ar.Header.Get("Location"))
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "http://localhost:*") {
		t.Fatalf("consent: %d %s", resp.StatusCode, page)
	}
	form := consentForm(t, string(page))
	submit := func(v url.Values, origin string) *http.Response {
		req, _ := http.NewRequest("POST", e.base+oauthAuthorizePath, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		r, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r
	}
	noCSRF := url.Values{}
	for k, v := range form {
		noCSRF[k] = v
	}
	noCSRF.Set("csrf", "forged")
	noCSRF.Set("decision", "allow")
	if r := submit(noCSRF, e.base); r.StatusCode != 403 {
		t.Fatalf("consent without CSRF: %d", r.StatusCode)
	}
	form.Set("decision", "allow")
	if r := submit(form, "https://evil.example.net"); r.StatusCode != 403 {
		t.Fatalf("cross-origin consent: %d", r.StatusCode)
	}
	deny := url.Values{}
	for k, v := range form {
		deny[k] = v
	}
	deny.Set("decision", "deny")
	if r := submit(deny, e.base); !strings.Contains(r.Header.Get("Location"), "error=access_denied") {
		t.Fatalf("deny: %s", r.Header.Get("Location"))
	}
	r := submit(form, e.base)
	cb, _ := url.Parse(r.Header.Get("Location"))
	code := cb.Query().Get("code")
	if r.StatusCode != 302 || cb.Host != "localhost:41234" || cb.Query().Get("state") != "st-1" || code == "" {
		t.Fatalf("code redirect: %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	exchange := func(v url.Values) (int, tokenResponse, string) {
		resp, err := http.PostForm(e.base+oauthTokenPath, v)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var tr tokenResponse
		_ = json.Unmarshal(raw, &tr)
		var oe oauthError
		_ = json.Unmarshal(raw, &oe)
		return resp.StatusCode, tr, oe.Error
	}
	base := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {RelayClientID}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	wrongVerifier := url.Values{}
	for k, v := range base {
		wrongVerifier[k] = v
	}
	otherVerifier, _ := pkcePair()
	wrongVerifier.Set("code_verifier", otherVerifier)
	if c, _, why := exchange(wrongVerifier); c != 400 || why != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %s", c, why)
	}
	wrongRedirect := url.Values{}
	for k, v := range base {
		wrongRedirect[k] = v
	}
	wrongRedirect.Set("redirect_uri", "http://localhost:9999")
	if c, _, _ := exchange(wrongRedirect); c != 400 {
		t.Fatalf("wrong redirect: %d", c)
	}
	c, tr, why := exchange(base)
	if c != 200 || tr.AccessToken == "" || tr.RefreshToken == "" || tr.TokenType != "Bearer" {
		t.Fatalf("exchange: %d %s %+v", c, why, tr)
	}
	var me uiapi.Me
	rr := e.do(t, "GET", "/api/v1/me", tr.AccessToken, "", nil)
	_ = json.NewDecoder(rr.Body).Decode(&me)
	if rr.StatusCode != 200 || me.Subject != "identity-center:alice@example.com" {
		t.Fatalf("relay token: %d %+v", rr.StatusCode, me)
	}
	c, tr2, _ := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}, "client_id": {RelayClientID}})
	if c != 200 || tr2.AccessToken == "" || tr2.AccessToken == tr.AccessToken {
		t.Fatalf("refresh: %d %+v", c, tr2)
	}
	if c, _, _ := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {code}, "client_id": {RelayClientID}}); c != 400 {
		t.Fatalf("code used as refresh token: %d", c)
	}
	e.offset = 3 * time.Minute
	if c, _, _ := exchange(base); c != 400 {
		t.Fatalf("expired code: %d", c)
	}
	e.offset = 2 * time.Hour
	if c, _, _ := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}, "client_id": {RelayClientID}}); c != 400 {
		t.Fatalf("refresh after the session: %d", c)
	}
	e.offset = 0

	evil := url.Values{}
	for k, v := range q {
		evil[k] = v
	}
	evil.Set("redirect_uri", "https://evil.example.net/cb")
	resp, _ = b.Get(e.base + oauthAuthorizePath + "?" + evil.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("foreign redirect URI: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	noPKCE := url.Values{}
	for k, v := range q {
		noPKCE[k] = v
	}
	noPKCE.Del("code_challenge")
	resp, _ = b.Get(e.base + oauthAuthorizePath + "?" + noPKCE.Encode())
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=invalid_request") {
		t.Fatalf("without PKCE: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSAMLConnectInfo(t *testing.T) {
	e := newSAMLEnv(t, func(c *config.Config) {
		c.MCP = config.MCP{Enabled: true, PlanTTL: config.Duration(10 * time.Minute), RequestsPerMinute: 600}
	})
	b := browser()
	e.login(t, b, "alice@example.com", "DNS-Writers")
	var ci uiapi.Connect
	if code := getJSON(t, b, e.base+"/api/v1/connect", &ci); code != 200 || ci.Issuer == nil || ci.Issuer.Kind != "saml" || ci.Issuer.URL != e.base || ci.ClientID != RelayClientID || ci.TokensURL != e.base+"/api/v1/tokens" || ci.ClaudeDesktopExtensionURL == "" {
		t.Fatalf("connect: %d %+v", code, ci)
	}
	var rm map[string]any
	if code := getJSON(t, b, e.base+resourceMetaPath, &rm); code != 200 || rm["authorization_servers"].([]any)[0] != e.base {
		t.Fatalf("resource metadata: %v", rm)
	}
}

func TestSAMLEmail(t *testing.T) {
	e := newSAMLEnv(t, func(c *config.Config) {
		c.UI.SAML.Attributes = map[string]string{"name_id_format": "nif"}
	})
	signIn := func(nameID, format string, attrs map[string][]string) (*http.Client, map[string]any) {
		t.Helper()
		b := browser()
		in := e.startLogin(t, b, "")
		a := e.assertion(in, nameID, "DNS-Writers")
		a.NameIDFormat = format
		for k, v := range attrs {
			a.Attributes[k] = v
		}
		if attrs != nil && attrs["email"] == nil {
			delete(a.Attributes, "email")
		}
		if r := e.post(t, b, e.idp.Response(a), in.RelayState); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("acs: %d", r.StatusCode)
		}
		var me map[string]any
		if code := getJSON(t, b, e.base+"/api/v1/me", &me); code != 200 {
			t.Fatalf("me: %d", code)
		}
		return b, me
	}
	persistent := "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	b, me := signIn("alice", persistent, map[string][]string{"email": {"alice@example.com"}})
	if me["email"] != "alice@example.com" {
		t.Fatalf("email attribute: %v", me)
	}
	_, tok, _ := issueToken(t, e, b, csrfOf(b, e.base), e.base)
	r := e.do(t, "GET", "/api/v1/me", tok.AccessToken, "", nil)
	var viaToken uiapi.Me
	_ = json.NewDecoder(r.Body).Decode(&viaToken)
	if r.StatusCode != 200 || viaToken.Email != "alice@example.com" {
		t.Fatalf("gate token: %d %+v", r.StatusCode, viaToken)
	}

	if _, me = signIn("bob@example.com", "", map[string][]string{}); me["email"] != "bob@example.com" {
		t.Fatalf("emailAddress NameID: %v", me)
	}
	if _, me = signIn("bob@example.com", persistent, map[string][]string{}); me["email"] != nil {
		t.Fatalf("persistent NameID taken for an email: %v", me)
	}
	if _, me = signIn("bob@example.com", persistent, map[string][]string{"nif": {"email"}}); me["email"] != nil {
		t.Fatalf("NameID format forged by an attribute: %v", me)
	}
	if _, me = signIn("bob", "", map[string][]string{}); me["email"] != nil {
		t.Fatalf("NameID that is not an address: %v", me)
	}
}
