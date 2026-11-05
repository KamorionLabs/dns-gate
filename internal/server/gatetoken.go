package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
)

// Endpoints of the gate token issuer. The authorization server is a
// stateless OAuth 2.0 authorization code flow with PKCE for native clients
// on a loopback redirect (RFC 8252), such as the Claude Desktop extension:
// codes and refresh tokens are sealed with the session key.
const (
	jwksPath           = "/.well-known/jwks.json"
	oidcConfigPath     = "/.well-known/openid-configuration"
	oauthMetadataPath  = "/.well-known/oauth-authorization-server"
	oauthAuthorizePath = "/oauth/authorize"
	oauthTokenPath     = "/oauth/token"

	// RelayClientID is the public client id of the Claude Desktop extension
	// (and of any native client) at the gate authorization server.
	RelayClientID = "dns-gate-relay"

	oauthCodeTTL     = 2 * time.Minute
	sealOAuthCode    = "dns-gate-oauth-code"
	sealOAuthRefresh = "dns-gate-oauth-refresh"
)

var pkceVerifierRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// oauthGrant is the sealed content of an authorization code or a refresh
// token: the session it was granted from.
type oauthGrant struct {
	Issuer    string         `json:"iss"`
	Claims    map[string]any `json:"c"`
	AuthTime  int64          `json:"at,omitempty"`
	AMR       []string       `json:"amr,omitempty"`
	Session   int64          `json:"sx"`
	Client    string         `json:"cid"`
	Redirect  string         `json:"ru,omitempty"`
	Challenge string         `json:"cc,omitempty"`
	Expires   int64          `json:"exp"`
}

// authorizationServer reports whether the gate signs users in for native
// clients: it needs the gate issuer and the UI login.
func (s *Server) authorizationServer() bool {
	return s.ui != nil && s.cfg.Authn.TokenIssuer() != nil
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.cfg.Authn.TokenIssuer().JWKS())
}

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	t := s.cfg.Authn.TokenIssuer()
	base := t.URL()
	algs := []string{}
	for _, k := range t.JWKS().Keys {
		algs = append(algs, k.Algorithm)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + oauthAuthorizePath,
		"token_endpoint":                        base + oauthTokenPath,
		"jwks_uri":                              base + jwksPath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "offline_access"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algs,
	})
}

// authorizeRequest is a validated authorization request.
type authorizeRequest struct {
	ClientID, RedirectURI, State, Challenge, Nonce, Scope string
}

func (a authorizeRequest) values() url.Values {
	v := url.Values{
		"response_type": {"code"}, "client_id": {a.ClientID}, "redirect_uri": {a.RedirectURI},
		"code_challenge": {a.Challenge}, "code_challenge_method": {"S256"},
	}
	for k, val := range map[string]string{"state": a.State, "nonce": a.Nonce, "scope": a.Scope} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v
}

// loopbackRedirect accepts http://localhost:<port> and http://127.0.0.1:<port>
// with an empty or "/" path (RFC 8252 loopback redirect).
func loopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" {
		return false
	}
	return u.Path == "" || u.Path == "/"
}

// parseAuthorize validates an authorization request. A nil redirect means
// the error must not be sent to the client (unknown client or redirect).
func parseAuthorize(v url.Values) (*authorizeRequest, string, bool) {
	a := &authorizeRequest{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"),
		Challenge: v.Get("code_challenge"), Nonce: v.Get("nonce"), Scope: v.Get("scope"),
	}
	if a.ClientID != RelayClientID || !loopbackRedirect(a.RedirectURI) {
		return nil, "unknown client or redirect URI", false
	}
	if len(a.State) > 512 || len(a.Nonce) > 512 || len(a.Scope) > 512 {
		return a, "invalid_request", true
	}
	if v.Get("response_type") != "code" {
		return a, "unsupported_response_type", true
	}
	if v.Get("code_challenge_method") != "S256" || len(a.Challenge) != 43 {
		return a, "invalid_request", true
	}
	return a, "", true
}

func redirectWith(w http.ResponseWriter, r *http.Request, a *authorizeRequest, params url.Values) {
	if a.State != "" {
		params.Set("state", a.State)
	}
	target := a.RedirectURI
	if strings.HasSuffix(target, "/") {
		target += "?" + params.Encode()
	} else {
		target += "/?" + params.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handleAuthorize shows the consent page to a signed-in user (GET), or
// sends an anonymous one through the UI login first, and issues the code
// once the user allows (POST).
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var values url.Values
	switch r.Method {
	case http.MethodGet:
		values = r.URL.Query()
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid form")
			return
		}
		values = r.PostForm
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET or POST only")
		return
	}
	a, oauthErr, redirectable := parseAuthorize(values)
	if !redirectable {
		writeError(w, http.StatusBadRequest, "invalid_request", oauthErr)
		return
	}
	if oauthErr != "" {
		redirectWith(w, r, a, url.Values{"error": {oauthErr}})
		return
	}
	subj, sess, err := s.ui.sessionSubject(r)
	if err != nil {
		var ae *authn.Error
		if errors.As(err, &ae) {
			writeError(w, ae.Status, ae.Reason, ae.Message)
			return
		}
		writeError(w, http.StatusForbidden, "forbidden", "not allowed")
		return
	}
	if subj == nil {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		http.Redirect(w, r, "/auth/login?"+url.Values{"return_to": {oauthAuthorizePath + "?" + a.values().Encode()}}.Encode(), http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		s.consentPage(w, r, a, subj)
		return
	}
	if !s.ui.checkFormCSRF(r, values.Get("csrf")) {
		writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token or origin")
		return
	}
	if values.Get("decision") != "allow" {
		redirectWith(w, r, a, url.Values{"error": {"access_denied"}})
		return
	}
	g := oauthGrant{
		Issuer: sess.Issuer, Claims: sess.Claims, AuthTime: sess.AuthTime, AMR: sess.AMR, Session: sess.Expires,
		Client: a.ClientID, Redirect: a.RedirectURI, Challenge: a.Challenge, Expires: s.now().Add(oauthCodeTTL).Unix(),
	}
	code, err := s.ui.sealer.seal(sealOAuthCode, g)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	redirectWith(w, r, a, url.Values{"code": {code}})
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Allow access to dns-gate</title>
<style>` + consentCSS + `</style></head>
<body><main>
<h1>Allow access to {{.Host}}?</h1>
<p>A local application (the Claude Desktop extension of this gate) asks to act as <strong>{{.Name}}</strong> on {{.Host}}, with your permissions, for the rest of this session.</p>
<p>Only allow it if you just started this sign-in yourself.</p>
<form method="post" action="` + oauthAuthorizePath + `">
{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">
{{end}}<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" class="secondary">Deny</button>
</form>
</main></body></html>`))

const consentCSS = `body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2330}main{max-width:34em;margin:4em auto;padding:2em;background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.12);line-height:1.5}h1{font-size:1.3em;margin-top:0}button{font:inherit;padding:.5em 1.2em;margin-right:.6em;border-radius:6px;border:1px solid #2b59c3;background:#2b59c3;color:#fff;cursor:pointer}button.secondary{background:#fff;color:#2b59c3}@media (prefers-color-scheme:dark){body{background:#14171c;color:#e4e7ec}main{background:#1d2129;box-shadow:none}button.secondary{background:#1d2129}}`

var consentStyleHash = func() string {
	sum := sha256.Sum256([]byte(consentCSS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

func (s *Server) consentPage(w http.ResponseWriter, r *http.Request, a *authorizeRequest, subj *identity.Subject) {
	csrf := ""
	if c, err := r.Cookie(csrfCookie); err == nil {
		csrf = c.Value
	}
	if csrf == "" {
		csrf = randomToken()
		http.SetCookie(w, s.ui.csrfCookie(csrf, s.cfg.Config.UI.SessionTTL.D()))
	}
	fields := map[string]string{}
	for k, v := range a.values() {
		fields[k] = v[0]
	}
	host := s.cfg.Authn.TokenIssuer().URL()
	if u, err := url.Parse(host); err == nil {
		host = u.Host
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src "+consentStyleHash+"; form-action 'self' http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(w, map[string]any{"Host": host, "Name": subj.Name, "Fields": fields, "CSRF": csrf})
}

// checkFormCSRF validates the CSRF token of a form post and its Origin.
func (u *uiAuth) checkFormCSRF(r *http.Request, token string) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" || token == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) != 1 {
		return false
	}
	return r.Header.Get("Origin") == u.origin
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleToken redeems an authorization code (with its PKCE verifier) or a
// refresh token for a gate token. The subject must still be bound.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	fail := func(status int, code, desc string) {
		writeJSON(w, status, oauthError{Error: code, Description: desc})
	}
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	f := r.PostForm
	now := s.now()
	var g oauthGrant
	refresh := ""
	via := f.Get("grant_type")
	switch via {
	case "authorization_code":
		if err := s.ui.sealer.open(sealOAuthCode, f.Get("code"), &g); err != nil || now.Unix() > g.Expires {
			fail(http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
			return
		}
		if f.Get("client_id") != g.Client || f.Get("redirect_uri") != g.Redirect {
			fail(http.StatusBadRequest, "invalid_grant", "client or redirect URI mismatch")
			return
		}
		verifier := f.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		if !pkceVerifierRe.MatchString(verifier) || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(g.Challenge)) != 1 {
			fail(http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		rg := g
		rg.Redirect, rg.Challenge, rg.Expires = "", "", g.Session
		var err error
		if refresh, err = s.ui.sealer.seal(sealOAuthRefresh, rg); err != nil {
			fail(http.StatusInternalServerError, "server_error", "")
			return
		}
	case "refresh_token":
		refresh = f.Get("refresh_token")
		if err := s.ui.sealer.open(sealOAuthRefresh, refresh, &g); err != nil || now.Unix() > g.Session {
			fail(http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
			return
		}
		if f.Get("client_id") != g.Client {
			fail(http.StatusBadRequest, "invalid_grant", "client mismatch")
			return
		}
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	subj, err := s.cfg.Authn.SubjectFromClaims(g.Issuer, g.Claims, identity.CategoryHuman)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_grant", "the identity is no longer allowed")
		return
	}
	tok, err := s.issueGateToken(r, subj, g.Issuer, g.Claims, g.AuthTime, g.AMR, g.Session, via, g.Client)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_grant", "session expired")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok.Raw, TokenType: "Bearer", ExpiresIn: int64(tok.Expires.Sub(now).Seconds()),
		RefreshToken: refresh, Scope: "openid offline_access",
	})
}

// issueGateToken signs a token for a session and records it in the audit
// log.
func (s *Server) issueGateToken(r *http.Request, subj *identity.Subject, origin string, claims map[string]any, authTime int64, amr []string, sessionExp int64, via, client string) (*authn.IssuedToken, error) {
	t := s.cfg.Authn.TokenIssuer()
	tok, err := t.Issue(authn.TokenRequest{
		Origin: origin, Subject: subj.ID, Category: subj.Category, Claims: claims,
		AuthTime: authTime, AMR: amr, MaxExpiry: time.Unix(sessionExp, 0),
	}, s.now())
	if err != nil {
		return nil, err
	}
	extra := map[string]any{"jti": tok.ID, "expires_at": tok.Expires.UTC().Format(time.RFC3339), "via": via}
	if client != "" {
		extra["client_id"] = client
	}
	s.cfg.Audit.Log(r.Context(), audit.Event{
		Time: s.now().UTC(), RequestID: requestid.From(r.Context()), Action: "token.issue", Decision: "allow",
		Subject: subj.String(), SubjectName: subj.Name, SubjectCategory: subj.Category, Teams: subj.Teams, Extra: extra,
	})
	return tok, nil
}

// issuedToken is the answer of POST /api/v1/tokens.
type issuedToken struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int64     `json:"expires_in"`
	ExpiresAt   time.Time `json:"expires_at"`
	Issuer      string    `json:"issuer"`
}

// handleIssueToken serves POST /api/v1/tokens: a gate token for the UI
// session (cookie, CSRF and origin checked by the caller).
func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request, subj *identity.Subject, sess *session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	if s.cfg.Authn.TokenIssuer() == nil {
		writeError(w, http.StatusNotFound, "not_found", "gate tokens are not enabled (no issuer with self: true)")
		return
	}
	if sess == nil {
		writeError(w, http.StatusForbidden, "session_required", "gate tokens are issued to UI sessions only")
		return
	}
	tok, err := s.issueGateToken(r, subj, sess.Issuer, sess.Claims, sess.AuthTime, sess.AMR, sess.Expires, "api", "")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "session expired")
		return
	}
	now := s.now()
	writeJSON(w, http.StatusOK, issuedToken{
		AccessToken: tok.Raw, TokenType: "Bearer", ExpiresIn: int64(tok.Expires.Sub(now).Seconds()),
		ExpiresAt: tok.Expires.UTC(), Issuer: s.cfg.Authn.TokenIssuer().URL(),
	})
}
