package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/samlauth"
)

const loginTTL = 10 * time.Minute

var protocolClaims = map[string]bool{
	"aud": true, "exp": true, "iat": true, "nbf": true, "nonce": true, "at_hash": true,
	"c_hash": true, "auth_time": true, "amr": true, "acr": true, "jti": true, "sid": true, "uti": true, "rh": true, "aio": true,
}

// uiAuth implements the UI login: OIDC authorization code flow with PKCE
// (S256), state and nonce, or SAML 2.0 (saml set), and an encrypted
// session cookie.
type uiAuth struct {
	cfg        config.UI
	issuer     config.Issuer
	saml       *samlauth.Provider
	groups     GroupLookup
	log        *slog.Logger
	authn      *authn.Authenticator
	client     *http.Client
	now        func() time.Time
	cookies    cookieNames
	sealer     *sealer
	origin     string // expected Origin of mutations
	editMaxAge time.Duration

	mu        sync.Mutex
	endpoints *oidcEndpoints
}

type oidcEndpoints struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
}

func newUIAuth(c *config.Config, a *authn.Authenticator, client *http.Client, now func() time.Time, groups GroupLookup) (*uiAuth, error) {
	u := &uiAuth{cfg: c.UI, authn: a, client: client, now: now, groups: groups}
	issuer, redirectURL := c.UI.Issuer, c.UI.RedirectURL
	if s := c.UI.SAML; s != nil {
		issuer, redirectURL = s.Issuer, s.ACSURL
		p, err := samlauth.New(*s, client)
		if err != nil {
			return nil, err
		}
		u.saml = p
	}
	for _, is := range c.AllIssuers() {
		if is.Name == issuer {
			u.issuer = is
		}
	}
	redirect, err := url.Parse(redirectURL)
	if err != nil {
		return nil, err
	}
	u.cookies = newCookieNames(redirect.Scheme == "https")
	u.origin = redirect.Scheme + "://" + redirect.Host
	u.editMaxAge = c.Policy.EditMaxAge.D()
	if u.sealer, err = newSealer(c.UI.SessionKey); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *uiAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case p == "/auth/login" && u.saml != nil:
		u.samlLogin(w, r)
	case p == config.SAMLACSPath && u.saml != nil:
		u.samlACS(w, r)
	case p == config.SAMLMetadataPath && u.saml != nil:
		u.samlMetadata(w, r)
	case p == "/auth/login":
		u.login(w, r)
	case p == "/auth/callback" && u.saml == nil:
		u.callback(w, r)
	case p == "/auth/logout":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
			return
		}
		http.SetCookie(w, u.cookies.clear(u.cookies.session))
		http.SetCookie(w, u.csrfCookie("", -1))
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown auth endpoint")
	}
}

func (u *uiAuth) discover(ctx context.Context) (*oidcEndpoints, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.endpoints != nil {
		return u.endpoints, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(u.issuer.Issuer, "/")+"/.well-known/openid-configuration", nil)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: status %d", resp.StatusCode)
	}
	var ep oidcEndpoints
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ep); err != nil {
		return nil, err
	}
	if strings.TrimSuffix(ep.Issuer, "/") != strings.TrimSuffix(u.issuer.Issuer, "/") || ep.Authorization == "" || ep.Token == "" {
		return nil, errors.New("discovery: incomplete or mismatched document")
	}
	u.endpoints = &ep
	return &ep, nil
}

func (u *uiAuth) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	ep, err := u.discover(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "idp_unavailable", "identity provider unavailable")
		return
	}
	next := r.URL.Query().Get("return_to")
	if next == "" {
		next = r.URL.Query().Get("next")
	}
	st := loginState{
		Reauth:   r.URL.Query().Get("reauth") == "1",
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: randomToken(),
		Next:     safeNext(next),
		Expires:  u.now().Add(loginTTL).Unix(),
	}
	val, err := u.sealer.seal(u.cookies.login, st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	http.SetCookie(w, u.cookies.cookie(u.cookies.login, val, loginTTL))
	challenge := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {u.cfg.ClientID},
		"redirect_uri":          {u.cfg.RedirectURL},
		"scope":                 {strings.Join(u.cfg.Scopes, " ")},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	if st.Reauth {
		q.Set("prompt", "login")
		q.Set("max_age", strconv.Itoa(int(u.editMaxAge.Seconds())))
	}
	target := ep.Authorization
	if strings.Contains(target, "?") {
		target += "&" + q.Encode()
	} else {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (u *uiAuth) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	c, err := r.Cookie(u.cookies.login)
	if err != nil {
		writeError(w, http.StatusBadRequest, "login_state", "login state missing, restart the login")
		return
	}
	http.SetCookie(w, u.cookies.clear(u.cookies.login))
	var st loginState
	if err := u.sealer.open(u.cookies.login, c.Value, &st); err != nil || u.now().Unix() > st.Expires {
		writeError(w, http.StatusBadRequest, "login_state", "login state invalid or expired")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		writeError(w, http.StatusUnauthorized, "idp_error", "identity provider returned an error")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		writeError(w, http.StatusBadRequest, "login_state", "state mismatch")
		return
	}
	code := q.Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "login_state", "authorization code missing")
		return
	}
	ep, err := u.discover(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "idp_unavailable", "identity provider unavailable")
		return
	}
	idToken, err := u.exchange(r.Context(), ep.Token, code, st.Verifier)
	if err != nil {
		writeError(w, http.StatusBadGateway, "token_exchange", "token exchange failed")
		return
	}
	claims, err := u.authn.VerifyToken(r.Context(), u.issuer.Name, idToken, []string{u.cfg.ClientID})
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid ID token")
		return
	}
	if nonce, _ := claims["nonce"].(string); subtle.ConstantTimeCompare([]byte(nonce), []byte(st.Nonce)) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "nonce mismatch")
		return
	}
	// Every identity claim is kept (managed groups may use any claim);
	// protocol claims are dropped. Roles and teams are recomputed per request.
	kept := map[string]any{}
	for k, v := range claims {
		if !protocolClaims[k] {
			kept[k] = v
		}
	}
	sess := session{Issuer: u.issuer.Name, Claims: kept, Expires: u.now().Add(u.cfg.SessionTTL.D()).Unix(), AMR: policyClaimStrings(claims["amr"])}
	if at, ok := claims["auth_time"].(float64); ok {
		sess.AuthTime = int64(at)
	} else if st.Reauth {
		sess.AuthTime = u.now().Unix()
	}
	u.establish(w, r, sess, st.Next)
}

// establish checks that the session claims are bound, then sets the session
// and CSRF cookies and redirects to next.
func (u *uiAuth) establish(w http.ResponseWriter, r *http.Request, sess session, next string) {
	if _, err := u.subject(sess.Claims); err != nil {
		var ae *authn.Error
		if errors.As(err, &ae) {
			writeError(w, ae.Status, ae.Reason, ae.Message)
			return
		}
		writeError(w, http.StatusForbidden, "forbidden", "not allowed")
		return
	}
	val, err := u.sealer.seal(u.cookies.session, sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if len(val) > 3800 {
		writeError(w, http.StatusInternalServerError, "session_too_large", "session claims too large for a cookie")
		return
	}
	ttl := time.Unix(sess.Expires, 0).Sub(u.now())
	if ttl > u.cfg.SessionTTL.D() || ttl < time.Minute {
		ttl = u.cfg.SessionTTL.D()
	}
	http.SetCookie(w, u.cookies.cookie(u.cookies.session, val, ttl))
	http.SetCookie(w, u.csrfCookie(randomToken(), ttl))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (u *uiAuth) exchange(ctx context.Context, tokenURL, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {u.cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	if u.cfg.ClientSecret == "" {
		form.Set("client_id", u.cfg.ClientID)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if u.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(u.cfg.ClientID), url.QueryEscape(u.cfg.ClientSecret))
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: status %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", err
	}
	if tr.IDToken == "" {
		return "", errors.New("token endpoint: no id_token")
	}
	return tr.IDToken, nil
}

func (u *uiAuth) subject(claims map[string]any) (*identity.Subject, error) {
	return u.authn.SubjectFromClaims(u.issuer.Name, claims, identity.CategoryHuman)
}

// sessionSubject returns the subject of a valid session cookie, nil if none.
func (u *uiAuth) sessionSubject(r *http.Request) (*identity.Subject, *session, error) {
	c, err := r.Cookie(u.cookies.session)
	if err != nil {
		return nil, nil, nil
	}
	var s session
	if err := u.sealer.open(u.cookies.session, c.Value, &s); err != nil || s.Issuer != u.issuer.Name || u.now().Unix() > s.Expires {
		return nil, nil, nil
	}
	method := audit.AuthOIDCSession
	if u.saml != nil {
		method = audit.AuthSAMLSession
	}
	audit.SetAuthMethod(r.Context(), method)
	subj, err := u.subject(s.Claims)
	if err != nil {
		return nil, nil, err
	}
	return subj, &s, nil
}

func (u *uiAuth) csrfCookie(value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: csrfCookie, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		HttpOnly: false, Secure: u.cookies.secure, SameSite: http.SameSiteStrictMode,
	}
}

// checkCSRF validates the double-submit token and the Origin of a
// cookie-authenticated mutation.
func (u *uiAuth) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	h := r.Header.Get(csrfHeader)
	if err != nil || c.Value == "" || h == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(h)) != 1 {
		return false
	}
	return r.Header.Get("Origin") == u.origin
}

func policyClaimStrings(v any) []string { return policy.ClaimStrings(v) }

// safeNext only allows redirects back into the UI or to the authorization
// endpoint of the gate issuer.
func safeNext(next string) string {
	if next == "" || !(strings.HasPrefix(next, "/ui/") || strings.HasPrefix(next, oauthAuthorizePath+"?")) || strings.Contains(next, "//") || strings.Contains(next, `\`) {
		return "/ui/"
	}
	return next
}
