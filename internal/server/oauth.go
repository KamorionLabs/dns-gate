package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
	"github.com/KamorionLabs/dns-gate/internal/scope"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// Declared OAuth clients (oauth.clients): authorization codes are stored
// and single use, refresh tokens are sealed references to a persisted
// grant, rotated on every use with reuse detection.
const (
	oauthRevokePath = "/oauth/revoke"

	sealGrantRefresh = "dns-gate-oauth-grant-refresh"
	sealGrantPending = "dns-gate-oauth-grant-pending:"

	// refreshGrace is the window in which the previous refresh token of a
	// grant gets the answer of its rotation again (two instances of a
	// client racing), instead of revoking the grant.
	refreshGrace    = 30 * time.Second
	maxGrantRetries = 4
)

// noopScopes are accepted in requests and echoed in answers; they grant
// nothing.
var noopScopes = []string{"openid", scope.OfflineAccess}

// grantSession is the session snapshot of a grant (store.OAuthGrant.Session).
type grantSession struct {
	Claims      map[string]any `json:"c"`
	AMR         []string       `json:"amr,omitempty"`
	StoreGroups bool           `json:"sg,omitempty"`
	BaseGroups  []string       `json:"bg,omitempty"`
}

// codeData is the content of a stored authorization code.
type codeData struct {
	Client      string   `json:"cid"`
	Redirect    string   `json:"ru"`
	Challenge   string   `json:"cc"`
	Scopes      []string `json:"sc"`
	Extra       []string `json:"xs,omitempty"`
	Subject     string   `json:"sub"`
	SubjectName string   `json:"sn,omitempty"`
	Consented   bool     `json:"ok,omitempty"`
	Session     session  `json:"s"`
}

// refreshRef is the sealed content of a refresh token of a declared client.
type refreshRef struct {
	Grant      string `json:"g"`
	Generation int64  `json:"n"`
	Nonce      string `json:"r"`
}

// pendingAnswer is the sealed answer of the last rotation of a grant.
type pendingAnswer struct {
	Access  string `json:"a"`
	Refresh string `json:"r"`
	Expires int64  `json:"e"`
	Scope   string `json:"s"`
}

func hashToken(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func newGrantID() string { return "g-" + randomToken()[:26] }

// declaredClient returns an enabled declared client.
func (s *Server) declaredClient(id string) *config.OAuthClient {
	oc := s.cfg.Config.OAuthClient(id)
	if oc == nil || oc.Disabled {
		return nil
	}
	return oc
}

// parseScopes splits a requested scope: the scopes of the client, and the
// accepted no-op scopes. An unknown scope or none at all (without default
// scopes) is invalid_scope.
func parseScopes(oc *config.OAuthClient, raw string) ([]string, []string, bool) {
	var scopes, extra []string
	for _, sc := range strings.Fields(raw) {
		switch {
		case slices.Contains(noopScopes, sc):
			if !slices.Contains(extra, sc) {
				extra = append(extra, sc)
			}
		case slices.Contains(oc.Scopes, sc):
			if !slices.Contains(scopes, sc) {
				scopes = append(scopes, sc)
			}
		default:
			return nil, nil, false
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, oc.DefaultScopes...)
	}
	slices.Sort(scopes)
	return scopes, extra, len(scopes) > 0
}

// scopeString is the scope of an answer: the granted scopes and the no-op
// scopes requested.
func scopeString(scopes, extra []string) string {
	return strings.Join(append(append([]string{}, scopes...), extra...), " ")
}

// appendQuery adds params to the query of a redirect URI.
func appendQuery(raw string, params url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// parseDeclared validates the authorization request of a declared client.
func (s *Server) parseDeclared(v url.Values, a *authorizeRequest) (string, bool) {
	oc := s.declaredClient(a.ClientID)
	if oc == nil || !slices.Contains(oc.RedirectURIs, a.RedirectURI) {
		return "unknown client or redirect URI", false
	}
	a.client = oc
	a.Prompt, a.MaxAge, a.LoginHint, a.Reauthed = v.Get("prompt"), v.Get("max_age"), v.Get("login_hint"), v.Get("gate_reauth") == "1"
	if len(a.State) > 512 || len(a.Nonce) > 512 || len(a.Scope) > 1024 || len(a.LoginHint) > 256 || len(a.Prompt) > 64 {
		return "invalid_request", true
	}
	if v.Get("response_type") != "code" {
		return "unsupported_response_type", true
	}
	if v.Get("code_challenge_method") != "S256" || len(a.Challenge) != 43 {
		return "invalid_request", true
	}
	if v.Get("request") != "" || v.Get("request_uri") != "" {
		return "request_not_supported", true
	}
	if a.MaxAge != "" {
		if n, err := strconv.Atoi(a.MaxAge); err != nil || n < 0 || len(a.MaxAge) > 9 {
			return "invalid_request", true
		}
	}
	for _, p := range strings.Fields(a.Prompt) {
		if p != "login" && p != "consent" && p != "none" && p != "select_account" {
			return "invalid_request", true
		}
		if p == "none" && len(strings.Fields(a.Prompt)) > 1 {
			return "invalid_request", true
		}
	}
	var ok bool
	if a.scopes, a.extra, ok = parseScopes(oc, a.Scope); !ok {
		return "invalid_scope", true
	}
	return "", true
}

// reauthURL is the forced sign-in that comes back to the request, marked
// so that a sign-in the IdP did not renew ends with login_required.
func (a *authorizeRequest) reauthURL() string {
	again := a.values()
	again.Del("prompt")
	if p := strings.Join(slices.DeleteFunc(strings.Fields(a.Prompt), func(p string) bool { return p == "login" || p == "select_account" }), " "); p != "" {
		again.Set("prompt", p)
	}
	again.Set("gate_reauth", "1")
	return "/auth/login?" + url.Values{"reauth": {"1"}, "return_to": {oauthAuthorizePath + "?" + again.Encode()}}.Encode()
}

func (a *authorizeRequest) prompts(p string) bool {
	return slices.Contains(strings.Fields(a.Prompt), p)
}

// needsLogin reports whether the request asks for a fresh sign-in at the
// gate: prompt=login or select_account, or a max_age older than the
// session sign-in.
func (a *authorizeRequest) needsLogin(sess *session, now time.Time) bool {
	if a.prompts("login") || a.prompts("select_account") {
		return true
	}
	if a.MaxAge == "" {
		return false
	}
	n, _ := strconv.Atoi(a.MaxAge)
	return sess.AuthTime == 0 || now.Sub(time.Unix(sess.AuthTime, 0)) > time.Duration(n)*time.Second+time.Minute
}

// authorizeDeclared continues the authorization of a signed-in user for a
// declared client: a fresh sign-in when asked, the remembered consent or
// the consent page (GET), the code once the user allows (POST).
func (s *Server) authorizeDeclared(w http.ResponseWriter, r *http.Request, a *authorizeRequest, subj *identity.Subject, sess *session, values url.Values) {
	now := s.now()
	if a.needsLogin(sess, now) {
		if a.Reauthed || a.prompts("none") {
			s.redirectDeclared(w, r, a, url.Values{"error": {"login_required"}})
			return
		}
		http.Redirect(w, r, a.reauthURL(), http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		remembered := !a.prompts("consent") && s.consentRemembered(r.Context(), a, subj)
		switch {
		case remembered:
			s.issueCode(w, r, a, subj, sess, false)
		case a.prompts("none"):
			s.redirectDeclared(w, r, a, url.Values{"error": {"consent_required"}})
		default:
			s.consentPage(w, r, a, subj)
		}
		return
	}
	if !s.ui.checkFormCSRF(r, values.Get("csrf")) {
		writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token or origin")
		return
	}
	if values.Get("decision") != "allow" {
		s.oauthAudit(r, subj, "oauth.authorize", a.client, "", "deny", "access_denied", map[string]any{"scopes": a.scopes})
		s.redirectDeclared(w, r, a, url.Values{"error": {"access_denied"}})
		return
	}
	s.issueCode(w, r, a, subj, sess, true)
}

// consentRemembered reports whether the subject has an active grant of
// the client covering the requested scopes.
func (s *Server) consentRemembered(ctx context.Context, a *authorizeRequest, subj *identity.Subject) bool {
	g, err := s.activeGrant(ctx, a.client.ID, subj.String())
	if err != nil || g == nil {
		return false
	}
	for _, sc := range a.scopes {
		if !slices.Contains(g.Scopes, sc) {
			return false
		}
	}
	return true
}

// activeGrant returns the newest grant of a client for a subject that is
// neither revoked, expired nor idle for refresh_idle_ttl, nil if none.
func (s *Server) activeGrant(ctx context.Context, client, subject string) (*store.OAuthGrant, error) {
	gs, err := s.cfg.OAuth.ListOAuthGrants(ctx, store.OAuthGrantQuery{ClientID: client, Subject: subject})
	if err != nil {
		return nil, err
	}
	oc := s.cfg.Config.OAuthClient(client)
	now := s.now()
	for i := range gs {
		if gs[i].Active(now) && oc != nil && now.Sub(gs[i].LastUsedAt) <= oc.RefreshIdleTTL.D() {
			return &gs[i], nil
		}
	}
	return nil, nil
}

func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, a *authorizeRequest, subj *identity.Subject, sess *session, consented bool) {
	code := randomToken()
	data := codeData{
		Client: a.client.ID, Redirect: a.RedirectURI, Challenge: a.Challenge, Scopes: a.scopes, Extra: a.extra,
		Subject: subj.String(), SubjectName: subj.Name, Consented: consented, Session: *sess,
	}
	raw, err := json.Marshal(data)
	if err == nil {
		err = s.cfg.OAuth.PutOAuthCode(r.Context(), store.OAuthCode{Hash: hashToken(code), ClientID: a.client.ID, Data: raw, ExpiresAt: s.now().Add(oauthCodeTTL)})
	}
	if err != nil {
		s.log.Error("oauth code", "err", err)
		s.redirectDeclared(w, r, a, url.Values{"error": {"temporarily_unavailable"}})
		return
	}
	reason := "consent"
	if !consented {
		reason = "remembered"
	}
	s.oauthAudit(r, subj, "oauth.authorize", a.client, "", "allow", reason, map[string]any{"scopes": a.scopes})
	s.redirectDeclared(w, r, a, url.Values{"code": {code}})
}

// redirectDeclared answers an authorization request of a declared client
// at its redirect URI, with state and iss (RFC 9207).
func (s *Server) redirectDeclared(w http.ResponseWriter, r *http.Request, a *authorizeRequest, params url.Values) {
	if a.State != "" {
		params.Set("state", a.State)
	}
	params.Set("iss", s.cfg.Authn.TokenIssuer().URL())
	http.Redirect(w, r, appendQuery(a.RedirectURI, params), http.StatusFound)
}

// tokenFail writes an OAuth error of the token or revocation endpoint.
func tokenFail(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, oauthError{Error: code, Description: desc})
}

func clientFail(w http.ResponseWriter, e *authn.ClientError) {
	if e.Unavailable {
		tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", e.Message)
		return
	}
	status := http.StatusBadRequest
	if e.Code == "invalid_client" {
		status = http.StatusUnauthorized
		if e.Basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="dns-gate"`)
		}
	}
	tokenFail(w, status, e.Code, e.Message)
}

// relayRequest reports whether a token or revocation request comes from
// the built-in relay client (no client authentication).
func relayRequest(r *http.Request, f url.Values) bool {
	return f.Get("client_id") == RelayClientID && r.Header.Get("Authorization") == "" && f.Get("client_assertion") == "" && f.Get("client_secret") == ""
}

// authenticateClient authenticates the client of a token or revocation
// request; assertions are recorded in the store against replays.
func (s *Server) authenticateClient(r *http.Request, f url.Values) (*config.OAuthClient, *authn.ClientError) {
	base := s.cfg.Authn.TokenIssuer().URL()
	audiences := []string{base + oauthTokenPath, base, base + "/", base + oauthRevokePath}
	return s.cfg.Authn.AuthenticateClient(r, f, audiences, func(ctx context.Context, key string, exp time.Time) error {
		sum := sha256.Sum256([]byte(key))
		err := s.cfg.OAuth.UseOAuthJTI(ctx, hex.EncodeToString(sum[:]), exp, s.now())
		if errors.Is(err, store.ErrConflict) {
			return authn.ErrReplay
		}
		return err
	})
}

// handleClientToken serves the token endpoint for a declared client.
func (s *Server) handleClientToken(w http.ResponseWriter, r *http.Request, f url.Values) {
	oc, cerr := s.authenticateClient(r, f)
	if cerr != nil {
		clientFail(w, cerr)
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		s.redeemCode(w, r, oc, f)
	case "refresh_token":
		s.refreshGrant(w, r, oc, f)
	default:
		tokenFail(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *Server) redeemCode(w http.ResponseWriter, r *http.Request, oc *config.OAuthClient, f url.Values) {
	ctx := r.Context()
	fail := func(desc string) {
		s.oauthAudit(r, nil, "oauth.token", oc, "", "deny", "invalid_grant", map[string]any{"via": "authorization_code", "message": desc})
		tokenFail(w, http.StatusBadRequest, "invalid_grant", desc)
	}
	code := f.Get("code")
	if code == "" || len(code) > 256 {
		fail("invalid or expired authorization code")
		return
	}
	c, err := s.cfg.OAuth.TakeOAuthCode(ctx, hashToken(code))
	if errors.Is(err, store.ErrNotFound) {
		fail("invalid or expired authorization code")
		return
	}
	if err != nil {
		s.log.Error("oauth code", "err", err)
		tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return
	}
	var d codeData
	if c.ClientID != oc.ID || !s.now().Before(c.ExpiresAt) || json.Unmarshal(c.Data, &d) != nil || d.Client != oc.ID {
		fail("invalid or expired authorization code")
		return
	}
	if f.Get("redirect_uri") != d.Redirect {
		fail("redirect URI mismatch")
		return
	}
	verifier := f.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if !pkceVerifierRe.MatchString(verifier) || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(d.Challenge)) != 1 {
		fail("PKCE verification failed")
		return
	}
	subj, err := s.cfg.Authn.SubjectFromClaims(d.Session.Issuer, d.Session.Claims, identity.CategoryHuman)
	if err != nil || subj.String() != d.Subject {
		fail("the identity is no longer allowed")
		return
	}
	snap, _ := json.Marshal(grantSession{Claims: d.Session.Claims, AMR: d.Session.AMR, StoreGroups: d.Session.StoreGroups, BaseGroups: d.Session.BaseGroups})
	refresh, nonce := "", ""
	var g *store.OAuthGrant
	for attempt := 0; ; attempt++ {
		now := s.now()
		cur, err := s.activeGrant(ctx, oc.ID, d.Subject)
		if err != nil {
			s.log.Error("oauth grant", "err", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
		nonce = randomToken()
		if cur == nil {
			g = &store.OAuthGrant{
				ID: newGrantID(), ClientID: oc.ID, Subject: d.Subject, CreatedAt: now, ConsentedAt: now, ExpiresAt: now.Add(oc.RefreshMaxTTL.D()),
			}
		} else {
			g = cur
			for _, sc := range d.Scopes {
				if !slices.Contains(g.Scopes, sc) {
					g.Scopes = append(g.Scopes, sc)
				}
			}
			if d.Consented {
				g.ConsentedAt, g.ExpiresAt = now, now.Add(oc.RefreshMaxTTL.D())
			}
		}
		if cur == nil {
			g.Scopes = append([]string{}, d.Scopes...)
		}
		slices.Sort(g.Scopes)
		g.SubjectName, g.Issuer, g.Session, g.AuthTime = d.SubjectName, d.Session.Issuer, snap, d.Session.AuthTime
		g.LastUsedAt, g.ClaimsAt = now, now
		g.Generation++
		g.BaseGeneration = g.Generation
		g.PreviousHash, g.RotatedAt, g.Pending = "", nil, ""
		if refresh, err = s.ui.sealer.seal(sealGrantRefresh, refreshRef{Grant: g.ID, Generation: g.Generation, Nonce: nonce}); err != nil {
			tokenFail(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		g.RefreshHash = hashToken(refresh)
		if cur == nil {
			err = s.cfg.OAuth.CreateOAuthGrant(ctx, *g)
		} else {
			err = s.cfg.OAuth.UpdateOAuthGrant(ctx, *g)
		}
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || attempt >= maxGrantRetries {
			s.log.Error("oauth grant", "err", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
	}
	s.cfg.Authn.InvalidateGrant(g.ID)
	tok, err := s.issueClientToken(r, oc, g, subj, d.Session.Claims, g.Scopes, "authorization_code")
	if err != nil {
		fail("session expired")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok.Raw, TokenType: "Bearer", ExpiresIn: int64(tok.Expires.Sub(s.now()).Round(time.Second).Seconds()),
		RefreshToken: refresh, Scope: scopeString(g.Scopes, d.Extra),
	})
}

// issueClientToken signs the access token of a grant and audits it
// (oauth.token).
func (s *Server) issueClientToken(r *http.Request, oc *config.OAuthClient, g *store.OAuthGrant, subj *identity.Subject, claims map[string]any, scopes []string, via string) (*authn.IssuedToken, error) {
	now := s.now()
	exp := now.Add(oc.AccessTokenTTL.D())
	if g.ExpiresAt.Before(exp) {
		exp = g.ExpiresAt
	}
	var sess grantSession
	_ = json.Unmarshal(g.Session, &sess)
	tok, err := s.cfg.Authn.TokenIssuer().Issue(authn.TokenRequest{
		Origin: g.Issuer, Subject: subj.ID, Category: identity.CategoryHuman, Claims: claims,
		AuthTime: g.AuthTime, AMR: sess.AMR, MaxExpiry: exp, Client: oc.ID, Scopes: scopes, Grant: g.ID,
	}, now)
	if err != nil {
		return nil, err
	}
	s.oauthAudit(r, subj, "oauth.token", oc, g.ID, "allow", "", map[string]any{
		"via": via, "jti": tok.ID, "expires_at": tok.Expires.UTC().Format(time.RFC3339), "scopes": scopes,
	})
	return tok, nil
}

func (s *Server) refreshGrant(w http.ResponseWriter, r *http.Request, oc *config.OAuthClient, f url.Values) {
	raw := f.Get("refresh_token")
	var ref refreshRef
	if raw == "" || len(raw) > 1024 || s.ui.sealer.open(sealGrantRefresh, raw, &ref) != nil || ref.Grant == "" {
		s.oauthAudit(r, nil, "oauth.token", oc, "", "deny", "invalid_grant", map[string]any{"via": "refresh_token", "message": "invalid refresh token"})
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}
	for attempt := 0; ; attempt++ {
		done, retry := s.refreshOnce(w, r, oc, f, raw, ref)
		if done {
			return
		}
		if !retry || attempt >= maxGrantRetries {
			s.log.Error("oauth refresh: concurrent updates", "grant", ref.Grant)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
	}
}

// refreshOnce runs one attempt of a refresh; retry is set when the grant
// changed meanwhile (another instance rotated it).
func (s *Server) refreshOnce(w http.ResponseWriter, r *http.Request, oc *config.OAuthClient, f url.Values, raw string, ref refreshRef) (done, retry bool) {
	ctx := r.Context()
	now := s.now()
	g, err := s.cfg.OAuth.GetOAuthGrant(ctx, ref.Grant)
	deny := func(desc string, extra map[string]any) (bool, bool) {
		if extra == nil {
			extra = map[string]any{}
		}
		extra["via"], extra["message"] = "refresh_token", desc
		gid := ""
		if g != nil {
			gid = g.ID
			extra["subject"] = g.Subject
		}
		s.oauthAudit(r, nil, "oauth.token", oc, gid, "deny", "invalid_grant", extra)
		tokenFail(w, http.StatusBadRequest, "invalid_grant", desc)
		return true, false
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return deny("invalid or expired refresh token", nil)
	case err != nil:
		s.log.Error("oauth grant", "err", err)
		tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return true, false
	case g.ClientID != oc.ID:
		return deny("invalid or expired refresh token", nil)
	case g.RevokedAt != nil:
		return deny("the grant is revoked", nil)
	case !now.Before(g.ExpiresAt):
		return deny("the grant expired (refresh_max_ttl): authorize again", nil)
	case now.Sub(g.LastUsedAt) > oc.RefreshIdleTTL.D():
		return deny("the grant expired (refresh_idle_ttl): authorize again", nil)
	}
	hash := hashToken(raw)
	switch {
	case ref.Generation == g.Generation && subtle.ConstantTimeCompare([]byte(hash), []byte(g.RefreshHash)) == 1:
	case ref.Generation == g.Generation-1 && g.PreviousHash != "" && subtle.ConstantTimeCompare([]byte(hash), []byte(g.PreviousHash)) == 1 &&
		g.RotatedAt != nil && now.Sub(*g.RotatedAt) <= refreshGrace && g.Pending != "":
		var p pendingAnswer
		if s.ui.sealer.open(sealGrantPending+g.ID, g.Pending, &p) != nil || now.Unix() >= p.Expires {
			return deny("invalid or expired refresh token", nil)
		}
		s.oauthAudit(r, nil, "oauth.token", oc, g.ID, "allow", "grace", map[string]any{"via": "refresh_token"})
		writeJSON(w, http.StatusOK, tokenResponse{AccessToken: p.Access, TokenType: "Bearer", ExpiresIn: p.Expires - now.Unix(), RefreshToken: p.Refresh, Scope: p.Scope})
		return true, false
	case ref.Generation >= g.BaseGeneration && ref.Generation < g.Generation:
		s.revokeGrant(ctx, g, "gate", "refresh_reuse")
		s.oauthAudit(r, nil, "oauth.refresh_reuse", oc, g.ID, "deny", "refresh_reuse", map[string]any{
			"subject": g.Subject, "generation": ref.Generation, "current_generation": g.Generation,
		})
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "refresh token reused: the grant is revoked")
		return true, false
	default:
		return deny("invalid or expired refresh token", map[string]any{"generation": ref.Generation})
	}
	var sess grantSession
	if json.Unmarshal(g.Session, &sess) != nil {
		return deny("invalid grant", nil)
	}
	claimsAt := g.ClaimsAt
	if sess.StoreGroups && s.ui.storeGroups() && g.Issuer == s.ui.issuer.Name {
		claims := map[string]any{}
		for k, v := range sess.Claims {
			claims[k] = v
		}
		if err := s.ui.mergeStoreGroups(ctx, claims, sess.BaseGroups); err != nil {
			s.log.Error("oauth refresh: identity store groups", "err", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "group membership unavailable")
			return true, false
		}
		sess.Claims, claimsAt = claims, now
	} else if now.Sub(g.ClaimsAt) > oc.ClaimsMaxAge.D() {
		return deny("the claims of the grant are older than claims_max_age: authorize again", nil)
	}
	subj, err := s.cfg.Authn.SubjectFromClaims(g.Issuer, sess.Claims, identity.CategoryHuman)
	if err != nil || subj.String() != g.Subject {
		return deny("the identity is no longer allowed", nil)
	}
	scopes := g.Scopes
	extra := []string{}
	if req := f.Get("scope"); req != "" {
		var narrowed []string
		for _, sc := range strings.Fields(req) {
			switch {
			case slices.Contains(noopScopes, sc):
				extra = append(extra, sc)
			case slices.Contains(g.Scopes, sc) && slices.Contains(oc.Scopes, sc):
				narrowed = append(narrowed, sc)
			default:
				s.oauthAudit(r, subj, "oauth.token", oc, g.ID, "deny", "invalid_scope", map[string]any{"via": "refresh_token"})
				tokenFail(w, http.StatusBadRequest, "invalid_scope", "scope "+sc+" is not granted")
				return true, false
			}
		}
		if len(narrowed) > 0 {
			slices.Sort(narrowed)
			scopes = narrowed
		}
	}
	nonce := randomToken()
	refresh, err := s.ui.sealer.seal(sealGrantRefresh, refreshRef{Grant: g.ID, Generation: g.Generation + 1, Nonce: nonce})
	if err != nil {
		tokenFail(w, http.StatusInternalServerError, "server_error", "")
		return true, false
	}
	exp := now.Add(oc.AccessTokenTTL.D())
	if g.ExpiresAt.Before(exp) {
		exp = g.ExpiresAt
	}
	tok, err := s.cfg.Authn.TokenIssuer().Issue(authn.TokenRequest{
		Origin: g.Issuer, Subject: subj.ID, Category: identity.CategoryHuman, Claims: sess.Claims,
		AuthTime: g.AuthTime, AMR: sess.AMR, MaxExpiry: exp, Client: oc.ID, Scopes: scopes, Grant: g.ID,
	}, now)
	if err != nil {
		return deny("the grant expired", nil)
	}
	answer := tokenResponse{AccessToken: tok.Raw, TokenType: "Bearer", ExpiresIn: int64(tok.Expires.Sub(now).Round(time.Second).Seconds()), RefreshToken: refresh, Scope: scopeString(scopes, extra)}
	pending, err := s.ui.sealer.seal(sealGrantPending+g.ID, pendingAnswer{Access: tok.Raw, Refresh: refresh, Expires: tok.Expires.Unix(), Scope: answer.Scope})
	if err != nil {
		tokenFail(w, http.StatusInternalServerError, "server_error", "")
		return true, false
	}
	next := *g
	if sess.StoreGroups {
		next.Session, _ = json.Marshal(sess)
	}
	rotated := now
	next.ClaimsAt, next.LastUsedAt = claimsAt, now
	next.Generation, next.PreviousHash, next.RefreshHash, next.RotatedAt, next.Pending = g.Generation+1, g.RefreshHash, hashToken(refresh), &rotated, pending
	if err := s.cfg.OAuth.UpdateOAuthGrant(ctx, next); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return false, true
		}
		s.log.Error("oauth grant", "err", err)
		tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return true, false
	}
	s.oauthAudit(r, subj, "oauth.token", oc, g.ID, "allow", "", map[string]any{
		"via": "refresh_token", "jti": tok.ID, "expires_at": tok.Expires.UTC().Format(time.RFC3339), "scopes": scopes,
	})
	writeJSON(w, http.StatusOK, answer)
	return true, false
}

// revokeGrant revokes a grant (and so every token of it); an already
// revoked grant is left alone.
func (s *Server) revokeGrant(ctx context.Context, g *store.OAuthGrant, by, reason string) error {
	for attempt := 0; ; attempt++ {
		if g.RevokedAt != nil {
			return nil
		}
		now := s.now()
		next := *g
		next.RevokedAt, next.RevokedBy, next.RevokeReason, next.Pending = &now, by, reason, ""
		err := s.cfg.OAuth.UpdateOAuthGrant(ctx, next)
		if err == nil {
			s.cfg.Authn.InvalidateGrant(g.ID)
			return nil
		}
		if !errors.Is(err, store.ErrConflict) || attempt >= maxGrantRetries {
			return err
		}
		if g, err = s.cfg.OAuth.GetOAuthGrant(ctx, g.ID); err != nil {
			return err
		}
	}
}

// handleRevoke serves the revocation endpoint (RFC 7009): a refresh or
// access token of the authenticated client revokes its grant. Unknown
// tokens, tokens of other clients and the stateless tokens of the relay
// client get 200 without effect.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	if err := r.ParseForm(); err != nil {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	f := r.PostForm
	if relayRequest(r, f) {
		w.WriteHeader(http.StatusOK)
		return
	}
	oc, cerr := s.authenticateClient(r, f)
	if cerr != nil {
		clientFail(w, cerr)
		return
	}
	tok := f.Get("token")
	if tok == "" {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}
	grantID := ""
	var ref refreshRef
	if len(tok) <= 1024 && s.ui.sealer.open(sealGrantRefresh, tok, &ref) == nil {
		grantID = ref.Grant
	} else if claims, err := s.cfg.Authn.GateTokenClaims(r.Context(), tok); err == nil {
		if c, _ := claims[authn.ClaimClientID].(string); c == oc.ID {
			grantID, _ = claims[authn.ClaimGrant].(string)
		}
	}
	if grantID != "" {
		g, err := s.cfg.OAuth.GetOAuthGrant(r.Context(), grantID)
		switch {
		case err == nil && g.ClientID == oc.ID:
			if err := s.revokeGrant(r.Context(), g, "client:"+oc.ID, "client"); err != nil {
				s.log.Error("oauth revoke", "err", err)
				tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
				return
			}
			s.oauthAudit(r, nil, "oauth.revoke", oc, g.ID, "allow", "client", map[string]any{"subject": g.Subject})
		case err != nil && !errors.Is(err, store.ErrNotFound):
			s.log.Error("oauth revoke", "err", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// oauthAudit records an event of the authorization server. subj is the
// user when known; the client and grant come from the configuration and
// the store.
func (s *Server) oauthAudit(r *http.Request, subj *identity.Subject, action string, oc *config.OAuthClient, grant, decision, reason string, extra map[string]any) {
	e := audit.Event{
		Time: s.now().UTC(), RequestID: requestid.From(r.Context()), Action: action, Decision: decision, Reason: reason,
		Extra: map[string]any{},
	}
	if subj != nil {
		e.Subject, e.SubjectName, e.SubjectCategory, e.Teams = subj.String(), subj.Name, subj.Category, subj.Teams
	} else if sub, ok := extra["subject"].(string); ok {
		e.Subject = sub
		delete(extra, "subject")
	}
	if oc != nil {
		e.SetClient(oc.ID, oc.Name)
	}
	for k, v := range extra {
		e.Extra[k] = v
	}
	if grant != "" {
		e.Extra["grant_id"] = grant
	}
	if len(e.Extra) == 0 {
		e.Extra = nil
	}
	s.cfg.Audit.Log(r.Context(), e)
}
