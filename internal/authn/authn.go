// Package authn authenticates callers (OIDC bearer tokens or gate-issued
// virtual keys) and binds them to roles and teams.
package authn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/apikey"
	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// Error is an authentication failure. Status is 401 (no or bad credentials)
// or 403 (valid credentials, no binding).
type Error struct {
	Status  int
	Reason  string
	Message string
}

func (e *Error) Error() string { return e.Reason + ": " + e.Message }

func unauthorized(msg string) *Error {
	return &Error{Status: http.StatusUnauthorized, Reason: "unauthenticated", Message: msg}
}

// Header names stripped from every request after authentication.
var credentialHeaders = []string{"Authorization", "X-App-Id", "X-Api-Key", "X-Api-User", "Cookie"}

type issuer struct {
	cfg     config.Issuer
	clients map[string]*config.DelegatedClient
	keys    *keySet
	static  *jose.JSONWebKey
	algs    []jose.SignatureAlgorithm
}

// Authenticator verifies credentials and builds subjects. Groups,
// bindings and virtual keys come from the current policy snapshot.
type Authenticator struct {
	byURL   map[string]*issuer
	byName  map[string]*issuer
	policy  *policy.Holder
	trusted []netip.Prefix
	self    *TokenIssuer
	keys    APIKeys
	audit   audit.Logger
	noise   noiseCounter
	now     func() time.Time
	log     *slog.Logger
	warned  sync.Map

	oauthClients map[string]*config.OAuthClient
	clientKeys   map[string]*keySet
	grants       OAuthGrants
	grantCache   grantCache
	clientNoise  noiseCounter
	publicNoise  noiseCounter
}

// SetLogger sets the logger of the warnings about refused team names
// (slog.Default by default).
func (a *Authenticator) SetLogger(l *slog.Logger) { a.log = l }

// warnOnce logs a warning once per key and process.
func (a *Authenticator) warnOnce(key, msg string, args ...any) {
	if _, seen := a.warned.LoadOrStore(key, true); seen {
		return
	}
	l := a.log
	if l == nil {
		l = slog.Default()
	}
	l.Warn(msg, args...)
}

// New builds an Authenticator. client is used for discovery and JWKS.
func New(c *config.Config, client *http.Client, h *policy.Holder) (*Authenticator, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if h == nil {
		var err error
		if h, err = policy.NewHolder(c); err != nil {
			return nil, err
		}
	}
	a := &Authenticator{
		byURL:        map[string]*issuer{},
		byName:       map[string]*issuer{},
		policy:       h,
		now:          time.Now,
		oauthClients: map[string]*config.OAuthClient{},
		clientKeys:   map[string]*keySet{},
	}
	for i := range c.OAuth.Clients {
		oc := &c.OAuth.Clients[i]
		a.oauthClients[oc.ID] = oc
		if oc.JWKSURI != "" {
			a.clientKeys[oc.ID] = newKeySet("", oc.JWKSURI, client)
		}
	}
	for _, ic := range c.AllIssuers() {
		is := &issuer{cfg: ic, clients: map[string]*config.DelegatedClient{}}
		for i := range is.cfg.DelegatedClients {
			for _, id := range is.cfg.DelegatedClients[i].MatchIDs() {
				is.clients[id] = &is.cfg.DelegatedClients[i]
			}
		}
		if ic.SAML {
			a.byName[ic.Name] = is
			continue
		}
		for _, alg := range ic.Algorithms {
			is.algs = append(is.algs, jose.SignatureAlgorithm(alg))
		}
		if ic.Self {
			t, err := newTokenIssuer(ic)
			if err != nil {
				return nil, fmt.Errorf("issuer %s: %w", ic.Name, err)
			}
			a.self, is.static = t, &t.public
		} else {
			is.keys = newKeySet(ic.Issuer, ic.JWKSURL, client)
		}
		a.byURL[strings.TrimSuffix(ic.Issuer, "/")] = is
		a.byName[ic.Name] = is
	}
	for _, p := range c.Listen.TrustedProxies {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		a.trusted = append(a.trusted, pfx)
	}
	return a, nil
}

// SetClock overrides the clock (tests).
func (a *Authenticator) SetClock(now func() time.Time) {
	a.now = now
	for _, is := range a.byName {
		if is.keys != nil {
			is.keys.now = now
		}
	}
	for _, k := range a.clientKeys {
		k.now = now
	}
}

// Authenticate reads the credentials of r. Bearer tokens and virtual keys
// are exclusive. A gate API key (dgk_...) is accepted as a bearer token, as
// the password of basic authentication (user name: the key id) and in
// X-Api-Key (X-App-Id or X-Api-User, when set: the key id). Tokens of
// delegated clients are refused (not_delegable): the surfaces open to them
// call AuthenticateFor.
func (a *Authenticator) Authenticate(r *http.Request) (*identity.Subject, error) {
	return a.authenticate(r, "")
}

// AuthenticateFor is Authenticate for a surface open to delegated clients
// (scope.SurfaceAPI, scope.SurfaceMCP): a token of a delegated client is
// accepted when the client may use the surface, and its subject carries
// the client and its scopes.
func (a *Authenticator) AuthenticateFor(r *http.Request, surface string) (*identity.Subject, error) {
	return a.authenticate(r, surface)
}

func (a *Authenticator) authenticate(r *http.Request, surface string) (*identity.Subject, error) {
	authz := r.Header.Get("Authorization")
	appID, apiKey := r.Header.Get("X-App-Id"), r.Header.Get("X-Api-Key")
	switch {
	case authz != "" && (appID != "" || apiKey != ""):
		return nil, unauthorized("use either a bearer token or a virtual key, not both")
	case authz != "":
		scheme, tok, ok := strings.Cut(authz, " ")
		if ok && strings.EqualFold(scheme, "Basic") {
			audit.SetAuthMethod(r.Context(), audit.AuthAPIKey)
			user, pass, ok := basicAuth(tok)
			if !ok || !apikey.Looks(pass) {
				return nil, unauthorized("basic authentication is only accepted with a gate API key")
			}
			return a.authenticateAPIKey(r.Context(), user, pass, a.ClientIP(r))
		}
		if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
			return nil, unauthorized("bearer token expected")
		}
		tok = strings.TrimSpace(tok)
		if apikey.Looks(tok) {
			audit.SetAuthMethod(r.Context(), audit.AuthAPIKey)
			return a.authenticateAPIKey(r.Context(), "", tok, a.ClientIP(r))
		}
		return a.authenticateToken(r.Context(), tok, surface)
	case apikey.Looks(apiKey):
		audit.SetAuthMethod(r.Context(), audit.AuthAPIKey)
		user := appID
		if user == "" {
			user = r.Header.Get("X-Api-User")
		}
		return a.authenticateAPIKey(r.Context(), user, apiKey, a.ClientIP(r))
	case appID != "" || apiKey != "":
		audit.SetAuthMethod(r.Context(), audit.AuthVirtualKey)
		return a.authenticateVirtualKey(appID, apiKey, a.ClientIP(r))
	default:
		return nil, unauthorized("credentials required")
	}
}

// StripCredentials removes client credentials so they never reach EuroDNS.
func StripCredentials(h http.Header) {
	for _, k := range credentialHeaders {
		h.Del(k)
	}
}

// Middleware authenticates, stores the subject in the context and strips
// credential headers. onError writes the failure.
func (a *Authenticator) Middleware(next http.Handler, onError func(http.ResponseWriter, *http.Request, *Error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.Authenticate(r)
		if err != nil {
			var ae *Error
			if !errors.As(err, &ae) {
				ae = unauthorized("authentication failed")
			}
			onError(w, r, ae)
			return
		}
		StripCredentials(r.Header)
		next.ServeHTTP(w, r.WithContext(identity.With(r.Context(), s)))
	})
}

func (a *Authenticator) authenticateToken(ctx context.Context, raw, surface string) (*identity.Subject, error) {
	audit.SetAuthMethod(ctx, audit.AuthOIDC)
	tok, err := jwt.ParseSigned(raw, allAlgs)
	if err != nil {
		return nil, unauthorized("malformed token")
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, unauthorized("malformed token")
	}
	is := a.byURL[strings.TrimSuffix(unverified.Issuer, "/")]
	if is == nil {
		return nil, unauthorized("untrusted issuer")
	}
	if is.cfg.Self {
		audit.SetAuthMethod(ctx, audit.AuthGateToken)
	}
	claims, err := a.verify(ctx, is, raw, is.cfg.Audiences)
	if err != nil {
		return nil, err
	}
	if is.cfg.Self {
		if _, ok := claims[ClaimExchanged]; ok {
			audit.SetAuthMethod(ctx, audit.AuthTokenExchange)
		}
		return a.bindGateToken(ctx, claims, surface)
	}
	for name, patterns := range is.cfg.BoundClaims {
		if !claimMatches(claims[name], patterns) {
			return nil, &Error{Status: http.StatusForbidden, Reason: "bound_claims", Message: "token claims not allowed for this issuer"}
		}
	}
	client, err := a.delegatedClient(ctx, is, claims)
	if err != nil {
		return nil, err
	}
	if client != nil && (surface == "" || !slices.Contains(client.Surfaces, surface)) {
		return nil, notDelegable(client, surface)
	}
	s, err := a.bind(is, claims)
	if err != nil {
		return nil, err
	}
	delegate(s, client)
	return s, nil
}

// notDelegable is the refusal of a delegated client on a surface it may
// not use.
func notDelegable(c *config.DelegatedClient, surface string) *Error {
	where := "this endpoint"
	if surface != "" {
		where = "the " + surface + " surface"
	}
	return &Error{Status: http.StatusForbidden, Reason: "not_delegable", Message: "client " + c.ID + " may not use " + where}
}

// tokenClient returns the claim naming the client a token was issued to:
// azp (v2), else appid (v1).
func tokenClient(claims map[string]any) (claim, value string) {
	if v, _ := claims["azp"].(string); v != "" {
		return "azp", v
	}
	if v, _ := claims["appid"].(string); v != "" {
		return "appid", v
	}
	return "", ""
}

// delegatedClient returns the delegated client of the issuer a token was
// issued to, nil when none matches. With require_known_client a token of
// another client is refused. The audit of the request records the client.
func (a *Authenticator) delegatedClient(ctx context.Context, is *issuer, claims map[string]any) (*config.DelegatedClient, error) {
	if len(is.cfg.DelegatedClients) == 0 {
		return nil, nil
	}
	claim, value := tokenClient(claims)
	if c := is.clients[strings.ToLower(value)]; c != nil && claim != "" {
		audit.SetAuthMethod(ctx, audit.AuthOAuthDelegated)
		audit.SetClient(ctx, c.ID, clientName(c))
		return c, nil
	}
	if is.cfg.RequireKnownClient {
		if claim == "" {
			return nil, &Error{Status: http.StatusForbidden, Reason: "unknown_client", Message: "issuer " + is.cfg.Name + " requires a known client: the token has no azp or appid claim"}
		}
		shown := audit.Truncate(value, 128)
		a.warnOnce("client:"+is.cfg.Name+":"+shown, "token of an undeclared client refused (require_known_client)", "issuer", is.cfg.Name, claim, shown)
		return nil, &Error{Status: http.StatusForbidden, Reason: "unknown_client", Message: "issuer " + is.cfg.Name + " requires a known client: " + claim + " " + shown + " is not a delegated client"}
	}
	if claim != "" {
		shown := audit.Truncate(value, 128)
		a.warnOnce("client:"+is.cfg.Name+":"+shown, "token of a client that is not a delegated client: it holds the full rights of its user (declare it in delegated_clients, or set require_known_client)", "issuer", is.cfg.Name, claim, shown)
	}
	return nil, nil
}

// delegate caps a subject to a delegated client.
func delegate(s *identity.Subject, c *config.DelegatedClient) {
	if c == nil {
		return
	}
	s.Client = &identity.Client{ID: c.ID, Name: clientName(c), Zones: append([]string(nil), c.Zones...), Surfaces: append([]string(nil), c.Surfaces...)}
	s.Scopes = append([]string(nil), c.Scopes...)
	slices.Sort(s.Scopes)
}

func clientName(c *config.DelegatedClient) string {
	if c.Name == "" {
		return c.ID
	}
	return c.Name
}

// clientByID returns the delegated client id of the named issuer.
func (a *Authenticator) clientByID(issuerName, id string) *config.DelegatedClient {
	is := a.byName[issuerName]
	if is == nil {
		return nil
	}
	for i := range is.cfg.DelegatedClients {
		if is.cfg.DelegatedClients[i].ID == id {
			return &is.cfg.DelegatedClients[i]
		}
	}
	return nil
}

// VerifyToken verifies a token of the named issuer for the given audiences
// and returns its claims. Used by the UI login for ID tokens.
func (a *Authenticator) VerifyToken(ctx context.Context, issuerName, raw string, audiences []string) (map[string]any, error) {
	is := a.byName[issuerName]
	if is == nil || is.cfg.SAML {
		return nil, unauthorized("unknown issuer")
	}
	return a.verify(ctx, is, raw, audiences)
}

func (a *Authenticator) verify(ctx context.Context, is *issuer, raw string, audiences []string) (map[string]any, error) {
	tok, err := jwt.ParseSigned(raw, is.algs)
	if err != nil {
		return nil, unauthorized("token algorithm not allowed")
	}
	if len(tok.Headers) != 1 {
		return nil, unauthorized("malformed token")
	}
	key := is.static
	if key == nil {
		key, err = is.keys.key(ctx, tok.Headers[0].KeyID)
		if err != nil {
			return nil, unauthorized("signing key not found")
		}
	} else if tok.Headers[0].KeyID != key.KeyID {
		return nil, unauthorized("signing key not found")
	}
	var std jwt.Claims
	claims := map[string]any{}
	if err := tok.Claims(key.Key, &std, &claims); err != nil {
		return nil, unauthorized("invalid signature")
	}
	if std.Expiry == nil {
		return nil, unauthorized("token without expiry")
	}
	exp := jwt.Expected{Issuer: is.cfg.Issuer, AnyAudience: jwt.Audience(audiences), Time: a.now()}
	if err := std.ValidateWithLeeway(exp, is.cfg.ClockSkew.D()); err != nil {
		if strings.TrimSuffix(std.Issuer, "/") == strings.TrimSuffix(is.cfg.Issuer, "/") && errors.Is(err, jwt.ErrInvalidIssuer) {
			exp.Issuer = std.Issuer
			err = std.ValidateWithLeeway(exp, is.cfg.ClockSkew.D())
		}
		if err != nil {
			return nil, unauthorized(fmt.Sprintf("token rejected: %v", err))
		}
	}
	return claims, nil
}

// Rebind binds a subject authenticated earlier again with the current
// policy (the approver of an ownership transfer whose apply is retried):
// a virtual key must still exist and be valid, an OIDC or SAML subject is
// bound from its recorded claims.
func (a *Authenticator) Rebind(s *identity.Subject) (*identity.Subject, error) {
	if s.Kind == identity.KindVirtualKey {
		for _, vk := range a.policy.Current().VirtualKeys() {
			if vk.ID != s.ID {
				continue
			}
			if vk.ExpiresAt != nil && !a.now().Before(*vk.ExpiresAt) {
				return nil, unauthorized("virtual key expired")
			}
			roles := append([]string(nil), vk.Roles...)
			sort.Strings(roles)
			teamRoles := map[string][]string{}
			for _, t := range vk.Teams {
				teamRoles[t] = roles
			}
			return &identity.Subject{Kind: identity.KindVirtualKey, Issuer: "virtual-key", ID: vk.ID, Claims: map[string]any{},
				Roles: roles, Teams: append([]string(nil), vk.Teams...), TeamRoles: teamRoles, Name: vk.ID, Category: identity.CategoryKey}, nil
		}
		return nil, unauthorized("virtual key removed")
	}
	if s.Kind == identity.KindAPIKey {
		if a.keys == nil {
			return nil, unauthorized("API keys are not enabled")
		}
		k, err := a.keys.GetAPIKey(context.Background(), s.ID)
		if err != nil {
			return nil, unauthorized("API key not found")
		}
		snap := a.policy.Current()
		switch {
		case k.RevokedAt != nil:
			return nil, unauthorized("API key revoked")
		case k.ExpiresAt != nil && !a.now().Before(*k.ExpiresAt):
			return nil, unauthorized("API key expired")
		case !snap.HasRole(k.Role) || snap.RoleReserved(k.Role) || (snap.StrictTeams() && !snap.TeamDeclared(k.Team)):
			return nil, unauthorized("the role or the team of this API key is no longer valid")
		}
		return &identity.Subject{Kind: identity.KindAPIKey, Issuer: APIKeyIssuer, ID: k.ID, Claims: map[string]any{}, Roles: []string{k.Role},
			Teams: []string{k.Team}, TeamRoles: map[string][]string{k.Team: {k.Role}}, Name: s.Name, Category: identity.CategoryKey}, nil
	}
	b, err := a.SubjectFromClaims(s.Issuer, s.Claims, s.Category)
	if err != nil || s.Client == nil {
		return b, err
	}
	if s.Client.Grant != "" {
		oc := a.oauthClients[s.Client.ID]
		if oc == nil || oc.Disabled {
			return nil, unauthorized("OAuth client " + s.Client.ID + " removed or disabled")
		}
		ctx := context.Background()
		if err := a.checkGrant(ctx, s.Client.Grant, oc.ID, b.String()); err != nil {
			return nil, err
		}
		a.delegateOAuth(ctx, b, oc, s.Client.Grant, s.Scopes)
		return b, nil
	}
	c := a.clientByID(s.Issuer, s.Client.ID)
	if c == nil {
		return nil, unauthorized("delegated client " + s.Client.ID + " removed")
	}
	delegate(b, c)
	return b, nil
}

// SubjectFromClaims binds verified claims of the named issuer. category
// overrides the issuer category when not empty (UI sessions are human).
func (a *Authenticator) SubjectFromClaims(issuerName string, claims map[string]any, category string) (*identity.Subject, error) {
	is := a.byName[issuerName]
	if is == nil {
		return nil, unauthorized("unknown issuer")
	}
	for name, patterns := range is.cfg.BoundClaims {
		if !claimMatches(claims[name], patterns) {
			return nil, &Error{Status: http.StatusForbidden, Reason: "bound_claims", Message: "token claims not allowed for this issuer"}
		}
	}
	s, err := a.bind(is, claims)
	if err != nil {
		return nil, err
	}
	if category != "" {
		s.Category = category
	}
	return s, nil
}

func (a *Authenticator) bind(is *issuer, claims map[string]any) (*identity.Subject, error) {
	id, err := subjectID(is.cfg, claims)
	if err != nil {
		return nil, unauthorized(err.Error())
	}
	s := &identity.Subject{
		Kind:     identity.KindOIDC,
		Issuer:   is.cfg.Name,
		ID:       id,
		Claims:   claims,
		Name:     id,
		Category: is.cfg.Category,
		Email:    subjectEmail(is.cfg, claims),
	}
	if is.cfg.CategoryClaim != "" {
		if v, ok := claims[is.cfg.CategoryClaim].(string); ok {
			if cat, ok := is.cfg.CategoryMap[v]; ok {
				s.Category = cat
			}
		}
	}
	if is.cfg.NameClaim != "" {
		if n, ok := claims[is.cfg.NameClaim].(string); ok && n != "" {
			s.Name = n
		}
	}
	return a.resolve(a.policy.Current(), is, s, claims)
}

// resolve applies the bindings of a snapshot to an OIDC subject.
func (a *Authenticator) resolve(snap *policy.Snapshot, is *issuer, s *identity.Subject, claims map[string]any) (*identity.Subject, error) {
	res := snap.Resolve(is.cfg.Name, claims)
	s.Roles, s.Teams, s.Groups, s.Delegations = res.Roles, res.Teams, res.Groups, res.Delegations
	s.TeamRoles = map[string][]string{}
	for team, roles := range res.TeamRoles {
		if team != "" {
			s.TeamRoles[team] = roles
		}
	}
	for _, ig := range res.Ignored {
		a.warnOnce("derived:"+is.cfg.Name+":"+ig, "binding ignored: its team derived from a claim is the name of a declared team", "issuer", is.cfg.Name, "binding", ig, "subject", s.ID)
	}
	teams := map[string]bool{}
	for _, t := range s.Teams {
		teams[t] = true
	}
	if is.cfg.TeamClaim != "" {
		for _, t := range policy.ClaimStrings(claims[is.cfg.TeamClaim]) {
			t = strings.ToLower(t)
			if t != "" {
				t = is.cfg.TeamClaimPrefix + t
			}
			if t != "" && !teams[t] && !snap.ClaimTeamAllowed(is.cfg.Name, t) {
				a.warnOnce("claim:"+is.cfg.Name+":"+t, "team claim value ignored: not a member of a team_from family, or the name of a declared team", "issuer", is.cfg.Name, "team", t)
				continue
			}
			if t != "" && !teams[t] {
				teams[t] = true
				s.Teams = append(s.Teams, t)
				s.TeamRoles[t] = res.TeamRoles[""]
			}
		}
	}
	if len(s.Roles) == 0 && len(s.Delegations) == 0 {
		return nil, &Error{Status: http.StatusForbidden, Reason: "no_binding", Message: "no role is bound to this identity"}
	}
	sort.Strings(s.Roles)
	return s, nil
}

// subjectID resolves the subject id from subject_claim or subject_template.
func subjectID(ic config.Issuer, claims map[string]any) (string, error) {
	if ic.SubjectTemplate != "" {
		id, err := config.RenderSubject(ic.SubjectTemplate, claims)
		if err != nil {
			return "", fmt.Errorf("token subject: %v", err)
		}
		return id, nil
	}
	name := ic.SubjectClaim
	if name == "" {
		name = "sub"
	}
	id, _ := claims[name].(string)
	if id == "" {
		return "", fmt.Errorf("token without %s claim", name)
	}
	return id, nil
}

func bindingMatches(b config.Binding, issuerName string, claims map[string]any) bool {
	for _, subj := range b.Subjects {
		if subj.Issuer != issuerName {
			continue
		}
		ok := true
		for name, patterns := range subj.Claims {
			if !claimMatches(claims[name], patterns) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func claimMatches(v any, patterns []string) bool { return policy.ClaimMatches(v, patterns) }

func (a *Authenticator) authenticateVirtualKey(appID, apiKey string, ip netip.Addr) (*identity.Subject, error) {
	if appID == "" || apiKey == "" {
		return nil, unauthorized("X-APP-ID and X-API-KEY required")
	}
	sum := sha256.Sum256([]byte(apiKey))
	keys := a.policy.Current().VirtualKeys()
	var match *uiapi.VirtualKey
	for i := range keys {
		vk := &keys[i]
		want, err := hex.DecodeString(vk.KeySHA256)
		if err != nil {
			continue
		}
		appOK := subtle.ConstantTimeCompare([]byte(vk.AppID), []byte(appID)) == 1
		keyOK := subtle.ConstantTimeCompare(want, sum[:]) == 1
		if appOK && keyOK {
			match = vk
		}
	}
	if match == nil {
		return nil, unauthorized("invalid virtual key")
	}
	if match.ExpiresAt != nil && !a.now().Before(*match.ExpiresAt) {
		return nil, unauthorized("virtual key expired")
	}
	if len(match.AllowedCIDRs) > 0 {
		allowed := false
		for _, c := range match.AllowedCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && ip.IsValid() && p.Contains(ip) {
				allowed = true
			}
		}
		if !allowed {
			return nil, &Error{Status: http.StatusForbidden, Reason: "source_ip", Message: "virtual key not allowed from this address"}
		}
	}
	roles := append([]string(nil), match.Roles...)
	sort.Strings(roles)
	teamRoles := map[string][]string{}
	for _, t := range match.Teams {
		teamRoles[t] = roles
	}
	return &identity.Subject{
		Kind:      identity.KindVirtualKey,
		Issuer:    "virtual-key",
		ID:        match.ID,
		Claims:    map[string]any{},
		Roles:     roles,
		Teams:     append([]string(nil), match.Teams...),
		TeamRoles: teamRoles,
		Name:      match.ID,
		Category:  identity.CategoryKey,
	}, nil
}

// ClientIP returns the caller address, honouring X-Forwarded-For only when
// the direct peer is a trusted proxy (rightmost untrusted hop wins).
func (a *Authenticator) ClientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if !a.isTrusted(peer) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		ip = ip.Unmap()
		if !a.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

func (a *Authenticator) isTrusted(ip netip.Addr) bool {
	for _, p := range a.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var allAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}
