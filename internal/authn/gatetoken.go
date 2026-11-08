package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

// Claims of gate-issued tokens besides the registered ones.
const (
	// ClaimOrigin names the issuer the session came from: the token is
	// bound as that issuer, so the same bindings apply.
	ClaimOrigin = "gate_iss"
	// ClaimCategory carries the subject category of the session.
	ClaimCategory = "gate_cat"
	// ClaimClientID, ClaimScope, ClaimGrant and ClaimActor mark a token
	// issued to a declared OAuth client (oauth.clients): the client, the
	// scopes consented to, the grant and the acting party (RFC 8693).
	ClaimClientID = "client_id"
	ClaimScope    = "scope"
	ClaimGrant    = "gate_grant"
	ClaimActor    = "act"
)

// registeredClaims are set by the gate and never copied from a session.
var registeredClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"auth_time": true, "amr": true, ClaimOrigin: true, ClaimCategory: true, ClaimExchanged: true,
	ClaimClientID: true, ClaimScope: true, ClaimGrant: true, ClaimActor: true, "may_act": true, "cnf": true,
}

// TokenIssuer signs the gate's own access tokens (issuer with self: true).
type TokenIssuer struct {
	name     string
	url      string
	audience string
	ttl      time.Duration
	signer   jose.Signer
	atSigner jose.Signer
	public   jose.JSONWebKey
}

// IssuedToken is a token signed by the gate.
type IssuedToken struct {
	Raw     string
	ID      string
	Subject string
	Expires time.Time
}

// TokenRequest describes the session a token is issued for.
type TokenRequest struct {
	Origin   string         // issuer name of the session
	Subject  string         // subject id, used when Claims has no "sub"
	Category string         // subject category
	Claims   map[string]any // session claims
	AuthTime int64          // last authentication at the IdP, 0 if unknown
	AMR      []string
	// MaxExpiry caps the token lifetime (end of the session), zero for none.
	MaxExpiry time.Time
	// Exchanged is the jti of the token a token exchange took, "" otherwise.
	Exchanged string
	// Client, Scopes and Grant describe a token issued to a declared OAuth
	// client (typ at+jwt, RFC 9068); Client is "" otherwise.
	Client string
	Scopes []string
	Grant  string
}

func newTokenIssuer(ic config.Issuer) (*TokenIssuer, error) {
	key, err := config.ParseTokenSigningKey(ic.SigningKey)
	if err != nil {
		return nil, err
	}
	alg := jose.EdDSA
	if _, ok := key.(*ecdsa.PrivateKey); ok {
		alg = jose.ES256
	}
	pub := jose.JSONWebKey{Key: key.Public(), Algorithm: string(alg), Use: "sig"}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: pub.KeyID}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	atSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: pub.KeyID}}, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		return nil, err
	}
	ttl := ic.TokenTTL.D()
	if ttl <= 0 {
		ttl = config.DefaultTokenTTL
	}
	return &TokenIssuer{name: ic.Name, url: ic.Issuer, audience: ic.Audiences[0], ttl: ttl, signer: signer, atSigner: atSigner, public: pub}, nil
}

// TokenIssuer returns the gate's token issuer, nil when none is configured.
func (a *Authenticator) TokenIssuer() *TokenIssuer { return a.self }

// Name is the configured name of the gate issuer.
func (t *TokenIssuer) Name() string { return t.name }

// URL is the issuer URL (the public origin of the gate).
func (t *TokenIssuer) URL() string { return t.url }

// TTL is the lifetime of issued tokens.
func (t *TokenIssuer) TTL() time.Duration { return t.ttl }

// JWKS returns the public key set of the gate issuer.
func (t *TokenIssuer) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{t.public}}
}

// Issue signs an access token for a session.
func (t *TokenIssuer) Issue(req TokenRequest, now time.Time) (*IssuedToken, error) {
	if req.Origin == "" {
		return nil, errors.New("token origin required")
	}
	exp := now.Add(t.ttl)
	if !req.MaxExpiry.IsZero() && req.MaxExpiry.Before(exp) {
		exp = req.MaxExpiry
	}
	if !exp.After(now) {
		return nil, errors.New("session expired")
	}
	claims := map[string]any{}
	for k, v := range req.Claims {
		if !registeredClaims[k] {
			claims[k] = v
		}
	}
	if s, _ := claims["sub"].(string); s == "" {
		if req.Subject == "" {
			return nil, errors.New("token subject required")
		}
		claims["sub"] = req.Subject
	}
	claims[ClaimOrigin] = req.Origin
	if req.Category != "" {
		claims[ClaimCategory] = req.Category
	}
	if req.AuthTime > 0 {
		claims["auth_time"] = req.AuthTime
	}
	if len(req.AMR) > 0 {
		claims["amr"] = req.AMR
	}
	if req.Exchanged != "" {
		claims[ClaimExchanged] = req.Exchanged
	}
	signer := t.signer
	if req.Client != "" {
		if req.Grant == "" || req.Exchanged != "" {
			return nil, errors.New("a client token needs a grant and is never exchanged")
		}
		claims[ClaimClientID] = req.Client
		claims[ClaimActor] = map[string]any{"sub": "client:" + req.Client}
		claims[ClaimScope] = strings.Join(req.Scopes, " ")
		claims[ClaimGrant] = req.Grant
		signer = t.atSigner
	}
	id := randomID()
	std := jwt.Claims{
		Issuer: t.url, Audience: jwt.Audience{t.audience}, ID: id,
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(exp),
	}
	raw, err := jwt.Signed(signer).Claims(std).Claims(claims).Serialize()
	if err != nil {
		return nil, err
	}
	sub, _ := claims["sub"].(string)
	return &IssuedToken{Raw: raw, ID: id, Subject: sub, Expires: exp}, nil
}

// bindGateToken binds the verified claims of a gate token as the issuer of
// the session it was issued for. A token of a declared OAuth client is
// accepted on the surfaces of the client only, while the client is enabled
// and its grant active; its subject carries the client and the consented
// scopes, capped by the current scopes of the client.
func (a *Authenticator) bindGateToken(ctx context.Context, claims map[string]any, surface string) (*identity.Subject, error) {
	origin, _ := claims[ClaimOrigin].(string)
	is := a.byName[origin]
	if is == nil || is.cfg.Self {
		return nil, unauthorized("gate token of an unknown issuer")
	}
	_, exchanged := claims[ClaimExchanged]
	if exchanged && !is.cfg.TokenExchange {
		return nil, unauthorized("exchanged token of an issuer without token_exchange")
	}
	clientID, hasClient := claims[ClaimClientID]
	var oc *config.OAuthClient
	if hasClient {
		id, _ := clientID.(string)
		audit.SetAuthMethod(ctx, audit.AuthOAuthDelegated)
		if oc = a.oauthClients[id]; oc == nil || id == "" || exchanged {
			return nil, unauthorized("token of an unknown OAuth client")
		}
		audit.SetClient(ctx, oc.ID, oc.Name)
		if oc.Disabled {
			return nil, unauthorized("OAuth client " + oc.ID + " is disabled")
		}
		if surface == "" || !slices.Contains(oc.Surfaces, surface) {
			return nil, &Error{Status: http.StatusForbidden, Reason: "not_delegable", Message: "client " + oc.ID + " may not use " + surfaceName(surface)}
		}
	}
	cat, _ := claims[ClaimCategory].(string)
	if cat != identity.CategoryHuman && cat != identity.CategoryPipeline {
		cat = ""
	}
	s, err := a.SubjectFromClaims(origin, claims, cat)
	if err != nil || oc == nil {
		return s, err
	}
	grant, _ := claims[ClaimGrant].(string)
	scopeClaim, _ := claims[ClaimScope].(string)
	if err := a.checkGrant(ctx, grant, oc.ID, s.String()); err != nil {
		return nil, err
	}
	a.delegateOAuth(ctx, s, oc, grant, strings.Fields(scopeClaim))
	return s, nil
}

// GateTokenClaims verifies a token signed by the gate (signature, issuer,
// audience, expiry) and returns its claims.
func (a *Authenticator) GateTokenClaims(ctx context.Context, raw string) (map[string]any, error) {
	if a.self == nil {
		return nil, unauthorized("no gate issuer")
	}
	is := a.byURL[strings.TrimSuffix(a.self.url, "/")]
	if is == nil {
		return nil, unauthorized("no gate issuer")
	}
	return a.verify(ctx, is, raw, is.cfg.Audiences)
}

func surfaceName(surface string) string {
	if surface == "" {
		return "this endpoint"
	}
	return "the " + surface + " surface"
}

// delegateOAuth caps a subject to a declared OAuth client: the scopes of
// the grant that the client still holds.
func (a *Authenticator) delegateOAuth(ctx context.Context, s *identity.Subject, oc *config.OAuthClient, grant string, scopes []string) {
	s.Client = &identity.Client{ID: oc.ID, Name: oc.Name, Zones: append([]string(nil), oc.Zones...), Surfaces: append([]string(nil), oc.Surfaces...),
		Grant: grant, WriteMaxAge: oc.WriteMaxAge.D()}
	s.Scopes = []string{}
	for _, sc := range scopes {
		if slices.Contains(oc.Scopes, sc) && !slices.Contains(s.Scopes, sc) {
			s.Scopes = append(s.Scopes, sc)
		}
	}
	slices.Sort(s.Scopes)
	audit.SetGrant(ctx, grant, s.Scopes)
}

// OAuthGrants reads the grants of the gate authorization server
// (store.OAuthStore).
type OAuthGrants interface {
	GetOAuthGrant(ctx context.Context, id string) (*store.OAuthGrant, error)
}

// SetOAuthGrants enables the tokens of declared OAuth clients: their grant
// is checked on every request (cached GrantCacheTTL).
func (a *Authenticator) SetOAuthGrants(g OAuthGrants) { a.grants = g }

// GrantCacheTTL is how long the state of a grant is cached per process: a
// revocation reaches the other replicas within it.
const GrantCacheTTL = 30 * time.Second

const maxGrantCache = 4096

type grantState struct {
	client, subject string
	expires         time.Time
	revoked         bool
	at              time.Time
}

type grantCache struct {
	mu sync.Mutex
	m  map[string]grantState
}

// InvalidateGrant drops the cached state of a grant (revoked here).
func (a *Authenticator) InvalidateGrant(id string) {
	a.grantCache.mu.Lock()
	delete(a.grantCache.m, id)
	a.grantCache.mu.Unlock()
}

func (a *Authenticator) checkGrant(ctx context.Context, id, client, subject string) error {
	if id == "" || a.grants == nil {
		return unauthorized("token without an OAuth grant")
	}
	now := a.now()
	c := &a.grantCache
	c.mu.Lock()
	st, ok := c.m[id]
	c.mu.Unlock()
	if !ok || now.Sub(st.at) > GrantCacheTTL || now.Before(st.at) {
		g, err := a.grants.GetOAuthGrant(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			st = grantState{revoked: true, at: now}
		case err != nil:
			return &Error{Status: http.StatusServiceUnavailable, Reason: "unavailable", Message: "OAuth grant lookup failed"}
		default:
			st = grantState{client: g.ClientID, subject: g.Subject, expires: g.ExpiresAt, revoked: g.RevokedAt != nil, at: now}
		}
		c.mu.Lock()
		if c.m == nil || len(c.m) >= maxGrantCache {
			c.m = map[string]grantState{}
		}
		c.m[id] = st
		c.mu.Unlock()
	}
	if st.revoked || !now.Before(st.expires) || st.client != client || st.subject != subject {
		return unauthorized("OAuth grant revoked or expired")
	}
	return nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
