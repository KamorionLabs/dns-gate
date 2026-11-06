package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
)

// Claims of gate-issued tokens besides the registered ones.
const (
	// ClaimOrigin names the issuer the session came from: the token is
	// bound as that issuer, so the same bindings apply.
	ClaimOrigin = "gate_iss"
	// ClaimCategory carries the subject category of the session.
	ClaimCategory = "gate_cat"
)

// registeredClaims are set by the gate and never copied from a session.
var registeredClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"auth_time": true, "amr": true, ClaimOrigin: true, ClaimCategory: true, ClaimExchanged: true,
}

// TokenIssuer signs the gate's own access tokens (issuer with self: true).
type TokenIssuer struct {
	name     string
	url      string
	audience string
	ttl      time.Duration
	signer   jose.Signer
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
	ttl := ic.TokenTTL.D()
	if ttl <= 0 {
		ttl = config.DefaultTokenTTL
	}
	return &TokenIssuer{name: ic.Name, url: ic.Issuer, audience: ic.Audiences[0], ttl: ttl, signer: signer, public: pub}, nil
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
	id := randomID()
	std := jwt.Claims{
		Issuer: t.url, Audience: jwt.Audience{t.audience}, ID: id,
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(exp),
	}
	raw, err := jwt.Signed(t.signer).Claims(std).Claims(claims).Serialize()
	if err != nil {
		return nil, err
	}
	sub, _ := claims["sub"].(string)
	return &IssuedToken{Raw: raw, ID: id, Subject: sub, Expires: exp}, nil
}

// bindGateToken binds the verified claims of a gate token as the issuer of
// the session it was issued for.
func (a *Authenticator) bindGateToken(claims map[string]any) (*identity.Subject, error) {
	origin, _ := claims[ClaimOrigin].(string)
	is := a.byName[origin]
	if is == nil || is.cfg.Self {
		return nil, unauthorized("gate token of an unknown issuer")
	}
	if _, exchanged := claims[ClaimExchanged]; exchanged && !is.cfg.TokenExchange {
		return nil, unauthorized("exchanged token of an issuer without token_exchange")
	}
	cat, _ := claims[ClaimCategory].(string)
	if cat != identity.CategoryHuman && cat != identity.CategoryPipeline {
		cat = ""
	}
	return a.SubjectFromClaims(origin, claims, cat)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
