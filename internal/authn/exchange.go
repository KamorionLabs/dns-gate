package authn

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/apikey"
	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/identity"
)

// ClaimExchanged marks a gate token issued by the token exchange: its value
// is the jti of the exchanged token ("-" when it had none).
const ClaimExchanged = "gate_xchg"

// Exchange is a token accepted for exchange: the subject it binds to, the
// issuer name and the claims to carry into the gate token.
type Exchange struct {
	Subject *identity.Subject
	Issuer  string
	Claims  map[string]any
	TokenID string
	// MaxTTL is the max_exchanged_ttl of the issuer, Expiry the expiry of
	// the subject token: both bound the gate token.
	MaxTTL time.Duration
	Expiry time.Time
}

// ExchangeToken validates a subject token for the token exchange exactly as
// a bearer token of its issuer (signature, audiences, bound claims,
// bindings). The issuer must have token_exchange; gate tokens and API keys
// are never exchanged.
func (a *Authenticator) ExchangeToken(ctx context.Context, raw string) (*Exchange, error) {
	audit.SetAuthMethod(ctx, audit.AuthTokenExchange)
	raw = strings.TrimSpace(raw)
	if apikey.Looks(raw) {
		return nil, unauthorized("API keys cannot be exchanged")
	}
	tok, err := jwt.ParseSigned(raw, allAlgs)
	if err != nil {
		return nil, unauthorized("malformed token")
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, unauthorized("malformed token")
	}
	is := a.byURL[strings.TrimSuffix(unverified.Issuer, "/")]
	switch {
	case is == nil:
		return nil, unauthorized("untrusted issuer")
	case is.cfg.Self:
		return nil, &Error{Status: http.StatusBadRequest, Reason: "not_exchangeable", Message: "gate tokens cannot be exchanged"}
	case !is.cfg.TokenExchange:
		return nil, &Error{Status: http.StatusBadRequest, Reason: "not_exchangeable", Message: "token exchange is not enabled for issuer " + is.cfg.Name}
	}
	claims, err := a.verify(ctx, is, raw, is.cfg.Audiences)
	if err != nil {
		return nil, err
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
	if client != nil {
		return nil, notDelegable(client, "")
	}
	s, err := a.bind(is, claims)
	if err != nil {
		return nil, err
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		jti = "-"
	}
	var exp time.Time
	if v, ok := claims["exp"].(float64); ok {
		exp = time.Unix(int64(v), 0)
	}
	return &Exchange{Subject: s, Issuer: is.cfg.Name, Claims: claims, TokenID: jti, MaxTTL: is.cfg.MaxExchangedTTL.D(), Expiry: exp}, nil
}

// IssueExchanged signs the gate token of an exchange, valid for ttl (capped
// by the token_ttl of the gate issuer).
func (t *TokenIssuer) IssueExchanged(x *Exchange, ttl time.Duration, now time.Time) (*IssuedToken, error) {
	return t.Issue(TokenRequest{
		Origin: x.Issuer, Subject: x.Subject.ID, Category: x.Subject.Category, Claims: x.Claims,
		MaxExpiry: now.Add(ttl), Exchanged: x.TokenID,
	}, now)
}

// AuthenticateBearer authenticates a bearer credential given outside the
// Authorization header (acme-dns X-Api-Key): a gate API key or a token.
func (a *Authenticator) AuthenticateBearer(r *http.Request, raw string) (*identity.Subject, error) {
	raw = strings.TrimSpace(raw)
	if apikey.Looks(raw) {
		audit.SetAuthMethod(r.Context(), audit.AuthAPIKey)
		return a.authenticateAPIKey(r.Context(), "", raw, a.ClientIP(r))
	}
	return a.authenticateToken(r.Context(), raw, "")
}
