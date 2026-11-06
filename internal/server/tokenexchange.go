package server

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
)

// TokenExchangePath serves the OAuth 2.0 token exchange (RFC 8693): a token
// of an issuer with token_exchange: true is exchanged for a short-lived gate
// token with the same identity, for clients that keep a credential for
// minutes (acme.sh, certbot hooks) while the CI or workload token lasts less.
const TokenExchangePath = "/api/v1/token-exchange"

const (
	grantTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"

	// DefaultExchangeTTL is the lifetime of an exchanged token when the
	// request names none; token_ttl of the gate issuer caps it.
	DefaultExchangeTTL = 15 * time.Minute
	minExchangeTTL     = time.Minute
)

// FeatureTokenExchange is advertised when the token exchange is served.
const FeatureTokenExchange = "token-exchange"

type exchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// tokenExchange reports whether the gate exchanges tokens: a gate issuer
// and at least one issuer with token_exchange.
func (s *Server) tokenExchange() bool {
	if s.cfg.Authn.TokenIssuer() == nil {
		return false
	}
	for _, is := range s.cfg.Config.Issuers {
		if is.TokenExchange {
			return true
		}
	}
	return false
}

func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, code, desc string) {
		writeJSON(w, status, oauthError{Error: code, Description: desc})
	}
	if r.Method != http.MethodPost {
		fail(http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	if !s.tokenExchange() {
		fail(http.StatusNotFound, "token_exchange_disabled", "the token exchange needs a gate issuer (self: true) and issuers with token_exchange: true")
		return
	}
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			return
		}
		fail(http.StatusBadRequest, "invalid_request", "form-encoded body expected")
		return
	}
	f := r.PostForm
	if f.Get("grant_type") != grantTokenExchange {
		fail(http.StatusBadRequest, "unsupported_grant_type", "grant_type must be "+grantTokenExchange)
		return
	}
	switch f.Get("subject_token_type") {
	case tokenTypeJWT, tokenTypeAccessToken, tokenTypeIDToken:
	default:
		fail(http.StatusBadRequest, "invalid_request", "subject_token_type must be a JWT, access token or ID token type")
		return
	}
	issued := tokenTypeAccessToken
	switch rt := f.Get("requested_token_type"); rt {
	case "", tokenTypeAccessToken:
	case tokenTypeJWT:
		issued = tokenTypeJWT
	default:
		fail(http.StatusBadRequest, "invalid_request", "requested_token_type must be an access token or a JWT")
		return
	}
	if f.Get("actor_token") != "" {
		fail(http.StatusBadRequest, "invalid_request", "delegation (actor_token) is not supported")
		return
	}
	t := s.cfg.Authn.TokenIssuer()
	ttl := DefaultExchangeTTL
	if v := f.Get("expires_in"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || time.Duration(n)*time.Second < minExchangeTTL {
			fail(http.StatusBadRequest, "invalid_request", "expires_in: seconds, at least 60")
			return
		}
		ttl = time.Duration(n) * time.Second
	}
	if ttl > t.TTL() {
		ttl = t.TTL()
	}
	x, err := s.cfg.Authn.ExchangeToken(r.Context(), f.Get("subject_token"))
	if err != nil {
		var ae *authn.Error
		if !errors.As(err, &ae) {
			ae = &authn.Error{Reason: "unauthenticated", Message: "token rejected"}
		}
		s.audit(r, nil, "gate.token.exchange", "", "deny", ae.Reason)
		fail(http.StatusBadRequest, "invalid_grant", ae.Message)
		return
	}
	now := s.now()
	tok, err := t.IssueExchanged(x, ttl, now)
	if err != nil {
		s.log.Error("token exchange", "err", err)
		fail(http.StatusInternalServerError, "server_error", "")
		return
	}
	subj := x.Subject
	s.cfg.Audit.Log(r.Context(), audit.Event{
		Time: now.UTC(), RequestID: requestid.From(r.Context()), Action: "gate.token.exchange", Decision: "allow",
		Subject: subj.String(), SubjectName: subj.Name, SubjectCategory: subj.Category, Teams: subj.Teams,
		Extra: map[string]any{"jti": tok.ID, "expires_at": tok.Expires.UTC().Format(time.RFC3339), "subject_token_jti": x.TokenID},
	})
	writeJSON(w, http.StatusOK, exchangeResponse{
		AccessToken: tok.Raw, IssuedTokenType: issued, TokenType: "Bearer", ExpiresIn: int64(tok.Expires.Sub(now).Seconds()),
	})
}
