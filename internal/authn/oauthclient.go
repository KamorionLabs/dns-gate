package authn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/requestid"
)

// ClientAssertionType is the client_assertion_type of private_key_jwt
// (RFC 7523).
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// MaxAssertionLifetime bounds the expiry of a client assertion.
const MaxAssertionLifetime = 5 * time.Minute

// ClientError is a failed client authentication: Code is the OAuth error
// (invalid_client, invalid_request), Basic tells whether the client used
// HTTP Basic (the answer then carries WWW-Authenticate).
type ClientError struct {
	Code, Message string
	Basic         bool
	Unavailable   bool
}

func (e *ClientError) Error() string { return e.Code + ": " + e.Message }

// UseJTI records the id of a client assertion until exp; it fails for a
// replay.
type UseJTI func(ctx context.Context, key string, exp time.Time) error

// ErrReplay is returned by a UseJTI for an assertion id already used.
var ErrReplay = errors.New("assertion replayed")

// OAuthClient returns a declared OAuth client, nil when unknown.
func (a *Authenticator) OAuthClient(id string) *config.OAuthClient { return a.oauthClients[id] }

// AuthenticateClient authenticates the client of a token or revocation
// request (RFC 6749 2.3, RFC 7523): client_secret_basic or
// client_secret_post (both accepted for a client with a secret),
// private_key_jwt (aud: one of audiences, jti recorded through useJTI), or
// client_id alone for a public client. Failures are audited
// (oauth.client_auth), aggregated per client, source and minute.
func (a *Authenticator) AuthenticateClient(r *http.Request, form url.Values, audiences []string, useJTI UseJTI) (*config.OAuthClient, *ClientError) {
	ctx := r.Context()
	id, secret, basic, cerr := clientCredentials(r, form)
	if cerr != nil {
		return nil, a.clientFailure(r, id, cerr)
	}
	assertion := form.Get("client_assertion")
	if assertion != "" {
		if form.Get("client_assertion_type") != ClientAssertionType {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "unsupported client_assertion_type"})
		}
		if basic || secret != "" {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_request", Message: "several client authentication methods"})
		}
		sub := assertionSubject(assertion)
		if id == "" {
			id = sub
		} else if sub != id {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "client_id and the assertion subject differ"})
		}
	}
	oc := a.oauthClients[id]
	if id == "" || oc == nil || oc.Disabled {
		return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "unknown or disabled client", Basic: basic})
	}
	switch {
	case oc.UsesSecret():
		if secret == "" || assertion != "" {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "client secret required", Basic: basic})
		}
		got, want := sha256.Sum256([]byte(secret)), sha256.Sum256([]byte(oc.Secret))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "invalid client secret", Basic: basic})
		}
	case oc.AuthMethod == config.OAuthPrivateKeyJWT:
		if assertion == "" {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "client assertion required", Basic: basic})
		}
		if err := a.verifyAssertion(ctx, oc, assertion, audiences, useJTI); err != nil {
			return nil, a.clientFailure(r, id, err)
		}
	default:
		if secret != "" || basic || assertion != "" {
			return nil, a.clientFailure(r, id, &ClientError{Code: "invalid_client", Message: "a public client does not authenticate", Basic: basic})
		}
	}
	return oc, nil
}

// clientCredentials reads the client id and secret of HTTP Basic or of the
// form; both at once are refused.
func clientCredentials(r *http.Request, form url.Values) (id, secret string, basic bool, err *ClientError) {
	id = form.Get("client_id")
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return id, form.Get("client_secret"), false, nil
	}
	scheme, raw, ok := strings.Cut(authz, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return id, "", false, &ClientError{Code: "invalid_client", Message: "only Basic client authentication is accepted in Authorization"}
	}
	user, pass, ok := basicAuth(raw)
	if ok {
		var e1, e2 error
		user, e1 = url.QueryUnescape(user)
		pass, e2 = url.QueryUnescape(pass)
		ok = e1 == nil && e2 == nil
	}
	if !ok || user == "" {
		return id, "", true, &ClientError{Code: "invalid_client", Message: "malformed Basic credentials", Basic: true}
	}
	if form.Get("client_secret") != "" || (id != "" && id != user) {
		return user, "", true, &ClientError{Code: "invalid_request", Message: "several client authentication methods", Basic: true}
	}
	return user, pass, true, nil
}

func assertionSubject(raw string) string {
	tok, err := jwt.ParseSigned(raw, allAlgs)
	if err != nil {
		return ""
	}
	var c jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&c); err != nil {
		return ""
	}
	return c.Subject
}

// verifyAssertion checks a private_key_jwt assertion: signed by a key of
// the client, iss = sub = client id, aud one of audiences, exp at most
// MaxAssertionLifetime ahead, jti never seen.
func (a *Authenticator) verifyAssertion(ctx context.Context, oc *config.OAuthClient, raw string, audiences []string, useJTI UseJTI) *ClientError {
	bad := func(msg string) *ClientError { return &ClientError{Code: "invalid_client", Message: msg} }
	tok, err := jwt.ParseSigned(raw, allAlgs)
	if err != nil || len(tok.Headers) != 1 {
		return bad("malformed client assertion")
	}
	key, err := a.clientKey(ctx, oc, tok.Headers[0].KeyID)
	if err != nil {
		return bad("client assertion key not found")
	}
	if key.Algorithm != "" && key.Algorithm != tok.Headers[0].Algorithm {
		return bad("client assertion algorithm does not match the key")
	}
	var c jwt.Claims
	if err := tok.Claims(key.Key, &c); err != nil {
		return bad("invalid client assertion signature")
	}
	now := a.now()
	switch {
	case c.Issuer != oc.ID || c.Subject != oc.ID:
		return bad("client assertion iss and sub must be the client id")
	case c.ID == "" || len(c.ID) > 256:
		return bad("client assertion without jti")
	case c.Expiry == nil:
		return bad("client assertion without exp")
	case c.Expiry.Time().After(now.Add(MaxAssertionLifetime + time.Minute)):
		return bad("client assertion lifetime above 5 minutes")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience(audiences), Time: now}, time.Minute); err != nil {
		return bad("client assertion rejected: " + err.Error())
	}
	if err := useJTI(ctx, oc.ID+":"+c.ID, c.Expiry.Time().Add(time.Minute)); err != nil {
		if errors.Is(err, ErrReplay) {
			return bad("client assertion replayed")
		}
		return &ClientError{Code: "invalid_client", Message: "client assertion check unavailable", Unavailable: true}
	}
	return nil
}

func (a *Authenticator) clientKey(ctx context.Context, oc *config.OAuthClient, kid string) (*jose.JSONWebKey, error) {
	if ks := a.clientKeys[oc.ID]; ks != nil {
		return ks.key(ctx, kid)
	}
	if oc.KeySet == nil {
		return nil, errors.New("no key")
	}
	set := &keySet{keys: *oc.KeySet}
	if k := set.lookup(kid); k != nil {
		return k, nil
	}
	return nil, errors.New("unknown key id")
}

// clientFailure audits a failed client authentication (oauth.client_auth),
// aggregated per declared client, source and minute (unknown client ids per
// source only), and returns e.
func (a *Authenticator) clientFailure(r *http.Request, id string, e *ClientError) *ClientError {
	if a.audit == nil || e.Unavailable {
		return e
	}
	ctx := r.Context()
	src := source(a.ClientIP(r))
	shown := audit.Truncate(id, 128)
	ev := audit.Event{
		Time: a.now().UTC(), RequestID: requestid.From(ctx), Action: "oauth.client_auth", Decision: "deny", Reason: e.Code,
		Extra: map[string]any{"message": e.Message, "remote_addr": src},
	}
	key := "|" + src
	if oc := a.oauthClients[id]; oc != nil {
		ev.SetClient(oc.ID, oc.Name)
		key = oc.ID + key
	} else if shown != "" {
		ev.Extra["client_id"] = shown
	}
	audit.Capture(ctx, &ev)
	for _, out := range a.clientNoise.note(key, a.now(), ev) {
		a.audit.Log(ctx, out)
	}
	return e
}

// SetAuditLog sets the logger of the authentication failures (also set by
// SetAPIKeys).
func (a *Authenticator) SetAuditLog(l audit.Logger) {
	if a.audit == nil {
		a.audit = l
	}
}

// OAuthClientIDs returns the ids of the declared OAuth clients, sorted.
func (a *Authenticator) OAuthClientIDs() []string {
	out := make([]string, 0, len(a.oauthClients))
	for id := range a.oauthClients {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
