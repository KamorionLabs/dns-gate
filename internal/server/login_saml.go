package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/KamorionLabs/dns-gate/internal/identitystore"
	"github.com/KamorionLabs/dns-gate/internal/samlauth"
)

// GroupLookup resolves the groups of a SAML user server-side (AWS IAM
// Identity Center identity store).
type GroupLookup interface {
	Groups(ctx context.Context, user string) ([]string, error)
}

// samlLogin sends the browser to the IdP with an AuthnRequest whose id is
// kept in the sealed login cookie, to be matched by the response.
func (u *uiAuth) samlLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	q := r.URL.Query()
	next := q.Get("return_to")
	if next == "" {
		next = q.Get("next")
	}
	reauth := q.Get("reauth") == "1"
	relay := randomToken()
	req, err := u.saml.AuthnRequest(r.Context(), relay, reauth)
	if err != nil {
		u.logError("saml login", err)
		writeError(w, http.StatusBadGateway, "idp_unavailable", "identity provider unavailable")
		return
	}
	st := loginState{Reauth: reauth, State: relay, RequestID: req.ID, Next: safeNext(next), Expires: u.now().Add(loginTTL).Unix()}
	val, err := u.sealer.seal(u.cookies.login, st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	http.SetCookie(w, u.cookies.crossSite(u.cookies.login, val, loginTTL))
	if req.RedirectURL != "" {
		http.Redirect(w, r, req.RedirectURL, http.StatusFound)
		return
	}
	page, hash := samlauth.PostForm(req)
	action := req.PostURL
	if pu, err := url.Parse(req.PostURL); err == nil {
		action = pu.Scheme + "://" + pu.Host
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src '"+hash+"'; form-action "+action+"; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

// samlACS validates the response the IdP posts back and opens the session.
func (u *uiAuth) samlACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	c, err := r.Cookie(u.cookies.login)
	if err != nil {
		if r.ParseForm() == nil && samlauth.Unsolicited(r.PostForm.Get("SAMLResponse")) {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		writeError(w, http.StatusBadRequest, "login_state", "login state missing, restart the login from the gate")
		return
	}
	http.SetCookie(w, u.cookies.clearCrossSite(u.cookies.login))
	var st loginState
	if err := u.sealer.open(u.cookies.login, c.Value, &st); err != nil || u.now().Unix() > st.Expires || st.RequestID == "" {
		writeError(w, http.StatusBadRequest, "login_state", "login state invalid or expired")
		return
	}
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid form")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("RelayState")), []byte(st.State)) != 1 {
		writeError(w, http.StatusBadRequest, "login_state", "relay state mismatch")
		return
	}
	res, err := u.saml.ParseResponse(r.Context(), r.PostForm.Get("SAMLResponse"), st.RequestID)
	if err != nil {
		u.logWarn("saml response rejected", err)
		writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid SAML response")
		return
	}
	claims, amr, base, err := u.samlClaims(r.Context(), res)
	if err != nil {
		u.logError("saml groups", err)
		writeError(w, http.StatusBadGateway, "groups_unavailable", "group membership unavailable")
		return
	}
	now := u.now()
	exp := now.Add(u.cfg.SessionTTL.D())
	if !res.SessionNotOnOrAfter.IsZero() && res.SessionNotOnOrAfter.Before(exp) {
		exp = res.SessionNotOnOrAfter
	}
	if !exp.After(now) {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "the identity provider session has ended")
		return
	}
	sess := session{Issuer: u.issuer.Name, Claims: claims, Expires: exp.Unix(), AMR: amr}
	if u.storeGroups() {
		sess.StoreGroups, sess.BaseGroups = true, base
	}
	if !res.AuthnInstant.IsZero() {
		sess.AuthTime = res.AuthnInstant.Unix()
	} else if st.Reauth {
		sess.AuthTime = now.Unix()
	}
	u.establish(w, r, sess, st.Next)
}

// samlClaims maps a validated assertion to session claims: "sub" is the
// NameID, mapped attributes become claims ("groups" always a list, merged
// with the identity store groups), an "amr" mapping and the authentication
// context class go to the AMR list. base are the groups of the assertion.
func (u *uiAuth) samlClaims(ctx context.Context, res *samlauth.Result) (map[string]any, []string, []string, error) {
	cfg := u.cfg.SAML
	claims := map[string]any{"sub": res.NameID}
	for claim, attr := range cfg.SAMLAttributes() {
		vals := res.Attributes[attr]
		switch {
		case len(vals) == 0:
		case len(vals) == 1 && claim != "groups":
			claims[claim] = vals[0]
		default:
			claims[claim] = anyList(vals)
		}
	}
	base := policyClaimStrings(claims["groups"])
	if _, err := u.mergeStoreGroups(ctx, claims, base); err != nil {
		return nil, nil, nil, err
	}
	var amr []string
	if v, ok := claims["amr"]; ok {
		amr = policyClaimStrings(v)
		delete(claims, "amr")
	}
	if res.AuthnContext != "" {
		amr = append(amr, res.AuthnContext)
	}
	for k := range claims {
		if protocolClaims[k] {
			delete(claims, k)
		}
	}
	return claims, amr, base, nil
}

// storeGroups reports whether the groups of SAML users come from the
// identity store.
func (u *uiAuth) storeGroups() bool {
	return u.saml != nil && u.groups != nil && u.cfg.SAML.GroupsFromIdentityStore != nil
}

// mergeStoreGroups sets the "groups" claim to base merged with the groups
// of the user in the identity store, when configured. found is false when
// the identity store does not know the user.
func (u *uiAuth) mergeStoreGroups(ctx context.Context, claims map[string]any, base []string) (found bool, err error) {
	if !u.storeGroups() {
		return true, nil
	}
	user, _ := claims[u.cfg.SAML.GroupsFromIdentityStore.UserClaim].(string)
	names, err := u.groups.Groups(ctx, user)
	if err != nil && !errors.Is(err, identitystore.ErrUserNotFound) {
		return false, err
	}
	found = err == nil
	merged := append([]string(nil), base...)
	seen := map[string]bool{}
	for _, g := range merged {
		seen[g] = true
	}
	for _, g := range names {
		if !seen[g] {
			seen[g] = true
			merged = append(merged, g)
		}
	}
	if len(merged) > 0 {
		claims["groups"] = anyList(merged)
	} else {
		delete(claims, "groups")
	}
	return found, nil
}

func anyList(vals []string) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

// samlMetadata serves the SP metadata (entity id, ACS URL, signing
// certificate when configured).
func (u *uiAuth) samlMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	md, err := u.saml.Metadata()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(md)
}

func (u *uiAuth) logError(msg string, err error) {
	if u.log != nil {
		u.log.Error(msg, "err", err)
	}
}

func (u *uiAuth) logWarn(msg string, err error) {
	if u.log != nil {
		u.log.Warn(msg, "err", err)
	}
}
