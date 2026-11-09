package authn

import (
	"net/mail"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

const (
	// ClaimNameIDFormat is set to "email" in the claims of a SAML session
	// whose NameID has the emailAddress format.
	ClaimNameIDFormat = "name_id_format"
	// ClaimNoEmail marks a gate token whose email is no longer vouched for
	// (the claims of its grant are older than claims_max_age).
	ClaimNoEmail = "gate_no_email"
)

const (
	defaultEmailClaim         = "email"
	defaultEmailVerifiedClaim = "email_verified"
	maxEmailLen               = 254
)

// subjectEmail returns the email address the issuer vouches for, "" when
// none. SAML: the email attribute, else the NameID of the emailAddress
// format. OIDC: email_claim when email_verified_claim is true, or without
// that claim when email_trusted is true. A verification claim present and
// not true, email_trusted false or ClaimNoEmail withholds it.
func subjectEmail(ic config.Issuer, claims map[string]any) string {
	if (ic.EmailTrusted != nil && !*ic.EmailTrusted) || claimTrue(claims[ClaimNoEmail]) {
		return ""
	}
	if ic.SAML {
		if v, ok := claims[defaultEmailVerifiedClaim]; ok && !claimTrue(v) {
			return ""
		}
		if e := emailValue(claims[defaultEmailClaim]); e != "" {
			return e
		}
		if f, _ := claims[ClaimNameIDFormat].(string); f == "email" {
			return emailValue(claims["sub"])
		}
		return ""
	}
	name, verified := ic.EmailClaim, ic.EmailVerifiedClaim
	if name == "" {
		name = defaultEmailClaim
	}
	if verified == "" {
		verified = defaultEmailVerifiedClaim
	}
	e := emailValue(claims[name])
	if e == "" {
		return ""
	}
	if v, ok := claims[verified]; ok {
		if claimTrue(v) {
			return e
		}
		return ""
	}
	if ic.EmailTrusted != nil && *ic.EmailTrusted {
		return e
	}
	return ""
}

func claimTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

// emailValue returns v when it is a bare email address.
func emailValue(v any) string {
	s, _ := v.(string)
	if s == "" || len(s) > maxEmailLen || strings.TrimSpace(s) != s {
		return ""
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s || !strings.Contains(s, "@") {
		return ""
	}
	return s
}
