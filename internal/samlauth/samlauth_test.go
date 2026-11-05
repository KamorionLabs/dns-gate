package samlauth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/samltest"
)

const (
	acsURL   = "https://gate.example.com/auth/saml/acs"
	entityID = "dns-gate-test"
)

func newProvider(t *testing.T, idp *samltest.IdP, tweak func(*config.UISAML)) *Provider {
	t.Helper()
	c := config.UISAML{Issuer: "identity-center", EntityID: entityID, ACSURL: acsURL, IDPMetadata: idp.Metadata(), NameIDFormat: "email"}
	if tweak != nil {
		tweak(&c)
	}
	p, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startLogin(t *testing.T, p *Provider) *samltest.Request {
	t.Helper()
	req, err := p.AuthnRequest(context.Background(), "relay-123", false)
	if err != nil {
		t.Fatal(err)
	}
	if req.RedirectURL == "" {
		t.Fatal("redirect binding expected")
	}
	in, err := samltest.ParseRedirect(req.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if in.ID != req.ID || in.ACSURL != acsURL || in.Issuer != entityID || in.RelayState != "relay-123" || in.ForceAuthn {
		t.Fatalf("authn request: %+v", in)
	}
	return in
}

func TestParseResponse(t *testing.T) {
	idp := samltest.New("https://idp.example.com/saml", "https://idp.example.com/sso")
	p := newProvider(t, idp, nil)
	in := startLogin(t, p)
	good := samltest.Assertion{
		RequestID: in.ID, ACSURL: acsURL, Audience: entityID, NameID: "alice@example.com",
		Attributes: map[string][]string{"email": {"alice@example.com"}, "groups": {"DNS-Admins", "Ops"}},
	}

	res, err := p.ParseResponse(context.Background(), idp.Response(good), in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.NameID != "alice@example.com" || len(res.Attributes["groups"]) != 2 || res.AuthnInstant.IsZero() || !strings.Contains(res.AuthnContext, "PasswordProtectedTransport") {
		t.Fatalf("result: %+v", res)
	}
	signedResponse := good
	signedResponse.SignResponse = true
	if _, err := p.ParseResponse(context.Background(), idp.Response(signedResponse), in.ID); err != nil {
		t.Fatalf("signed response: %v", err)
	}

	cases := []struct {
		name  string
		tweak func(*samltest.Assertion)
		reqID string
	}{
		{"bad signature", func(a *samltest.Assertion) { a.WrongKey = true }, in.ID},
		{"unsigned", func(a *samltest.Assertion) { a.Unsigned = true }, in.ID},
		{"wrong audience", func(a *samltest.Assertion) { a.Audience = "other-app" }, in.ID},
		{"wrong recipient", func(a *samltest.Assertion) { a.ACSURL = "https://evil.example.com/auth/saml/acs" }, in.ID},
		{"expired", func(a *samltest.Assertion) {
			a.IssueInstant = time.Now().Add(-time.Hour)
			a.NotOnOrAfter = time.Now().Add(-55 * time.Minute)
		}, in.ID},
		{"conditions expired", func(a *samltest.Assertion) { a.NotOnOrAfter = time.Now().Add(-10 * time.Minute) }, in.ID},
		{"stale issue instant", func(a *samltest.Assertion) { a.IssueInstant = time.Now().Add(-5 * time.Minute) }, in.ID},
		{"wrong InResponseTo", func(a *samltest.Assertion) {}, "id-another-request"},
		{"wrong issuer", func(a *samltest.Assertion) { a.Issuer = "https://evil.example.com" }, in.ID},
		{"no request", func(a *samltest.Assertion) {}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := good
			c.tweak(&a)
			_, err := p.ParseResponse(context.Background(), idp.Response(a), c.reqID)
			t.Log(err)
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := p.ParseResponse(context.Background(), "%%%", in.ID); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestMetadataAndSignedRequests(t *testing.T) {
	idp := samltest.New("https://idp.example.com/saml", "https://idp.example.com/sso")
	key, cert := samltest.KeyPair("sp")
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	p := newProvider(t, idp, func(c *config.UISAML) { c.SPKey, c.SPCert = keyPEM, certPEM })

	md, err := p.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	for _, want := range []string{`entityID="dns-gate-test"`, `Location="https://gate.example.com/auth/saml/acs"`, `AuthnRequestsSigned="true"`, `use="signing"`, "emailAddress"} {
		if !strings.Contains(s, want) {
			t.Fatalf("metadata lacks %s:\n%s", want, s)
		}
	}
	if strings.Contains(s, "HTTP-Artifact") {
		t.Fatalf("artifact binding advertised:\n%s", s)
	}
	req, err := p.AuthnRequest(context.Background(), "r", true)
	if err != nil {
		t.Fatal(err)
	}
	in, err := samltest.ParseRedirect(req.RedirectURL)
	if err != nil || !in.Signed || !in.ForceAuthn {
		t.Fatalf("signed request: %+v %v", in, err)
	}

	_, other := samltest.KeyPair("other")
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw}))
	if _, err := New(config.UISAML{EntityID: entityID, ACSURL: acsURL, IDPMetadata: idp.Metadata(), SPKey: keyPEM, SPCert: otherPEM}, nil); err == nil {
		t.Fatal("mismatched key pair accepted")
	}
	if _, err := New(config.UISAML{EntityID: entityID, ACSURL: acsURL, IDPMetadata: "<x/>"}, nil); err == nil {
		t.Fatal("invalid metadata accepted")
	}
}

func TestMetadataURL(t *testing.T) {
	idp := samltest.New("https://idp.example.com/saml", "https://idp.example.com/sso")
	var hits atomic.Int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(idp.Metadata()))
	}))
	defer srv.Close()
	p, err := New(config.UISAML{EntityID: entityID, ACSURL: acsURL, IDPMetadataURL: srv.URL}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p.SetClock(func() time.Time { return now })
	for range 3 {
		if _, err := p.AuthnRequest(context.Background(), "r", false); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("metadata fetched %d times", hits.Load())
	}
	fail.Store(true)
	now = now.Add(25 * time.Hour)
	if _, err := p.AuthnRequest(context.Background(), "r", false); err != nil {
		t.Fatalf("stale metadata not kept on failure: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("metadata refresh not attempted: %d", hits.Load())
	}
}
