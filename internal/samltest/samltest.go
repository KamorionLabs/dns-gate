// Package samltest is a SAML 2.0 identity provider for tests: it publishes
// metadata and signs responses, valid or deliberately broken.
package samltest

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// IdP is a test identity provider.
type IdP struct {
	EntityID string
	SSOURL   string
	key      *rsa.PrivateKey
	cert     *x509.Certificate
}

// New returns an IdP with a fresh RSA key and self-signed certificate.
func New(entityID, ssoURL string) *IdP {
	key, cert := KeyPair("test-idp")
	return &IdP{EntityID: entityID, SSOURL: ssoURL, key: key, cert: cert}
}

// KeyPair returns an RSA key and a self-signed certificate valid for a day.
func KeyPair(cn string) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return key, cert
}

// Metadata returns the IdP metadata XML, with HTTP-Redirect and HTTP-POST
// single sign-on services at SSOURL.
func (i *IdP) Metadata() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, xmlEscape(i.EntityID), base64.StdEncoding.EncodeToString(i.cert.Raw), xmlEscape(i.SSOURL), xmlEscape(i.SSOURL))
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// Assertion describes a response to build. Zero times default to now
// (IssueInstant, AuthnInstant) and now+5m (NotOnOrAfter).
type Assertion struct {
	RequestID  string
	ACSURL     string
	Audience   string
	NameID     string
	Attributes map[string][]string

	IssueInstant time.Time
	AuthnInstant time.Time
	NotOnOrAfter time.Time
	AuthnContext string

	// SignResponse signs the Response instead of the Assertion.
	SignResponse bool
	// WrongKey signs with a key the SP does not know.
	WrongKey bool
	// Unsigned leaves the response and the assertion unsigned.
	Unsigned bool
	// Issuer overrides the IdP entity id in the response and assertion.
	Issuer string
}

// Response returns the base64 SAMLResponse for a.
func (i *IdP) Response(a Assertion) string {
	now := time.Now().UTC()
	if a.IssueInstant.IsZero() {
		a.IssueInstant = now
	}
	if a.AuthnInstant.IsZero() {
		a.AuthnInstant = a.IssueInstant
	}
	if a.NotOnOrAfter.IsZero() {
		a.NotOnOrAfter = a.IssueInstant.Add(5 * time.Minute)
	}
	if a.AuthnContext == "" {
		a.AuthnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	}
	issuer := i.EntityID
	if a.Issuer != "" {
		issuer = a.Issuer
	}
	key, cert := i.key, i.cert
	if a.WrongKey {
		key, cert = KeyPair("rogue")
	}
	assertion := &saml.Assertion{
		ID: "id-" + randomHex(), IssueInstant: a.IssueInstant, Version: "2.0",
		Issuer: saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: a.NameID},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: a.RequestID, NotOnOrAfter: a.NotOnOrAfter, Recipient: a.ACSURL,
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore: a.IssueInstant.Add(-time.Minute), NotOnOrAfter: a.NotOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: a.Audience}}},
		},
		AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant: a.AuthnInstant, SessionIndex: "s-" + randomHex(),
			AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: a.AuthnContext}},
		}},
	}
	if len(a.Attributes) > 0 {
		st := saml.AttributeStatement{}
		for name, vals := range a.Attributes {
			at := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"}
			for _, v := range vals {
				at.Values = append(at.Values, saml.AttributeValue{Type: "xs:string", Value: v})
			}
			st.Attributes = append(st.Attributes, at)
		}
		assertion.AttributeStatements = []saml.AttributeStatement{st}
	}
	ctx := signingContext(key, cert)
	assertionEl := assertion.Element()
	if !a.Unsigned && !a.SignResponse {
		signed, err := ctx.SignEnveloped(assertionEl)
		if err != nil {
			panic(err)
		}
		assertion.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
		assertionEl = assertion.Element()
	}
	resp := &saml.Response{
		ID: "id-" + randomHex(), InResponseTo: a.RequestID, IssueInstant: a.IssueInstant, Version: "2.0",
		Destination: a.ACSURL,
		Issuer:      &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer},
		Status:      saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	respEl := resp.Element()
	respEl.AddChild(assertionEl)
	if !a.Unsigned && a.SignResponse {
		signed, err := ctx.SignEnveloped(respEl)
		if err != nil {
			panic(err)
		}
		resp.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
		respEl = resp.Element()
		respEl.AddChild(assertionEl)
	}
	doc := etree.NewDocument()
	doc.SetRoot(respEl)
	out, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

func signingContext(key *rsa.PrivateKey, cert *x509.Certificate) *dsig.SigningContext {
	ks := dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key})
	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		panic(err)
	}
	return ctx
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Request is an authentication request received by the IdP.
type Request struct {
	ID         string
	ACSURL     string
	Issuer     string
	ForceAuthn bool
	RelayState string
	Signed     bool
}

// ParseRedirect decodes the AuthnRequest of an HTTP-Redirect binding URL.
func ParseRedirect(raw string) (*Request, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	data, err := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if err != nil {
		return nil, err
	}
	xmlData, err := io.ReadAll(flate.NewReader(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	var ar saml.AuthnRequest
	if err := xml.Unmarshal(xmlData, &ar); err != nil {
		return nil, err
	}
	r := &Request{ID: ar.ID, ACSURL: ar.AssertionConsumerServiceURL, RelayState: q.Get("RelayState"), Signed: q.Get("Signature") != ""}
	if ar.Issuer != nil {
		r.Issuer = ar.Issuer.Value
	}
	if ar.ForceAuthn != nil {
		r.ForceAuthn = *ar.ForceAuthn
	}
	return r, nil
}
