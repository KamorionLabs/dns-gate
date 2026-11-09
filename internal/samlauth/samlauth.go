// Package samlauth is the SAML 2.0 service provider of the UI login: it
// builds authentication requests, validates the IdP responses posted to the
// assertion consumer service and publishes the SP metadata. It keeps no
// state between requests: the request id an answer must refer to is kept
// by the caller (in the sealed login cookie).
package samlauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

const (
	maxMetadataBytes = 1 << 20
	maxResponseBytes = 512 << 10
	metadataMaxAge   = 24 * time.Hour
	metadataRetry    = time.Minute
	bearerMethod     = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

var nameIDFormats = map[string]saml.NameIDFormat{
	"unspecified": saml.UnspecifiedNameIDFormat,
	"email":       saml.EmailAddressNameIDFormat,
	"persistent":  saml.PersistentNameIDFormat,
	"transient":   saml.TransientNameIDFormat,
}

// Provider is the service provider of one ui.saml configuration.
type Provider struct {
	cfg    config.UISAML
	client *http.Client
	acs    url.URL
	meta   url.URL
	key    crypto.Signer
	cert   *x509.Certificate
	now    func() time.Time

	mu        sync.Mutex
	idp       *saml.EntityDescriptor
	fetchedAt time.Time
	failedAt  time.Time
}

// Result is a validated assertion.
type Result struct {
	NameID       string
	NameIDFormat string
	// Attributes holds the values of every attribute, under its Name and,
	// when different, its FriendlyName.
	Attributes map[string][]string
	// AuthnInstant is when the user authenticated at the IdP (zero if the
	// assertion has no AuthnStatement).
	AuthnInstant time.Time
	// AuthnContext is the AuthnContextClassRef of the AuthnStatement.
	AuthnContext string
	// SessionNotOnOrAfter ends the IdP session, zero if not set.
	SessionNotOnOrAfter time.Time
	AssertionID         string
}

// EmailNameID reports whether the NameID has the emailAddress format.
func (r *Result) EmailNameID() bool {
	return r.NameIDFormat == string(saml.EmailAddressNameIDFormat)
}

// New builds a provider. client fetches idp_metadata_url.
func New(c config.UISAML, client *http.Client) (*Provider, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	acs, err := url.Parse(c.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: acs_url: %w", err)
	}
	p := &Provider{cfg: c, client: client, acs: *acs, now: time.Now}
	p.meta = *acs
	p.meta.Path = config.SAMLMetadataPath
	if c.SPKey != "" || c.SPCert != "" {
		if p.key, p.cert, err = parseKeyPair(c.SPKey, c.SPCert); err != nil {
			return nil, fmt.Errorf("saml: SP key pair: %w", err)
		}
	}
	if c.IDPMetadata != "" {
		ed, err := parseIDPMetadata([]byte(c.IDPMetadata))
		if err != nil {
			return nil, fmt.Errorf("saml: idp_metadata: %w", err)
		}
		p.idp, p.fetchedAt = ed, time.Now()
	}
	return p, nil
}

// SetClock overrides the clock of the metadata cache (tests).
func (p *Provider) SetClock(now func() time.Time) { p.now = now }

func parseKeyPair(keyPEM, certPEM string) (crypto.Signer, *x509.Certificate, error) {
	kb, _ := pem.Decode([]byte(keyPEM))
	cb, _ := pem.Decode([]byte(certPEM))
	if kb == nil || cb == nil {
		return nil, nil, errors.New("PEM key and certificate expected")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	var key any
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	}
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("unsupported key type")
	}
	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return nil, nil, errors.New("RSA or ECDSA key expected")
	}
	if !publicKeysEqual(signer.Public(), cert.PublicKey) {
		return nil, nil, errors.New("the certificate does not match the key")
	}
	return signer, cert, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

func parseIDPMetadata(data []byte) (*saml.EntityDescriptor, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		var set saml.EntitiesDescriptor
		if err2 := xml.Unmarshal(data, &set); err2 != nil {
			return nil, err
		}
		found := false
		for _, e := range set.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				ed, found = e, true
				break
			}
		}
		if !found {
			return nil, errors.New("no identity provider in the metadata")
		}
	}
	if ed.EntityID == "" || len(ed.IDPSSODescriptors) == 0 {
		return nil, errors.New("not the metadata of an identity provider")
	}
	hasCert, hasSSO := false, false
	for _, d := range ed.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if (kd.Use == "" || kd.Use == "signing") && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
				hasCert = true
			}
		}
		for _, s := range d.SingleSignOnServices {
			if s.Binding == saml.HTTPRedirectBinding || s.Binding == saml.HTTPPostBinding {
				if u, err := url.Parse(s.Location); err == nil && u.Host != "" {
					hasSSO = true
				}
			}
		}
	}
	if !hasCert {
		return nil, errors.New("no signing certificate in the IdP metadata")
	}
	if !hasSSO {
		return nil, errors.New("no HTTP-Redirect or HTTP-POST single sign-on service in the IdP metadata")
	}
	return &ed, nil
}

// idpMetadata returns the IdP metadata, fetching idp_metadata_url when it
// is missing or older than a day (a failed refresh keeps the old copy).
func (p *Provider) idpMetadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.cfg.IDPMetadataURL == "" || (p.idp != nil && now.Sub(p.fetchedAt) < metadataMaxAge) {
		return p.idp, nil
	}
	if p.idp != nil && now.Sub(p.failedAt) < metadataRetry {
		return p.idp, nil
	}
	ed, err := p.fetch(ctx)
	if err != nil {
		p.failedAt = now
		if p.idp != nil {
			return p.idp, nil
		}
		return nil, err
	}
	p.idp, p.fetchedAt = ed, now
	return ed, nil
}

func (p *Provider) fetch(ctx context.Context) (*saml.EntityDescriptor, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.IDPMetadataURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("saml metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("saml metadata: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes))
	if err != nil {
		return nil, fmt.Errorf("saml metadata: %w", err)
	}
	return parseIDPMetadata(data)
}

// sp returns a service provider for one request.
func (p *Provider) sp(idp *saml.EntityDescriptor) *saml.ServiceProvider {
	sp := &saml.ServiceProvider{
		EntityID:          p.cfg.EntityID,
		AcsURL:            p.acs,
		MetadataURL:       p.meta,
		IDPMetadata:       idp,
		AuthnNameIDFormat: nameIDFormats[p.cfg.NameIDFormat],
		HTTPClient:        p.client,
	}
	if sp.AuthnNameIDFormat == "" {
		sp.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	}
	if p.key != nil {
		sp.Key, sp.Certificate = p.key, p.cert
		switch p.key.(type) {
		case *ecdsa.PrivateKey:
			sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		default:
			sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		}
	}
	sp.ValidateAudienceRestriction = p.validateAudience
	return sp
}

// validateAudience requires an audience restriction and our entity id in
// every one of them.
func (p *Provider) validateAudience(a *saml.Assertion) error {
	if a.Conditions == nil || len(a.Conditions.AudienceRestrictions) == 0 {
		return errors.New("no audience restriction")
	}
	for _, r := range a.Conditions.AudienceRestrictions {
		if r.Audience.Value != p.cfg.EntityID {
			return fmt.Errorf("audience %q is not %q", r.Audience.Value, p.cfg.EntityID)
		}
	}
	return nil
}

// Request is an authentication request to send to the IdP.
type Request struct {
	ID string
	// RedirectURL is set for the HTTP-Redirect binding; otherwise PostURL
	// and SAMLRequest are to be posted by the browser (HTTP-POST binding).
	RedirectURL string
	PostURL     string
	SAMLRequest string
	RelayState  string
}

// AuthnRequest builds an authentication request. relayState must be URL
// safe; forceAuthn asks the IdP for a fresh authentication.
func (p *Provider) AuthnRequest(ctx context.Context, relayState string, forceAuthn bool) (*Request, error) {
	idp, err := p.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	sp := p.sp(idp)
	if forceAuthn {
		t := true
		sp.ForceAuthn = &t
	}
	if loc := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding); loc != "" {
		ar, err := sp.MakeAuthenticationRequest(loc, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			return nil, err
		}
		u, err := ar.Redirect(url.QueryEscape(relayState), sp)
		if err != nil {
			return nil, err
		}
		return &Request{ID: ar.ID, RedirectURL: u.String(), RelayState: relayState}, nil
	}
	loc := sp.GetSSOBindingLocation(saml.HTTPPostBinding)
	ar, err := sp.MakeAuthenticationRequest(loc, saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	d := etree.NewDocument()
	d.SetRoot(ar.Element())
	doc, err := d.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return &Request{ID: ar.ID, PostURL: loc, SAMLRequest: base64.StdEncoding.EncodeToString(doc), RelayState: relayState}, nil
}

// ParseResponse validates the base64 SAMLResponse of the HTTP-POST binding:
// XML signature with the IdP certificate (response or assertion),
// destination and recipient equal to the ACS URL, InResponseTo equal to
// requestID, issuer, audience, issue instant (at most 90 s old) and
// validity window (3 min clock skew).
func (p *Provider) ParseResponse(ctx context.Context, samlResponse, requestID string) (res *Result, err error) {
	if requestID == "" {
		return nil, errors.New("saml: no pending request")
	}
	if len(samlResponse) > maxResponseBytes {
		return nil, errors.New("saml: response too large")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlResponse))
	if err != nil {
		return nil, errors.New("saml: response is not base64")
	}
	idp, err := p.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("saml: malformed assertion")
		}
	}()
	a, err := p.sp(idp).ParseXMLResponse(raw, []string{requestID}, p.acs)
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return nil, fmt.Errorf("saml: %w", ire.PrivateErr)
		}
		return nil, fmt.Errorf("saml: %w", err)
	}
	return result(a, requestID)
}

func result(a *saml.Assertion, requestID string) (*Result, error) {
	if a.Subject == nil || a.Subject.NameID == nil || strings.TrimSpace(a.Subject.NameID.Value) == "" {
		return nil, errors.New("saml: assertion without NameID")
	}
	bearer := false
	for _, sc := range a.Subject.SubjectConfirmations {
		if sc.Method == bearerMethod && sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo == requestID {
			bearer = true
		}
	}
	if !bearer {
		return nil, errors.New("saml: no bearer subject confirmation for this request")
	}
	r := &Result{
		NameID:       strings.TrimSpace(a.Subject.NameID.Value),
		NameIDFormat: a.Subject.NameID.Format,
		Attributes:   map[string][]string{},
		AssertionID:  a.ID,
	}
	if len(a.AuthnStatements) > 0 {
		st := a.AuthnStatements[0]
		r.AuthnInstant = st.AuthnInstant
		if st.SessionNotOnOrAfter != nil {
			r.SessionNotOnOrAfter = *st.SessionNotOnOrAfter
		}
		if st.AuthnContext.AuthnContextClassRef != nil {
			r.AuthnContext = strings.TrimSpace(st.AuthnContext.AuthnContextClassRef.Value)
		}
	}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			var vals []string
			for _, v := range at.Values {
				val := strings.TrimSpace(v.Value)
				if v.NameID != nil {
					val = strings.TrimSpace(v.NameID.Value)
				}
				if val != "" {
					vals = append(vals, val)
				}
			}
			for _, name := range []string{at.Name, at.FriendlyName} {
				if name != "" {
					r.Attributes[name] = appendUnique(r.Attributes[name], vals...)
				}
			}
		}
	}
	return r, nil
}

func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		dup := false
		for _, d := range dst {
			dup = dup || d == v
		}
		if !dup {
			dst = append(dst, v)
		}
	}
	return dst
}

// Unsolicited reports whether an (unverified) SAMLResponse answers no
// request: an IdP-initiated login, such as a click on the application in
// the AWS access portal.
func Unsolicited(samlResponse string) bool {
	if len(samlResponse) > maxResponseBytes {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlResponse))
	if err != nil {
		return false
	}
	var r struct {
		XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		InResponseTo string   `xml:"InResponseTo,attr"`
	}
	return xml.Unmarshal(raw, &r) == nil && r.InResponseTo == ""
}

// Metadata returns the SP metadata: entity id, ACS (HTTP-POST), name id
// format and, with an SP key pair, the signing certificate.
func (p *Provider) Metadata() ([]byte, error) {
	sp := p.sp(nil)
	ed := sp.Metadata()
	for i := range ed.SPSSODescriptors {
		d := &ed.SPSSODescriptors[i]
		var acs []saml.IndexedEndpoint
		for _, e := range d.AssertionConsumerServices {
			if e.Binding == saml.HTTPPostBinding {
				e.Index = 0
				acs = append(acs, e)
			}
		}
		d.AssertionConsumerServices = acs
		var keys []saml.KeyDescriptor
		for _, k := range d.KeyDescriptors {
			if k.Use == "signing" {
				keys = append(keys, k)
			}
		}
		d.KeyDescriptors = keys
	}
	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// PostForm returns the auto-submitting HTML page of an HTTP-POST binding
// request and the hash of its script, for the Content-Security-Policy.
func PostForm(r *Request) (page []byte, scriptHash string) {
	const script = `document.forms[0].submit();`
	sum := sha256.Sum256([]byte(script))
	var b bytes.Buffer
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in</title></head><body>`)
	b.WriteString(`<form method="post" action="` + html.EscapeString(r.PostURL) + `">`)
	b.WriteString(`<input type="hidden" name="SAMLRequest" value="` + html.EscapeString(r.SAMLRequest) + `">`)
	b.WriteString(`<input type="hidden" name="RelayState" value="` + html.EscapeString(r.RelayState) + `">`)
	b.WriteString(`<noscript><button type="submit">Continue to sign-in</button></noscript></form>`)
	b.WriteString(`<script>` + script + `</script></body></html>`)
	return b.Bytes(), "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}
