package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/provider/restapi"
)

const (
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	imdsVersion   = "2018-02-01"
)

// resource is the audience of the tokens: the Resource Manager endpoint.
func (p *Provider) resource() string { return p.base + "/" }

type tokenResponse struct {
	AccessToken string      `json:"access_token"`
	ExpiresIn   json.Number `json:"expires_in"`
}

// fetchToken gets a Resource Manager token for the configured identity.
// Errors never carry the response body of the token endpoint.
func (p *Provider) fetchToken(ctx context.Context) (string, time.Time, error) {
	c := &restapi.Client{HTTP: p.cfg.HTTP, UserAgent: p.cfg.UserAgent, MaxRetries: 1}
	var raw []byte
	var err error
	switch {
	case p.cfg.ClientSecret != "" || p.cfg.FederatedTokenFile != "":
		form := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {p.cfg.ClientID},
			"scope":      {p.resource() + ".default"},
		}
		if p.cfg.ClientSecret != "" {
			form.Set("client_secret", p.cfg.ClientSecret)
		} else {
			assertion, rerr := os.ReadFile(p.cfg.FederatedTokenFile)
			if rerr != nil {
				return "", time.Time{}, fmt.Errorf("azure %s: federated token file: %w", p.id, rerr)
			}
			form.Set("client_assertion_type", assertionType)
			form.Set("client_assertion", strings.TrimSpace(string(assertion)))
		}
		u := strings.TrimRight(p.cfg.AuthorityURL, "/") + "/" + url.PathEscape(p.cfg.TenantID) + "/oauth2/v2.0/token"
		raw, _, err = c.Do(ctx, http.MethodPost, u,
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	default:
		q := url.Values{"api-version": {imdsVersion}, "resource": {p.resource()}}
		if p.cfg.ClientID != "" {
			q.Set("client_id", p.cfg.ClientID)
		}
		u := strings.TrimRight(p.cfg.IMDSURL, "/") + "/metadata/identity/oauth2/token?" + q.Encode()
		raw, _, err = c.Do(ctx, http.MethodGet, u, http.Header{"Metadata": {"true"}}, nil)
	}
	if err != nil {
		if st := restapi.Status(err); st != 0 {
			return "", time.Time{}, fmt.Errorf("azure %s: token request refused: HTTP %d", p.id, st)
		}
		return "", time.Time{}, fmt.Errorf("azure %s: token request: %w", p.id, err)
	}
	var out tokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("azure %s: token response is not JSON", p.id)
	}
	secs, _ := out.ExpiresIn.Int64()
	if secs <= 0 {
		secs = 300
	}
	return out.AccessToken, time.Now().Add(time.Duration(secs) * time.Second), nil
}
