package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const recordProviders = `  - id: ovh-main
    kind: OVH
    zones: {include: ["*.fr"]}
    ovh: {application_key: ak}
  - id: ovh-sa
    kind: ovh
    zones: {include: ["*.be"]}
    ovh: {endpoint: ovh-ca, client_id: cid}
  - id: scw
    kind: scaleway
    zones: {include: ["*.io"]}
  - id: ik
    kind: infomaniak
    zones: {include: ["*.ch"]}
    infomaniak: {zones: ["Example.CH."]}
  - id: az
    kind: azure
    zones: {include: ["*.net"]}
    azure:
      subscription_id: 00000000-0000-0000-0000-000000000001
      resource_group: rg-dns
`

func withProviders(extra string) string {
	return strings.Replace(base, "    eurodns: {app_id: app}\n", "    zones: {include: [\"*.com\"]}\n    eurodns: {app_id: app}\n"+extra, 1)
}

func TestRecordProviders(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("az-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte(withProviders(recordProviders)), env(map[string]string{
		"EURODNS_API_KEY":                 "k",
		"OVH_OVH_MAIN_APPLICATION_SECRET": "as",
		"OVH_OVH_MAIN_CONSUMER_KEY":       "ck",
		"OVH_OVH_SA_CLIENT_SECRET":        "cs",
		"SCW_SECRET_KEY":                  "scw",
		"INFOMANIAK_IK_TOKEN":             "tok",
		"AZURE_AZ_CLIENT_SECRET_FILE":     secret,
		"AZURE_TENANT_ID":                 "tenant",
		"AZURE_CLIENT_ID":                 "client",
	}))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Providers
	if o := p[1].OVH; p[1].Kind != KindOVH || o.Endpoint != "ovh-eu" || o.ApplicationKey != "ak" || o.ApplicationSecret != "as" || o.ConsumerKey != "ck" || o.ClientID != "" {
		t.Errorf("ovh application: %+v", o)
	}
	if o := p[2].OVH; o.Endpoint != "ovh-ca" || o.ClientID != "cid" || o.ClientSecret != "cs" || o.ApplicationKey != "" {
		t.Errorf("ovh service account: %+v", o)
	}
	if p[3].Scaleway.SecretKey != "scw" {
		t.Errorf("scaleway: %+v", p[3].Scaleway)
	}
	if k := p[4].Infomaniak; k.Token != "tok" || k.Zones[0] != "example.ch" || k.Rate.Every.D() != time.Second {
		t.Errorf("infomaniak: %+v", k)
	}
	if a := p[5].Azure; a.ClientSecret != "az-secret" || a.TenantID != "tenant" || a.ClientID != "client" {
		t.Errorf("azure: %+v", a)
	}
}

func TestRecordProvidersInvalid(t *testing.T) {
	sub := "00000000-0000-0000-0000-000000000001"
	for name, tc := range map[string]struct {
		yaml string
		env  map[string]string
		want string
	}{
		"ovh no credentials": {"  - {id: o, kind: ovh}\n", nil, "credentials missing"},
		"ovh incomplete":     {"  - {id: o, kind: ovh, ovh: {application_key: a}}\n", nil, "application credentials incomplete"},
		"ovh both": {"  - {id: o, kind: ovh, ovh: {application_key: a, client_id: c}}\n",
			map[string]string{"OVH_APPLICATION_SECRET": "s", "OVH_CONSUMER_KEY": "c", "OVH_CLIENT_SECRET": "s"}, "keep one"},
		"ovh endpoint":       {"  - {id: o, kind: ovh, ovh: {endpoint: ovh-xx}}\n", map[string]string{"OVH_CLIENT_ID": "c", "OVH_CLIENT_SECRET": "s"}, "ovh.endpoint"},
		"scaleway no key":    {"  - {id: s, kind: scaleway}\n", nil, "secret key missing"},
		"scaleway project":   {"  - {id: s, kind: scaleway, scaleway: {project_id: nope}}\n", map[string]string{"SCW_SECRET_KEY": "k"}, "is not a UUID"},
		"infomaniak token":   {"  - {id: i, kind: infomaniak}\n", nil, "API token missing"},
		"infomaniak zone":    {"  - {id: i, kind: infomaniak, zones: {include: [\"*.ch\"]}, infomaniak: {zones: [example.fr]}}\n", map[string]string{"INFOMANIAK_TOKEN": "t"}, "excluded by the zones filter"},
		"azure subscription": {"  - {id: a, kind: azure, azure: {managed_identity: true}}\n", nil, "subscription_id"},
		"azure identity":     {"  - {id: a, kind: azure, azure: {subscription_id: " + sub + "}}\n", nil, "identity missing"},
		"azure tenant":       {"  - {id: a, kind: azure, azure: {subscription_id: " + sub + "}}\n", map[string]string{"AZURE_CLIENT_SECRET": "s"}, "tenant_id and client_id are required"},
		"wrong block":        {"  - {id: a, kind: azure, ovh: {}, azure: {subscription_id: " + sub + ", managed_identity: true}}\n", nil, "ovh: not allowed for kind azure"},
		"unknown kind":       {"  - {id: g, kind: gandi}\n", nil, "expected eurodns, route53, ovh, scaleway, infomaniak, azure"},
	} {
		e := map[string]string{"EURODNS_API_KEY": "k"}
		for k, v := range tc.env {
			e[k] = v
		}
		_, err := Parse([]byte(withProviders(tc.yaml)), env(e))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
