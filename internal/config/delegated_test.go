package config

import (
	"slices"
	"strings"
	"testing"
)

func TestDelegatedClients(t *testing.T) {
	issuer := "    audiences: [dns-gate]\n"
	ok := strings.Replace(base, issuer, issuer+`    require_known_client: true
    delegated_clients:
      - id: m365-copilot
        name: Microsoft 365 Copilot
        azp: ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b
        scopes: [dns.read, dns.plan]
        surfaces: [mcp]
      - id: legacy
        appid: [11111111-2222-3333-4444-555555555555]
        scopes: [dns.read]
        zones: ["*.example.com"]
`, 1)
	c, err := Parse([]byte(ok), env(map[string]string{"EURODNS_API_KEY": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	dc := c.Issuers[0].DelegatedClients
	if !c.Issuers[0].RequireKnownClient || len(dc) != 2 || !slices.Equal(dc[0].Surfaces, []string{"mcp"}) || !slices.Equal(dc[1].Surfaces, []string{"api"}) || dc[1].Name != "legacy" || dc[0].AZP[0] != "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b" {
		t.Fatalf("delegated clients: %+v", dc)
	}

	cases := map[string]string{
		"unknown scope":       "      - {id: a, azp: x, scopes: [dns.read, dns.admin]}\n",
		"no scope":            "      - {id: a, azp: x}\n",
		"policy write scope":  "      - {id: a, azp: x, scopes: [policy.approve]}\n",
		"api key scope":       "      - {id: a, azp: x, scopes: [gate.apikey.manage]}\n",
		"no match":            "      - {id: a, scopes: [dns.read]}\n",
		"glob match":          "      - {id: a, azp: 'x*', scopes: [dns.read]}\n",
		"bad id":              "      - {id: A!, azp: x, scopes: [dns.read]}\n",
		"duplicate id":        "      - {id: a, azp: x, scopes: [dns.read]}\n      - {id: a, azp: y, scopes: [dns.read]}\n",
		"azp of two clients":  "      - {id: a, azp: x, scopes: [dns.read]}\n      - {id: b, azp: x, scopes: [dns.read]}\n",
		"unknown surface":     "      - {id: a, azp: x, scopes: [dns.read], surfaces: [ui]}\n",
		"zone with uppercase": "      - {id: a, azp: x, scopes: [dns.read], zones: [Example.com]}\n",
	}
	for name, clients := range cases {
		y := strings.Replace(base, issuer, issuer+"    delegated_clients:\n"+clients, 1)
		if _, err := Parse([]byte(y), env(map[string]string{"EURODNS_API_KEY": "x"})); err == nil || !strings.Contains(err.Error(), "delegated_clients") {
			t.Errorf("%s: %v", name, err)
		}
	}
	y := strings.Replace(base, issuer, issuer+"    require_known_client: true\n", 1)
	if _, err := Parse([]byte(y), env(map[string]string{"EURODNS_API_KEY": "x"})); err == nil || !strings.Contains(err.Error(), "require_known_client") {
		t.Errorf("require_known_client without clients: %v", err)
	}
}
