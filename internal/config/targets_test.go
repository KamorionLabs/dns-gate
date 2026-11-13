package config

import (
	"strings"
	"testing"
)

func TestTargetOwners(t *testing.T) {
	key := env(map[string]string{"EURODNS_API_KEY": "k"})
	c, err := Parse([]byte(base+`target_owners:
  - {match: d1234abcd.cloudfront.net, owner: NH prod}
  - {match: "*.nbs-aws.com", owner: NBS legacy}
  - {match: cloudfront.net, owner: AWS CloudFront}
  - {match: mail.protection.outlook.com., owner: Microsoft 365}
`), key)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"d1234abcd.cloudfront.net.":                "NH prod",
		"D9999.CloudFront.net":                     "AWS CloudFront",
		"cloudfront.net":                           "AWS CloudFront",
		"notcloudfront.net":                        "",
		"www.nbs-aws.com.":                         "NBS legacy",
		"nbs-aws.com":                              "",
		"contoso-com.mail.protection.outlook.com.": "Microsoft 365",
		"": "",
	} {
		if got := MatchTargetOwner(c.TargetOwners, name); got != want {
			t.Errorf("MatchTargetOwner(%q) = %q, want %q", name, got, want)
		}
	}
	for name, doc := range map[string]string{
		"no match":   "target_owners: [{owner: x}]\n",
		"no owner":   "target_owners: [{match: example.net}]\n",
		"everything": "target_owners: [{match: \"*\", owner: x}]\n",
		"bad chars":  "target_owners: [{match: \"exa mple.net\", owner: x}]\n",
		"url":        "target_owners: [{match: \"https://example.net\", owner: x}]\n",
		"twice":      "target_owners: [{match: example.net, owner: x}, {match: Example.NET., owner: y}]\n",
		"long owner": "target_owners: [{match: example.net, owner: " + strings.Repeat("a", 65) + "}]\n",
		"unknown":    "target_owners: [{match: example.net, owner: x, team: y}]\n",
	} {
		if _, err := Parse([]byte(base+doc), key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
