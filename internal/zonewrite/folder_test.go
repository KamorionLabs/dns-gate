package zonewrite

import (
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// folderAuthz grants the writes of alice through the folder /ES.
type folderAuthz struct{ fakeAuthz }

func (a *folderAuthz) GrantFolder(s *identity.Subject, action, _ string, _ dns.Key) string {
	if s.ID == "alice" && action == policy.ActionRecordWrite {
		return "/ES"
	}
	return ""
}

func TestWriteEventCarriesTheGrantingFolder(t *testing.T) {
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) { c.Authz = &folderAuthz{} })
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	e.mustAdd(bob, rec("A", "api", "192.0.2.2"))
	var got []string
	for _, ev := range e.audit.find("addRecords", "allow") {
		f, _ := ev.Extra["folder"].(string)
		got = append(got, ev.Subject+"="+f)
	}
	if len(got) != 2 || got[0] != "idp:alice=/ES" || got[1] != "idp:bob=" {
		t.Fatalf("write events: %v", got)
	}
}
