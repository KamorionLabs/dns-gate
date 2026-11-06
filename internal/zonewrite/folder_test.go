package zonewrite

import (
	"context"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

// folderAuthz grants the writes of alice through the folder /ES; with
// moveAfter, the zone leaves /ES right after the first such grant.
type folderAuthz struct {
	fakeAuthz
	moved     bool
	moveAfter bool
}

func (a *folderAuthz) AllowRRsetFolder(s *identity.Subject, action, zone string, k dns.Key) (bool, string) {
	ok := a.AllowRRset(s, action, zone, k)
	if ok && s.ID == "alice" && action == policy.ActionRecordWrite && !a.moved {
		a.moved = a.moveAfter
		return true, "/ES"
	}
	return ok, ""
}

func TestWriteEventCarriesTheGrantingFolder(t *testing.T) {
	az := &folderAuthz{}
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) { c.Authz = az })
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

// The folder recorded is the one of the authorization, not a new decision
// made when the event is emitted (the zone may have moved in between).
func TestWriteEventFolderIsTheOneAuthorized(t *testing.T) {
	az := &folderAuthz{moveAfter: true}
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) { c.Authz = az })
	e.mustAdd(alice, rec("A", "www", "192.0.2.1"))
	evs := e.audit.find("addRecords", "allow")
	if len(evs) != 1 || evs[0].Extra["folder"] != "/ES" {
		t.Fatalf("write event: %+v", evs)
	}
}

func TestTransferEventsCarryTheGrantingFolder(t *testing.T) {
	az := &folderAuthz{}
	e := newEnvConfig(t, eurodnstest.Options{}, nil, func(c *Config) {
		c.Authz = az
		c.TombstoneTTL = 7 * 24 * time.Hour
		c.TransferTTL = 24 * time.Hour
		c.Teams = teamList{"team-a": true, "team-b": true}
	})
	ctx := context.Background()
	if _, err := e.eng.ApplyRRsets(ctx, alice, zoneName, put("a1", "192.0.2.1"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.(Transfers).ProposeTransfer(ctx, alice, zoneName, uiapi.TransferProposal{RRsets: adoptRefs("a1 A"), ToTeam: "team-b", Comment: "x"}); err != nil {
		t.Fatal(err)
	}
	evs := e.audit.find("gate.transfer.propose", "allow")
	if len(evs) != 1 || evs[0].Extra["folder"] != "/ES" {
		t.Fatalf("transfer event: %+v", evs)
	}
}
