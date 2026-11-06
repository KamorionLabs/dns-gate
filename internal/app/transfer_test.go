package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// transferApp is a gate with an approved rename left applying, whose
// approver no longer has a binding: a retrier wired with the Rebinder
// fails it, one without would apply it with the rights recorded at the
// approval.
func transferApp(t *testing.T, opts Options) (*App, string) {
	t.Helper()
	yaml := `
providers:
  - {id: eurodns, kind: eurodns, eurodns: {base_url: "http://127.0.0.1:1", app_id: app, max_retries: 0}}
zones: [example.com]
issuers:
  - {name: ci, issuer: "https://token.example.net", audiences: [dns-gate], category: human}
roles:
  admin:
    rules: [{zones: ["*"], actions: [policy.read, policy.propose, policy.approve, dns.ownership.approve, dns.read]}]
bindings:
  - {role: admin, team: ops, subjects: [{issuer: ci, claims: {sub: [admin]}}]}
`
	cfg, err := config.Parse([]byte(yaml), func(k string) string {
		if k == "EURODNS_API_KEY" {
			return "k"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := a.Store.Put(ctx, store.Ownership{Zone: "example.com", Host: "www", Type: "A", Owner: "web", State: store.StateActive, ContentHash: "h", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	decided := now.Add(-10 * time.Minute)
	tr := store.Transfer{
		ID: "tr-0000000000001-0a1b2c3d4e", Kind: uiapi.TransferKindRename, FromTeam: "web", ToTeam: "ops", Status: uiapi.TransferApplying,
		Requester: "ci:admin", CreatedAt: decided, ExpiresAt: now.Add(time.Hour), DecidedBy: "ci:gone", DecidedAt: &decided,
		Approver: &store.SubjectRecord{Kind: "oidc", Issuer: "ci", ID: "gone", Category: "human", Claims: map[string]any{"sub": "gone"},
			Roles: []string{"admin"}, Teams: []string{"ops"}, TeamRoles: map[string][]string{"ops": {"admin"}}},
	}
	if err := a.Store.CreateTransfer(ctx, tr); err != nil {
		t.Fatal(err)
	}
	return a, tr.ID
}

func wantRebindRefusal(t *testing.T, a *App, id string) bool {
	t.Helper()
	got, err := a.Store.GetTransfer(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == uiapi.TransferApplying {
		return false
	}
	if got.Status != uiapi.TransferFailed || !strings.Contains(got.Error, "no longer bound") {
		t.Fatalf("the retrier did not bind the approver again: %+v", got)
	}
	if o, _ := a.Store.Get(context.Background(), "example.com", "www", "A"); o.Owner != "web" {
		t.Fatalf("moved with the rights recorded at the approval: %+v", o)
	}
	return true
}

func TestTransferRetrierWiredInMaintenance(t *testing.T) {
	a, id := transferApp(t, Options{Holder: "lambda"})
	_ = a.Maintenance(context.Background())
	if !wantRebindRefusal(t, a, id) {
		t.Fatal("the maintenance pass did not retry the transfer")
	}
}

func TestTransferRetrierWiredInRun(t *testing.T) {
	a, id := transferApp(t, Options{Holder: "pod", TransferRetryInterval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !wantRebindRefusal(t, a, id) {
		if time.Now().After(deadline) {
			t.Fatal("Run did not retry the transfer")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
