package audit

import (
	"context"
	"testing"
	"time"
)

func TestDelegatedClientFormats(t *testing.T) {
	ctx := WithRequest(context.Background(), Request{SourceIP: "192.0.2.1"})
	SetAuthMethod(ctx, AuthOAuthDelegated)
	SetClient(ctx, "m365-copilot", "Microsoft 365 Copilot")
	e := Event{Time: time.Unix(0, 0).UTC(), Subject: "entra:t/u", Action: "mcp.list_zones", Decision: "allow"}
	Prepare(ctx, &e)
	if e.ClientID != "m365-copilot" || e.Actor == nil || *e.Actor != (Actor{Type: ActorOAuthClient, ID: "m365-copilot", Name: "Microsoft 365 Copilot"}) || e.AuthMethod != AuthOAuthDelegated {
		t.Fatalf("prepared: %+v", e)
	}
	ecs := ToECS(e)
	if ecs["dns_gate"].(map[string]any)["client_id"] != "m365-copilot" {
		t.Fatalf("ecs: %v", ecs["dns_gate"])
	}
	actor := ToOCSF(e)["actor"].(map[string]any)
	if actor["app_uid"] != "m365-copilot" || actor["app_name"] != "Microsoft 365 Copilot" {
		t.Fatalf("ocsf: %v", actor)
	}
	sys := Event{SubjectCategory: "system", Action: "gate.expire", Decision: "allow"}
	Prepare(ctx, &sys)
	if sys.ClientID != "" || sys.Actor != nil {
		t.Fatalf("system event: %+v", sys)
	}
	plain := Event{Action: "x", Decision: "allow"}
	Prepare(WithRequest(context.Background(), Request{}), &plain)
	if _, ok := ToOCSF(plain)["actor"].(map[string]any)["app_uid"]; ok || plain.ClientID != "" {
		t.Fatalf("direct: %+v", plain)
	}
}
