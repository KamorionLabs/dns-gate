package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

type failingStore struct {
	n    int
	last Event
}

func (f *failingStore) AppendAudit(_ context.Context, e Event) error {
	f.n++
	f.last = e
	return errors.New("down")
}

func TestTee(t *testing.T) {
	var buf bytes.Buffer
	st := &failingStore{}
	tee := &Tee{Primary: NewJSON(&buf), Store: st}
	ctx := WithRequest(context.Background(), Request{SourceIP: "192.0.2.7", UserAgent: "terraform/1.9"})
	SetAuthMethod(ctx, AuthOIDC)
	tee.Log(ctx, Event{RequestID: "r1", Decision: "allow"})
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["type"] != "audit" || line["request_id"] != "r1" || line["time"] == nil || line["schema_version"] != SchemaVersion {
		t.Fatalf("line %v", line)
	}
	if st.n != 1 {
		t.Fatal("store not called")
	}
	if line["event_id"] == "" || line["event_id"] != st.last.EventID {
		t.Fatalf("event id differs: stdout %v, store %q", line["event_id"], st.last.EventID)
	}
	if line["source_ip"] != "192.0.2.7" || line["user_agent"] != "terraform/1.9" || line["auth_method"] != "oidc" ||
		st.last.SourceIP != "192.0.2.7" || st.last.AuthMethod != "oidc" {
		t.Fatalf("request context: %v / %+v", line, st.last)
	}
}

// Events stored before the provider-neutral model carry a numeric EuroDNS
// snapshot id; they must still decode.
func TestSnapshotIDCompat(t *testing.T) {
	var old Event
	if err := json.Unmarshal([]byte(`{"request_id":"r","decision":"allow","snapshot_id":884301}`), &old); err != nil || old.SnapshotID != "884301" {
		t.Fatalf("numeric id: %q %v", old.SnapshotID, err)
	}
	b, _ := json.Marshal(Event{SnapshotID: "42", Provider: "eurodns"})
	var back Event
	if err := json.Unmarshal(b, &back); err != nil || back.SnapshotID != "42" || back.Provider != "eurodns" || !bytes.Contains(b, []byte(`"snapshot_id":"42"`)) {
		t.Fatalf("round trip %s: %v", b, err)
	}
	if b, _ := json.Marshal(Event{}); bytes.Contains(b, []byte("snapshot_id")) || bytes.Contains(b, []byte("provider")) {
		t.Fatalf("empty fields must be omitted: %s", b)
	}
}

var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewID(t *testing.T) {
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	a, b := NewID(now), NewID(now.Add(time.Millisecond))
	if !uuidV7.MatchString(a) || a == b || a[:13] >= b[:13] {
		t.Fatalf("ids %s %s", a, b)
	}
	if want := fmt.Sprintf("%012x", now.UnixMilli()); strings.ReplaceAll(a, "-", "")[:12] != want {
		t.Fatalf("timestamp prefix %s", a)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("a\nb\x00c", 10); got != "abc" {
		t.Fatalf("controls: %q", got)
	}
	if got := Truncate(strings.Repeat("é", 200), 255); len(got) != 254 || !strings.HasPrefix(got, "é") {
		t.Fatalf("utf-8 cut: %d", len(got))
	}
	ctx := WithRequest(context.Background(), Request{UserAgent: strings.Repeat("x", 1000)})
	e := Event{}
	Prepare(ctx, &e)
	if len(e.UserAgent) != MaxUserAgent {
		t.Fatalf("user agent %d", len(e.UserAgent))
	}
	Prepare(context.Background(), &e)
	if AuthMethodFrom(context.Background()) != "" {
		t.Fatal("no request context")
	}
}

func sampleEvents() []Event {
	return []Event{
		{RequestID: "r1", Subject: "idp:alice", SubjectName: "alice@example.com", SubjectCategory: "human", Teams: []string{"web"},
			Action: "applyRRsets", Zone: "example.com", Provider: "eurodns", Decision: "allow", SnapshotID: "77",
			Changes: []uiapi.Change{{Op: "create", Host: "www", Type: "A", NewTTL: 300, NewValues: []string{"192.0.2.1"}}},
			Extra:   map[string]any{"ignored_out_of_scope": []string{"MX @"}}},
		{RequestID: "r2", Action: "getDnsZone", Zone: "example.com", Decision: "deny", Reason: "unauthenticated",
			Extra: map[string]any{"remote_addr": "198.51.100.4"}},
		{RequestID: "r3", Subject: "api-key:k1", SubjectCategory: "key", Action: "apikey.create", Decision: "allow",
			Extra: map[string]any{"key_id": "k2", "team": "web", "role": "writer", "via": "api"}},
		{RequestID: "r4", Subject: "idp:ci", SubjectCategory: "pipeline", Action: "policy.activate", Decision: "deny", Reason: "conflict"},
		{RequestID: "r5", Subject: "gate:reconciler", SubjectCategory: "system", Action: "gate.expire", Zone: "example.org", Decision: "error", Reason: "upstream"},
		{RequestID: "r6", Subject: "idp:alice", SubjectCategory: "human", Action: "applyRRsets", Zone: "example.com", Decision: "allow",
			Changes: []uiapi.Change{{Op: "update", Host: "go", Type: dns.TypeURLForward,
				OldForward: &dns.Forward{Mode: "301", URL: "https://example.net/"},
				NewForward: &dns.Forward{Mode: "frame", URL: "https://example.net/", Title: "Example"}}},
			Extra: map[string]any{"zone_admin_forwards": []string{"old URLFWD"}}},
	}
}

func logSample(t *testing.T, o Options) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	l, err := NewJSONWith(&buf, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequest(context.Background(), Request{SourceIP: "2001:db8::1", UserAgent: "curl/8 <script>"})
	SetAuthMethod(ctx, AuthGateToken)
	for _, e := range sampleEvents() {
		l.Log(ctx, e)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte{'\n'}) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if m["type"] != "audit" {
			t.Fatalf("type discriminator missing: %s", line)
		}
		out = append(out, m)
	}
	return out
}

func schema(t *testing.T) *jsonschema.Resolved {
	t.Helper()
	raw, err := os.ReadFile("../../api/audit-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestSchemaNative(t *testing.T) {
	rs := schema(t)
	for _, chain := range []bool{false, true} {
		for _, m := range logSample(t, Options{HashChain: chain}) {
			if err := rs.Validate(m); err != nil {
				t.Errorf("chain=%v: %v\n%v", chain, err, m)
			}
		}
	}
	bad := logSample(t, Options{})[0]
	bad["decision"] = "maybe"
	if rs.Validate(bad) == nil {
		t.Fatal("schema accepts an unknown decision")
	}
	bad = logSample(t, Options{})[0]
	bad["surprise"] = 1
	if rs.Validate(bad) == nil {
		t.Fatal("schema accepts an undocumented member")
	}
}

func get(m map[string]any, path string) any {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func TestECS(t *testing.T) {
	lines := logSample(t, Options{Format: FormatECS})
	w := lines[0]
	checks := map[string]any{
		"ecs.version": ECSVersion, "event.action": "applyRRsets", "event.outcome": "success", "event.kind": "event",
		"user.id": "idp:alice", "user.name": "alice@example.com", "user.group.name": "web", "source.ip": "2001:db8::1",
		"user_agent.original": "curl/8 <script>", "dns.question.name": "example.com", "http.request.id": "r1",
		"dns_gate.auth_method": "gate-token", "dns_gate.provider": "eurodns", "dns_gate.snapshot_id": "77",
	}
	for k, want := range checks {
		if got := get(w, k); got != want {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	if get(w, "event.id") == "" || get(w, "@timestamp") == nil {
		t.Fatal("id and timestamp")
	}
	if cats := get(w, "event.category").([]any); cats[0] != "api" || cats[1] != "configuration" {
		t.Fatalf("categories %v", cats)
	}
	if types := get(w, "event.type").([]any); types[0] != "creation" || types[1] != "allowed" {
		t.Fatalf("types %v", types)
	}
	if hosts := get(w, "related.hosts").([]any); len(hosts) != 2 || hosts[1] != "www.example.com" {
		t.Fatalf("related hosts %v", hosts)
	}
	if get(lines[1], "event.category").([]any)[0] != "authentication" || get(lines[1], "event.outcome") != "failure" || get(lines[1], "user") != nil {
		t.Fatalf("auth failure %v", lines[1])
	}
	if get(lines[2], "event.category").([]any)[0] != "iam" {
		t.Fatalf("api key %v", lines[2])
	}
	if get(lines[4], "event.outcome") != "failure" || get(lines[4], "event.reason") != "upstream" {
		t.Fatalf("error %v", lines[4])
	}
}

func TestOCSF(t *testing.T) {
	lines := logSample(t, Options{Format: FormatOCSF})
	type want struct {
		class, activity, typeUID float64
		status                   string
	}
	wants := []want{
		{OCSFAPIActivity, 1, 600301, "Success"},
		{OCSFAuthentication, 1, 300201, "Failure"},
		{OCSFAccountChange, 1, 300101, "Success"},
		{OCSFAPIActivity, 3, 600303, "Failure"},
		{OCSFAPIActivity, 4, 600304, "Failure"},
	}
	for i, w := range wants {
		m := lines[i]
		if m["class_uid"] != w.class || m["activity_id"] != w.activity || m["type_uid"] != w.typeUID || m["status"] != w.status {
			t.Errorf("line %d: class %v activity %v type %v status %v", i, m["class_uid"], m["activity_id"], m["type_uid"], m["status"])
		}
		for _, k := range []string{"metadata.uid", "metadata.version", "metadata.product.name", "time", "severity_id", "category_uid"} {
			if get(m, k) == nil {
				t.Errorf("line %d: %s missing", i, k)
			}
		}
	}
	m := lines[0]
	if get(m, "api.operation") != "applyRRsets" || get(m, "actor.user.uid") != "idp:alice" || get(m, "src_endpoint.ip") != "2001:db8::1" ||
		get(m, "http_request.user_agent") != "curl/8 <script>" || get(m, "cloud.provider") != "eurodns" || get(m, "unmapped.dns_gate.auth_method") != "gate-token" {
		t.Fatalf("api activity %v", m)
	}
	if get(lines[1], "user.name") != "unknown" || get(lines[2], "user.uid") != "k2" {
		t.Fatalf("users: %v / %v", lines[1]["user"], lines[2]["user"])
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := NewJSONWith(&bytes.Buffer{}, Options{Format: "cef"}); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestClassifyActivities(t *testing.T) {
	cases := map[string]Activity{
		"getDnsZone": ActivityRead, "saveDnsZone": ActivityUpdate, "addDnsRecords": ActivityCreate, "deleteDnsRecord": ActivityDelete,
		"mcp.list_zones": ActivityRead, "mcp.apply_rrset_change": ActivityUpdate, "api.plan": ActivityRead,
		"policy.delegated.delete_role": ActivityDelete, "apikey.revoke": ActivityDelete, "gate.transfer.propose": ActivityCreate,
		"acme.register": ActivityCreate, "acme.update": ActivityUpdate,
		"oauth.authorize": ActivityCreate, "oauth.revoke": ActivityDelete,
	}
	for action, want := range cases {
		if _, got := Classify(Event{Action: action, Subject: "s", Decision: "allow"}); got != want {
			t.Errorf("%s: %s, want %s", action, got, want)
		}
	}
}

// Events of system actors (discovery, reconciler) logged while serving a
// request do not take the client of that request.
func TestClassifyOAuth(t *testing.T) {
	for action, want := range map[string]Class{
		"oauth.token": ClassAuthentication, "oauth.client_auth": ClassAuthentication, "oauth.refresh_reuse": ClassAuthentication,
		"oauth.authorize": ClassAccountChange, "oauth.revoke": ClassAccountChange,
	} {
		if got, _ := Classify(Event{Action: action, Subject: "s", Decision: "allow"}); got != want {
			t.Errorf("%s: %s, want %s", action, got, want)
		}
	}
}

func TestGrantOfTheRequest(t *testing.T) {
	ctx := WithRequest(context.Background(), Request{})
	SetClient(ctx, "skopea", "Skopea")
	SetGrant(ctx, "g-1", []string{"dns.read"})
	e := Event{Subject: "idp:alice", Action: "api.rrset.put", Decision: "allow", ClientID: "skopea", Extra: map[string]any{"via": "api"}}
	Prepare(ctx, &e)
	if e.Extra["grant_id"] != "g-1" || e.Extra["via"] != "api" {
		t.Fatalf("grant of the request: %+v", e.Extra)
	}
	other := Event{Subject: "idp:alice", Action: "x", Decision: "allow"}
	Prepare(ctx, &other)
	if other.Extra != nil {
		t.Fatalf("grant on an event without the client: %+v", other.Extra)
	}
}

func TestPrepareSystemActor(t *testing.T) {
	ctx := WithRequest(context.Background(), Request{SourceIP: "192.0.2.7", UserAgent: "ua"})
	SetAuthMethod(ctx, AuthOIDC)
	e := Event{Subject: "gate:discovery", SubjectCategory: "system", Action: "gate.zone.folder_seen", Decision: "allow"}
	Prepare(ctx, &e)
	if e.SourceIP != "" || e.UserAgent != "" || e.AuthMethod != "" || e.EventID == "" {
		t.Fatalf("system event: %+v", e)
	}
}

// ecsTypes are the event.type values ECS 8.11 expects per event.category.
var ecsTypes = map[string][]string{
	"api":            {"access", "admin", "allowed", "change", "creation", "deletion", "denied", "end", "info", "start", "user"},
	"authentication": {"start", "end", "info"},
	"configuration":  {"access", "change", "creation", "deletion", "info"},
	"iam":            {"admin", "change", "creation", "deletion", "group", "info", "user"},
}

// Every ECS event.type must be expected for one of its categories.
func TestECSCategorization(t *testing.T) {
	cases := []struct {
		e          Event
		categories string
		types      string
	}{
		{Event{Subject: "idp:a", Action: "apikey.manage", Decision: "deny", Reason: "forbidden"}, "iam", "user,info"},
		{Event{Subject: "idp:a", Action: "apikey.create", Decision: "allow"}, "iam", "user,creation"},
		{Event{Subject: "idp:a", Action: "apikey.revoke", Decision: "allow"}, "iam", "user,deletion"},
		{Event{Subject: "idp:a", Action: "policy.activate", Decision: "deny", Reason: "conflict"}, "iam,configuration", "change"},
		{Event{Subject: "idp:a", Action: "getDnsZone", Zone: "example.com", Decision: "deny", Reason: "forbidden"}, "api", "access,denied"},
		{Event{Subject: "gate:reconciler", SubjectCategory: "system", Action: "gate.expire", Zone: "example.com", Decision: "error", Reason: "upstream"}, "api,configuration", "deletion"},
		{Event{Subject: "gate:discovery", SubjectCategory: "system", Action: "gate.zone.folder_changed", Zone: "example.com", Decision: "allow"}, "configuration", "change"},
		{Event{Subject: "gate:discovery", SubjectCategory: "system", Action: "gate.zone.folder_seen", Zone: "example.com", Decision: "allow"}, "configuration", "creation"},
		{Event{Subject: "gate:discovery", SubjectCategory: "system", Action: "gate.zone.folder_gone", Zone: "example.com", Decision: "allow"}, "configuration", "deletion"},
		{Event{Subject: "gate:discovery", SubjectCategory: "system", Action: "gate.zone.folders_listed", Decision: "allow"}, "configuration", "info"},
		{Event{Action: "getDnsZone", Decision: "deny", Reason: "unauthenticated"}, "authentication", "start"},
	}
	for _, c := range cases {
		ev := ToECS(c.e)["event"].(map[string]any)
		cats, types := ev["category"].([]string), ev["type"].([]string)
		if strings.Join(cats, ",") != c.categories || strings.Join(types, ",") != c.types {
			t.Errorf("%s: %v %v, want %s %s", c.e.Action, cats, types, c.categories, c.types)
		}
		for _, ty := range types {
			ok := false
			for _, cat := range cats {
				for _, allowed := range ecsTypes[cat] {
					ok = ok || allowed == ty
				}
			}
			if !ok {
				t.Errorf("%s: type %s not expected for %v", c.e.Action, ty, cats)
			}
		}
	}
}
