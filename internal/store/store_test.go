package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func conformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	zone := "example.com"

	t.Run("crud", func(t *testing.T) {
		if _, err := s.Get(ctx, zone, "www", "A"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get missing: %v", err)
		}
		exp := clock.Now().Add(time.Hour)
		o := Ownership{Zone: zone, Host: "www", Type: "A", Owner: "team-a", CreatedBy: "iss:sub",
			CreatedByName: "ci", CreatedByCategory: "pipeline", UpdatedBy: "iss:sub",
			CreatedAt: clock.Now(), UpdatedAt: clock.Now(), ContentHash: "h1", State: StateActive, ExpiresAt: &exp}
		if err := s.Put(ctx, o); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, o); !errors.Is(err, ErrConflict) {
			t.Fatalf("double create: %v", err)
		}
		got, err := s.Get(ctx, zone, "www", "A")
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 1 || got.Owner != "team-a" || got.CreatedByName != "ci" || got.UpdatedBy != "iss:sub" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
			t.Fatalf("unexpected %+v", got)
		}
		got.ContentHash = "h2"
		if err := s.Put(ctx, *got); err != nil {
			t.Fatal(err)
		}
		stale := *got
		if err := s.Put(ctx, stale); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale update: %v", err)
		}
		if err := s.Put(ctx, Ownership{Zone: zone, Host: "api", Type: "CNAME", Owner: "team-b", State: StatePending}); err != nil {
			t.Fatal(err)
		}
		list, err := s.List(ctx, zone)
		if err != nil || len(list) != 2 || list[0].Host != "api" {
			t.Fatalf("list %v %+v", err, list)
		}
		if other, _ := s.List(ctx, "other.com"); len(other) != 0 {
			t.Fatalf("list leaks zones: %+v", other)
		}
		if err := s.Delete(ctx, zone, "www", "A", 1); !errors.Is(err, ErrConflict) {
			t.Fatalf("delete stale: %v", err)
		}
		if err := s.Delete(ctx, zone, "www", "A", 2); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, zone, "www", "A", 2); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete missing: %v", err)
		}
	})

	t.Run("zone version", func(t *testing.T) {
		v, err := s.ZoneVersion(ctx, "v.example.com")
		if err != nil || v != 0 {
			t.Fatalf("initial %d %v", v, err)
		}
		if v, err = s.BumpZoneVersion(ctx, "v.example.com", 0); err != nil || v != 1 {
			t.Fatalf("bump %d %v", v, err)
		}
		if _, err = s.BumpZoneVersion(ctx, "v.example.com", 0); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale bump %v", err)
		}
		if v, _ = s.ZoneVersion(ctx, "v.example.com"); v != 1 {
			t.Fatalf("version %d", v)
		}
	})

	t.Run("audit", func(t *testing.T) {
		base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
		for i := 0; i < 7; i++ {
			e := audit.Event{
				Time: base.Add(time.Duration(i) * time.Second), RequestID: "r" + string(rune('a'+i)),
				Subject: "ci:pipeline-1", SubjectName: "pipeline one", SubjectCategory: "pipeline",
				Action: "dns.record.write", Zone: "audit.example.com", Decision: "allow",
				Changes: []uiapi.Change{{Op: "create", Host: "www", Type: "A", NewValues: []string{"192.0.2.1"}}},
			}
			if i%2 == 1 {
				e.Decision = "deny"
				e.Subject, e.SubjectName, e.SubjectCategory = "idp:alice", "alice@example.com", "human"
				e.Changes = []uiapi.Change{{Op: "update", Host: "api", Type: "CNAME"}}
			}
			if i == 6 {
				e.Zone = "other.example.com"
			}
			if err := s.AppendAudit(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		page, cur, err := s.ListAudit(ctx, AuditQuery{Zone: "audit.example.com", Limit: 4})
		if err != nil || len(page) != 4 || cur == "" || page[0].RequestID != "rf" || page[3].RequestID != "rc" {
			t.Fatalf("page1 %v %q %+v", err, cur, page)
		}
		page, cur, err = s.ListAudit(ctx, AuditQuery{Zone: "audit.example.com", Limit: 4, Cursor: cur})
		if err != nil || len(page) != 2 || cur != "" || page[1].RequestID != "ra" {
			t.Fatalf("page2 %v %q %+v", err, cur, page)
		}
		all, _, _ := s.ListAudit(ctx, AuditQuery{})
		if len(all) < 7 || all[0].RequestID != "rg" {
			t.Fatalf("all %+v", all)
		}
		for _, tc := range []struct {
			q    AuditQuery
			want int
		}{
			{AuditQuery{Zone: "audit.example.com", Decision: "deny"}, 3},
			{AuditQuery{Zone: "audit.example.com", Category: "pipeline"}, 3},
			{AuditQuery{Zone: "audit.example.com", Subject: "alice@example.com"}, 3},
			{AuditQuery{Zone: "audit.example.com", Subject: "ALICE"}, 3},
			{AuditQuery{Zone: "audit.example.com", Subject: "pipeline-"}, 3},
			{AuditQuery{Zone: "audit.example.com", Subject: "ci:"}, 3},
			{AuditQuery{Zone: "audit.example.com", Subject: "%"}, 0},
			{AuditQuery{Zone: "audit.example.com", Subject: "pipeline_one"}, 0},
			{AuditQuery{Zone: "audit.example.com", Host: "www", Type: "a"}, 3},
			{AuditQuery{Zone: "audit.example.com", Since: base.Add(2 * time.Second), Until: base.Add(4 * time.Second)}, 3},
		} {
			got, _, err := s.ListAudit(ctx, tc.q)
			if err != nil || len(got) != tc.want {
				t.Errorf("%+v: got %d want %d (%v)", tc.q, len(got), tc.want, err)
			}
		}
		if _, _, err := s.ListAudit(ctx, AuditQuery{Cursor: "%%%"}); err == nil {
			t.Fatal("bad cursor accepted")
		}
	})

	t.Run("policy", func(t *testing.T) { policyConformance(t, s) })
	t.Run("plans", func(t *testing.T) { planConformance(t, s, clock) })
	t.Run("api_keys", func(t *testing.T) { apiKeyConformance(t, s, clock) })
	t.Run("tombstones", func(t *testing.T) { tombstoneConformance(t, s, clock) })
	t.Run("transfers", func(t *testing.T) { transferConformance(t, s, clock) })
	t.Run("reassign", func(t *testing.T) { reassignConformance(t, s, clock) })

	t.Run("lock", func(t *testing.T) {
		z := "lock.example.com"
		if err := s.Lock(ctx, z, "a", time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := s.Lock(ctx, z, "a", time.Minute); err != nil {
			t.Fatalf("reentrant: %v", err)
		}
		if err := s.Lock(ctx, z, "b", time.Minute); !errors.Is(err, ErrLockHeld) {
			t.Fatalf("held: %v", err)
		}
		if err := s.Unlock(ctx, z, "b"); err != nil {
			t.Fatalf("foreign unlock must be a no-op: %v", err)
		}
		if err := s.Lock(ctx, z, "b", time.Minute); !errors.Is(err, ErrLockHeld) {
			t.Fatalf("foreign unlock released the lock: %v", err)
		}
		clock.Add(2 * time.Minute)
		if err := s.Lock(ctx, z, "b", time.Minute); err != nil {
			t.Fatalf("expired lease: %v", err)
		}
		if err := s.Unlock(ctx, z, "b"); err != nil {
			t.Fatal(err)
		}
		if err := s.Lock(ctx, z, "a", time.Minute); err != nil {
			t.Fatalf("after unlock: %v", err)
		}
	})
}

func TestMemory(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	conformance(t, NewMemoryWithClock(clock.Now), clock)
}

// TestDynamoDB runs against DynamoDB Local, e.g.
// docker run -p 8000:8000 amazon/dynamodb-local; DYNAMODB_ENDPOINT=http://localhost:8000
func TestDynamoDB(t *testing.T) {
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DYNAMODB_ENDPOINT not set")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	ctx := context.Background()
	table := "dns-gate-test-" + time.Now().Format("150405.000000")
	st, err := NewDynamoDB(ctx, DynamoDBConfig{Table: table, Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	d := st.(*dynamo)
	api := d.api.(*dynamodb.Client)
	_, err = api.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("sk"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("sk"), KeyType: types.KeyTypeRange},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = api.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})
	clock := &fakeClock{t: time.Now()}
	d.now = clock.Now
	conformance(t, d, clock)
}

func TestSQLite(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/gate.db"
	st, err := NewSQLite(ctx, SQLiteConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	s := st.(*sqlStore)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.now = clock.Now
	conformance(t, s, clock)
	testSQLMigrationsAndPurge(t, s, clock)
	_ = s.Close()

	// Reopening keeps data and does not re-apply migrations.
	again, err := NewSQLite(ctx, SQLiteConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer again.(*sqlStore).Close()
	if v, _ := again.ZoneVersion(ctx, "v.example.com"); v != 1 {
		t.Fatalf("data lost on reopen: %d", v)
	}
}

// TestPostgres runs against PostgreSQL, e.g.
// POSTGRES_DSN=postgres://postgres:test@localhost:5432/postgres?sslmode=disable
func TestPostgres(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}
	ctx := context.Background()
	st, err := NewPostgres(ctx, PostgresConfig{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	s := st.(*sqlStore)
	defer s.Close()
	for _, table := range []string{"acme_registration", "api_key", "policy_active", "policy_revision", "ownership", "zone_meta", "zone_lock", "audit", "rrset_plan", "ownership_tombstone", "ownership_transfer"} {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.now = clock.Now
	conformance(t, s, clock)
	testSQLMigrationsAndPurge(t, s, clock)

	// A second store on the same database (another replica) sees the lease.
	other, err := NewPostgres(ctx, PostgresConfig{DSN: dsn, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer other.(*sqlStore).Close()
	other.(*sqlStore).now = clock.Now
	if err := s.Lock(ctx, "ha.example.com", "pod-a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := other.Lock(ctx, "ha.example.com", "pod-b", time.Minute); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("lease not shared: %v", err)
	}
}

func testSQLMigrationsAndPurge(t *testing.T, s *sqlStore, clock *fakeClock) {
	ctx := context.Background()
	var n int
	entries, _ := migrationsFS.ReadDir("migrations/" + string(s.dialect))
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil || n != len(entries) {
		t.Fatalf("schema_migrations %d %v", n, err)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	old := audit.Event{Time: clock.Now().Add(-500 * 24 * time.Hour), RequestID: "old", Zone: "purge.example.com", Decision: "allow"}
	recent := audit.Event{Time: clock.Now(), RequestID: "recent", Zone: "purge.example.com", Decision: "allow"}
	for _, e := range []audit.Event{old, recent} {
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PurgeAudit(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.ListAudit(ctx, AuditQuery{Zone: "purge.example.com"})
	if err != nil || len(got) != 1 || got[0].RequestID != "recent" {
		t.Fatalf("purge %v %+v", err, got)
	}
}

func policyConformance(t *testing.T, s Store) {
	ctx := context.Background()
	base := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	rev := func(id string, i int, status string) PolicyRevision {
		return PolicyRevision{ID: id, Document: []byte(`{"roles":{"r` + id + `":{}}}`), Author: "idp:alice",
			AuthorName: "alice@example.com", AuthorCat: "human", CreatedAt: base.Add(time.Duration(i) * time.Minute),
			Comment: "c" + id, Status: status}
	}
	if _, err := s.ActiveRevision(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no active: %v", err)
	}
	for i, id := range []string{"p1", "p2", "p3", "p4", "p5"} {
		if err := s.CreateRevision(ctx, rev(id, i, revisionProposed)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateRevision(ctx, rev("p1", 9, revisionProposed)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.CreateRevision(ctx, rev("bad", 9, revisionActive)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("create active: %v", err)
	}
	if _, err := s.GetRevision(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	r1, err := s.GetRevision(ctx, "p1")
	if err != nil || r1.Version != 1 || string(r1.Document) != `{"roles":{"rp1":{}}}` || r1.AuthorName != "alice@example.com" || !r1.CreatedAt.Equal(base) {
		t.Fatalf("get %v %+v", err, r1)
	}
	upd := *r1
	upd.Status = revisionApproved
	upd.Document = []byte(`{"tampered":true}`)
	upd.Comment = "tampered"
	upd.Approvals = []PolicyApproval{{By: "idp:bob", ByName: "bob", ByCategory: "human", At: base.Add(time.Hour), Decision: "approve", Comment: "ok"}}
	if err := s.UpdateRevision(ctx, upd); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRevision(ctx, upd); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	r1, _ = s.GetRevision(ctx, "p1")
	if r1.Status != revisionApproved || r1.Version != 2 || string(r1.Document) != `{"roles":{"rp1":{}}}` || r1.Comment != "cp1" ||
		len(r1.Approvals) != 1 || r1.Approvals[0].ByName != "bob" || !r1.Approvals[0].At.Equal(base.Add(time.Hour)) {
		t.Fatalf("after update %+v", r1)
	}
	toActive := *r1
	toActive.Status = revisionActive
	if err := s.UpdateRevision(ctx, toActive); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("update to active: %v", err)
	}
	if err := s.UpdateRevision(ctx, PolicyRevision{ID: "nope", Version: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}

	at := base.Add(2 * time.Hour)
	if err := s.Activate(ctx, "p1", "", "idp:bob", at); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, "p2", "", "idp:bob", at); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale expected: %v", err)
	}
	act, err := s.ActiveRevision(ctx)
	if err != nil || act.ID != "p1" || act.Status != revisionActive || act.ActivatedBy != "idp:bob" || act.ActivatedAt == nil || !act.ActivatedAt.Equal(at) {
		t.Fatalf("active %v %+v", err, act)
	}
	if err := s.Activate(ctx, "p2", "p1", "idp:bob", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.GetRevision(ctx, "p1"); r.Status != revisionSuperseded {
		t.Fatalf("previous %s", r.Status)
	}
	if act, _ := s.ActiveRevision(ctx); act.ID != "p2" {
		t.Fatalf("active %s", act.ID)
	}
	sup, _ := s.GetRevision(ctx, "p1")
	sup.Status = revisionApproved
	if err := s.UpdateRevision(ctx, *sup); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("revive superseded: %v", err)
	}

	r3, _ := s.GetRevision(ctx, "p3")
	r3.Status = "rejected"
	if err := s.UpdateRevision(ctx, *r3); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, "p3", "p2", "idp:bob", at); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("activate rejected: %v", err)
	}
	if err := s.Activate(ctx, "nope", "p2", "idp:bob", at); !errors.Is(err, ErrNotFound) {
		t.Fatalf("activate missing: %v", err)
	}

	page, cur, err := s.ListRevisions(ctx, "", 2, "")
	if err != nil || len(page) != 2 || page[0].ID != "p5" || page[1].ID != "p4" || cur == "" {
		t.Fatalf("page1 %v %+v", err, page)
	}
	page, cur, err = s.ListRevisions(ctx, "", 2, cur)
	if err != nil || len(page) != 2 || page[0].ID != "p3" || page[1].ID != "p2" || cur == "" {
		t.Fatalf("page2 %v %+v", err, page)
	}
	page, cur, err = s.ListRevisions(ctx, "", 2, cur)
	if err != nil || len(page) != 1 || page[0].ID != "p1" || cur != "" {
		t.Fatalf("page3 %v %q %+v", err, cur, page)
	}
	if got, _, _ := s.ListRevisions(ctx, revisionProposed, 0, ""); len(got) != 2 || got[0].ID != "p5" {
		t.Fatalf("proposed %+v", got)
	}
	if _, _, err := s.ListRevisions(ctx, "", 2, "%%"); err == nil {
		t.Fatal("bad cursor accepted")
	}

	// Concurrent activations from the same expected state: one winner.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := []string{"p4", "p5"}[i%2]
			err := s.Activate(ctx, id, "p2", "idp:bob", at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrConflict), errors.Is(err, ErrInvalidTransition):
			default:
				t.Errorf("activate: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent activations won", wins)
	}
	act, _ = s.ActiveRevision(ctx)
	other := map[string]string{"p4": "p5", "p5": "p4"}[act.ID]
	if r, _ := s.GetRevision(ctx, other); r.Status != revisionProposed {
		t.Fatalf("loser %s is %s", other, r.Status)
	}
	if r, _ := s.GetRevision(ctx, "p2"); r.Status != revisionSuperseded {
		t.Fatalf("p2 is %s", r.Status)
	}
	actives, _, _ := s.ListRevisions(ctx, revisionActive, 0, "")
	if len(actives) != 1 {
		t.Fatalf("%d active revisions", len(actives))
	}
}

func planConformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	now := clock.Now()
	changes := []uiapi.RRsetChange{{Host: "www", Type: "A", TTL: 600, Values: []string{"192.0.2.1"}, ExpectedHash: "h1"}}
	p := Plan{ID: "plan-a", Subject: "idp:alice", Zone: "example.com", Team: "web", Changes: changes, ZoneVersion: 7, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if err := s.PutPlan(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPlan(ctx, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate plan: %v", err)
	}
	if _, err := s.TakePlan(ctx, "plan-a", "idp:mallory", now); !errors.Is(err, ErrPlanOwner) {
		t.Fatalf("foreign take: %v", err)
	}
	got, err := s.TakePlan(ctx, "plan-a", "idp:alice", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone != "example.com" || got.Team != "web" || got.ZoneVersion != 7 || len(got.Changes) != 1 || got.Changes[0].ExpectedHash != "h1" || got.Changes[0].Values[0] != "192.0.2.1" ||
		!got.ExpiresAt.Equal(p.ExpiresAt.Truncate(time.Millisecond)) {
		t.Fatalf("taken plan %+v", got)
	}
	if _, err := s.TakePlan(ctx, "plan-a", "idp:alice", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take: %v", err)
	}

	if err := s.PutPlan(ctx, Plan{ID: "plan-b", Subject: "idp:alice", Zone: "example.com", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakePlan(ctx, "plan-b", "idp:alice", now.Add(2*time.Minute)); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("expired take: %v", err)
	}
	if _, err := s.TakePlan(ctx, "plan-b", "idp:alice", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired plan kept: %v", err)
	}

	var wg sync.WaitGroup
	if err := s.PutPlan(ctx, Plan{ID: "plan-c", Subject: "idp:alice", Zone: "example.com", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	taken := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.TakePlan(ctx, "plan-c", "idp:alice", now); err == nil {
				mu.Lock()
				taken++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if taken != 1 {
		t.Fatalf("plan taken %d times", taken)
	}

	for _, id := range []string{"plan-d", "plan-e"} {
		if err := s.PutPlan(ctx, Plan{ID: id, Subject: "idp:bob", Zone: "example.com", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutPlan(ctx, Plan{ID: "plan-f", Subject: "idp:bob", Zone: "example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	n, err := s.GCPlans(ctx, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, isDynamo := s.(*dynamo); !isDynamo && n != 2 {
		t.Fatalf("gc removed %d plans", n)
	}
	if _, err := s.TakePlan(ctx, "plan-f", "idp:bob", now); err != nil {
		t.Fatalf("gc removed a live plan: %v", err)
	}
}

func tombstoneConformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	now := clock.Now().UTC().Truncate(time.Millisecond)
	z := "tomb.example.com"
	tb := Tombstone{Zone: z, Host: "www", Type: "A", Team: "web", ContentHash: "h1", DeletedBy: "idp:alice", DeletedByName: "alice",
		DeletedByCategory: "human", DeletedAt: now, ExpiresAt: now.Add(time.Hour), RequestID: "r1"}
	if _, err := s.GetTombstone(ctx, z, "www", "A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent tombstone: %v", err)
	}
	if err := s.PutTombstone(ctx, tb); err != nil {
		t.Fatal(err)
	}
	tb.Team = "ops"
	if err := s.PutTombstone(ctx, tb); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, err := s.GetTombstone(ctx, z, "www", "A")
	if err != nil || got.Team != "ops" || got.ContentHash != "h1" || got.DeletedBy != "idp:alice" || !got.ExpiresAt.Equal(tb.ExpiresAt) || got.RequestID != "r1" {
		t.Fatalf("get tombstone %+v %v", got, err)
	}
	old := Tombstone{Zone: z, Host: "old", Type: "TXT", Team: "web", DeletedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := s.PutTombstone(ctx, old); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListTombstones(ctx, z)
	if err != nil || len(list) != 2 || list[0].Host != "old" || list[1].Host != "www" {
		t.Fatalf("list tombstones %+v %v", list, err)
	}
	n, err := s.GCTombstones(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, isDynamo := s.(*dynamo); !isDynamo && n != 1 {
		t.Fatalf("gc removed %d tombstones", n)
	}
	if err := s.Put(ctx, Ownership{Zone: z, Host: "gone", Type: "A", Owner: "web", State: StateActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	gone := Tombstone{Zone: z, Host: "gone", Type: "A", Team: "web", DeletedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.DeleteWithTombstone(ctx, z, "gone", "A", 7, gone); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete with tombstone: %v", err)
	}
	if _, err := s.GetTombstone(ctx, z, "gone", "A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused delete wrote its tombstone: %v", err)
	}
	if err := s.DeleteWithTombstone(ctx, z, "gone", "A", 1, gone); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, z, "gone", "A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ownership kept: %v", err)
	}
	if tb, err := s.GetTombstone(ctx, z, "gone", "A"); err != nil || tb.Team != "web" {
		t.Fatalf("tombstone of the delete: %+v %v", tb, err)
	}
	if err := s.DeleteWithTombstone(ctx, z, "gone", "A", 1, gone); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of an absent entry: %v", err)
	}
	if err := s.DeleteTombstone(ctx, z, "www", "A"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTombstone(ctx, z, "www", "A"); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	if _, err := s.GetTombstone(ctx, z, "www", "A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted tombstone: %v", err)
	}
}

func transferConformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	now := clock.Now().UTC().Truncate(time.Millisecond)
	mk := func(id, zone string, at time.Time) Transfer {
		return Transfer{ID: id, Kind: "rrsets", Zone: zone, FromTeam: "web", ToTeam: "ops", Status: "proposed",
			Items:     []TransferItem{{Host: "www", Type: "A", ContentHash: "h1"}, {Host: "old", Type: "TXT", Tombstone: true}},
			Requester: "idp:alice", RequesterName: "alice", Comment: "reorg", CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
	}
	a := mk("tr-a", "a.example.com", now)
	if err := s.CreateTransfer(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTransfer(ctx, a); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate transfer: %v", err)
	}
	got, err := s.GetTransfer(ctx, "tr-a")
	if err != nil || got.Version != 1 || len(got.Items) != 2 || !got.Items[1].Tombstone || got.Requester != "idp:alice" || !got.CreatedAt.Equal(now) {
		t.Fatalf("get transfer %+v %v", got, err)
	}
	if _, err := s.GetTransfer(ctx, "tr-none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown transfer: %v", err)
	}
	got.Status, got.DecidedBy = "applied", "idp:bob"
	at := now.Add(time.Minute)
	got.DecidedAt = &at
	if err := s.UpdateTransfer(ctx, *got); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTransfer(ctx, *got); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	upd, _ := s.GetTransfer(ctx, "tr-a")
	if upd.Status != "applied" || upd.DecidedBy != "idp:bob" || upd.Version != 2 || upd.DecidedAt == nil || !upd.DecidedAt.Equal(at) {
		t.Fatalf("updated transfer %+v", upd)
	}
	for i, zone := range []string{"a.example.com", "b.example.com", "a.example.com"} {
		if err := s.CreateTransfer(ctx, mk(fmt.Sprintf("tr-%d", i), zone, now.Add(time.Duration(i+1)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	page, next, err := s.ListTransfers(ctx, TransferQuery{Zone: "a.example.com", Limit: 2})
	if err != nil || len(page) != 2 || page[0].ID != "tr-2" || page[1].ID != "tr-0" || next == "" {
		t.Fatalf("first page %+v %q %v", page, next, err)
	}
	page, next, err = s.ListTransfers(ctx, TransferQuery{Zone: "a.example.com", Limit: 2, Cursor: next})
	if err != nil || len(page) != 1 || page[0].ID != "tr-a" || next != "" {
		t.Fatalf("second page %+v %q %v", page, next, err)
	}
	page, _, err = s.ListTransfers(ctx, TransferQuery{Status: "proposed"})
	if err != nil || len(page) != 3 {
		t.Fatalf("by status %+v %v", page, err)
	}
	n, err := s.GCTransfers(ctx, now.Add(time.Hour+1500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, isDynamo := s.(*dynamo); !isDynamo && n != 2 {
		t.Fatalf("gc removed %d transfers", n)
	}
}

func reassignConformance(t *testing.T, s Store, clock *fakeClock) {
	ctx := context.Background()
	now := clock.Now().UTC().Truncate(time.Millisecond)
	z := "reassign.example.com"
	for _, h := range []string{"a", "b"} {
		if err := s.Put(ctx, Ownership{Zone: z, Host: h, Type: "A", Owner: "web", State: StateActive, ContentHash: "h-" + h, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	tomb := Tombstone{Zone: z, Host: "c", Type: "A", Team: "web", DeletedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.PutTombstone(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get(ctx, z, "a", "A")
	b, _ := s.Get(ctx, z, "b", "A")
	stale := *b
	stale.Version = 9
	a.Owner, stale.Owner = "ops", "ops"
	moved := tomb
	moved.Team = "ops"
	if err := s.Reassign(ctx, "web", []Ownership{*a, stale}, []Tombstone{moved}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale reassign: %v", err)
	}
	if cur, _ := s.Get(ctx, z, "a", "A"); cur.Owner != "web" {
		t.Fatal("a conflicting reassign changed an entry")
	}
	if cur, _ := s.GetTombstone(ctx, z, "c", "A"); cur.Team != "web" {
		t.Fatal("a conflicting reassign changed a tombstone")
	}
	b.Owner = "ops"
	a.TransferID, b.TransferID = "tr-1", "tr-1"
	if err := s.Reassign(ctx, "web", []Ownership{*a, *b}, []Tombstone{moved}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"a", "b"} {
		cur, _ := s.Get(ctx, z, h, "A")
		if cur.Owner != "ops" || cur.Version != 2 || cur.ContentHash != "h-"+h || cur.TransferID != "tr-1" {
			t.Fatalf("reassigned %+v", cur)
		}
	}
	if cur, _ := s.GetTombstone(ctx, z, "c", "A"); cur.Team != "ops" {
		t.Fatalf("tombstone not reassigned: %+v", cur)
	}
	zones, err := s.ListOwnedZones(ctx)
	if err != nil || !slices.Contains(zones, z) || !slices.Contains(zones, "tomb.example.com") || !slices.IsSorted(zones) {
		t.Fatalf("owned zones %v %v", zones, err)
	}
	if err := s.Reassign(ctx, "web", nil, []Tombstone{moved}); !errors.Is(err, ErrConflict) {
		t.Fatalf("tombstone of another team: %v", err)
	}
	if err := s.Reassign(ctx, "web", make([]Ownership, MaxReassign+1), nil); err == nil {
		t.Fatal("oversized reassign accepted")
	}
}
