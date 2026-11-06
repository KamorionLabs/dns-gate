package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// Plan is a persisted RRset plan: the changes a subject planned on a zone at
// a zone version. It is applied at most once, before ExpiresAt, and only by
// the subject that created it.
type Plan struct {
	ID          string
	Subject     string // issuer:id
	Zone        string
	Team        string // team the subject selected for the plan, "" for its default team
	Changes     []uiapi.RRsetChange
	ZoneVersion int64
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

var (
	// ErrPlanOwner is returned by TakePlan when the plan belongs to another
	// subject; the plan is kept.
	ErrPlanOwner = errors.New("store: plan belongs to another subject")
	// ErrPlanExpired is returned by TakePlan for an expired plan, which is
	// removed.
	ErrPlanExpired = errors.New("store: plan expired")
)

// PlanStore persists RRset plans, shared by every gate instance (MCP
// plan_rrset_change and POST /api/v1/zones/{zone}/plan).
type PlanStore interface {
	// PutPlan stores a new plan; ErrConflict if the id exists.
	PutPlan(ctx context.Context, p Plan) error
	// TakePlan removes and returns the plan of subject, atomically: two
	// concurrent calls never both get it. ErrNotFound for an unknown or
	// already taken plan, ErrPlanOwner and ErrPlanExpired otherwise.
	TakePlan(ctx context.Context, id, subject string, now time.Time) (*Plan, error)
	// GCPlans removes the plans expired at now and returns how many were
	// removed. DynamoDB relies on its TTL attribute and removes nothing.
	GCPlans(ctx context.Context, now time.Time) (int, error)
}

func validatePlan(p Plan) error {
	if p.ID == "" || p.Subject == "" || p.Zone == "" || p.ExpiresAt.IsZero() {
		return errors.New("store: plan id, subject, zone and expiry are required")
	}
	return nil
}

func encodeChanges(c []uiapi.RRsetChange) (string, error) {
	if c == nil {
		c = []uiapi.RRsetChange{}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("store: encode plan: %w", err)
	}
	return string(b), nil
}

func decodeChanges(s string) ([]uiapi.RRsetChange, error) {
	var c []uiapi.RRsetChange
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil, fmt.Errorf("store: decode plan: %w", err)
	}
	return c, nil
}

func clonePlan(p Plan) (Plan, error) {
	s, err := encodeChanges(p.Changes)
	if err != nil {
		return Plan{}, err
	}
	if p.Changes, err = decodeChanges(s); err != nil {
		return Plan{}, err
	}
	p.CreatedAt, p.ExpiresAt = p.CreatedAt.UTC(), p.ExpiresAt.UTC()
	return p, nil
}

func (m *memory) PutPlan(_ context.Context, p Plan) error {
	if err := validatePlan(p); err != nil {
		return err
	}
	cp, err := clonePlan(p)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.plans[p.ID]; ok {
		return ErrConflict
	}
	m.plans[p.ID] = cp
	return nil
}

func (m *memory) TakePlan(_ context.Context, id, subject string, now time.Time) (*Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.plans[id]
	switch {
	case !ok:
		return nil, ErrNotFound
	case p.Subject != subject:
		return nil, ErrPlanOwner
	}
	delete(m.plans, id)
	if now.After(p.ExpiresAt) {
		return nil, ErrPlanExpired
	}
	return &p, nil
}

func (m *memory) GCPlans(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, p := range m.plans {
		if now.After(p.ExpiresAt) {
			delete(m.plans, id)
			n++
		}
	}
	return n, nil
}

func (s *sqlStore) PutPlan(ctx context.Context, p Plan) error {
	if err := validatePlan(p); err != nil {
		return err
	}
	changes, err := encodeChanges(p.Changes)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, "INSERT INTO rrset_plan (id, subject, zone, team, changes, zone_version, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
		p.ID, p.Subject, p.Zone, p.Team, changes, p.ZoneVersion, micros(p.CreatedAt), micros(p.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: put plan: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) TakePlan(ctx context.Context, id, subject string, now time.Time) (*Plan, error) {
	p := Plan{ID: id}
	var changes string
	var created, expires int64
	err := s.db.QueryRowContext(ctx, s.rebind("DELETE FROM rrset_plan WHERE id = ? AND subject = ? RETURNING subject, zone, team, changes, zone_version, created_at, expires_at"), id, subject).
		Scan(&p.Subject, &p.Zone, &p.Team, &changes, &p.ZoneVersion, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		var owner string
		err := s.db.QueryRowContext(ctx, s.rebind("SELECT subject FROM rrset_plan WHERE id = ?"), id).Scan(&owner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrNotFound
		case err != nil:
			return nil, fmt.Errorf("store: take plan: %w", err)
		}
		return nil, ErrPlanOwner
	}
	if err != nil {
		return nil, fmt.Errorf("store: take plan: %w", err)
	}
	p.CreatedAt, p.ExpiresAt = fromMicros(created), fromMicros(expires)
	if now.After(p.ExpiresAt) {
		return nil, ErrPlanExpired
	}
	if p.Changes, err = decodeChanges(changes); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *sqlStore) GCPlans(ctx context.Context, now time.Time) (int, error) {
	n, err := s.exec(ctx, "DELETE FROM rrset_plan WHERE expires_at < ?", micros(now))
	if err != nil {
		return 0, fmt.Errorf("store: gc plans: %w", err)
	}
	return int(n), nil
}
