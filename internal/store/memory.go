package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

type memKey struct{ zone, host, typ string }

type memLock struct {
	holder  string
	expires time.Time
}

type memory struct {
	mu       sync.Mutex
	entries  map[memKey]Ownership
	versions map[string]int64
	locks    map[string]memLock
	audit    []memAudit

	revisions      map[string]PolicyRevision
	activeRevision string
	plans          map[string]Plan
	now            func() time.Time
}

func newMemory(now func() time.Time) *memory {
	return &memory{
		entries:   map[memKey]Ownership{},
		versions:  map[string]int64{},
		locks:     map[string]memLock{},
		revisions: map[string]PolicyRevision{},
		plans:     map[string]Plan{},
		now:       now,
	}
}

func (m *memory) Get(_ context.Context, zone, host, typ string) (*Ownership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.entries[memKey{zone, host, typ}]
	if !ok {
		return nil, ErrNotFound
	}
	return &o, nil
}

func (m *memory) List(_ context.Context, zone string) ([]Ownership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Ownership
	for k, o := range m.entries {
		if k.zone == zone {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

func (m *memory) Put(_ context.Context, o Ownership) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey{o.Zone, o.Host, o.Type}
	cur, exists := m.entries[k]
	switch {
	case o.Version == 0 && exists:
		return ErrConflict
	case o.Version != 0 && (!exists || cur.Version != o.Version):
		return ErrConflict
	}
	o.Version++
	m.entries[k] = o
	return nil
}

func (m *memory) Delete(_ context.Context, zone, host, typ string, version int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey{zone, host, typ}
	cur, ok := m.entries[k]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != version {
		return ErrConflict
	}
	delete(m.entries, k)
	return nil
}

func (m *memory) ZoneVersion(_ context.Context, zone string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.versions[zone], nil
}

func (m *memory) BumpZoneVersion(_ context.Context, zone string, expected int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.versions[zone] != expected {
		return 0, ErrConflict
	}
	m.versions[zone] = expected + 1
	return expected + 1, nil
}

func (m *memory) Lock(_ context.Context, zone, holder string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if l, ok := m.locks[zone]; ok && l.holder != holder && now.Before(l.expires) {
		return ErrLockHeld
	}
	m.locks[zone] = memLock{holder: holder, expires: now.Add(ttl)}
	return nil
}

func (m *memory) Unlock(_ context.Context, zone, holder string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.locks[zone]; ok && l.holder == holder {
		delete(m.locks, zone)
	}
	return nil
}

const memoryAuditCap = 10000

type memAudit struct {
	sk string
	e  audit.Event
}

func (m *memory) AppendAudit(_ context.Context, e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, memAudit{sk: auditSortKey(e), e: e})
	sort.SliceStable(m.audit, func(i, j int) bool { return m.audit[i].sk < m.audit[j].sk })
	if len(m.audit) > memoryAuditCap {
		m.audit = m.audit[len(m.audit)-memoryAuditCap:]
	}
	return nil
}

func (m *memory) ListAudit(_ context.Context, q AuditQuery) ([]audit.Event, string, error) {
	after, err := decodeCursor(q.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := auditLimit(q)
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for i := len(m.audit) - 1; i >= 0; i-- {
		a := m.audit[i]
		if after != "" && a.sk >= after {
			continue
		}
		if !matchAudit(a.e, q) {
			continue
		}
		if len(out) == limit {
			return out, encodeCursor(auditSortKey(out[len(out)-1])), nil
		}
		out = append(out, a.e)
	}
	return out, "", nil
}

func (m *memory) CreateRevision(_ context.Context, r PolicyRevision) error {
	if err := validateNewRevision(r); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.revisions[r.ID]; ok {
		return ErrConflict
	}
	r = cloneRevision(r)
	r.Version = 1
	m.revisions[r.ID] = r
	return nil
}

func (m *memory) GetRevision(_ context.Context, id string) (*PolicyRevision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.revisions[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := cloneRevision(r)
	return &c, nil
}

func (m *memory) ListRevisions(_ context.Context, status string, limit int, cursor string) ([]PolicyRevision, string, error) {
	m.mu.Lock()
	all := make([]PolicyRevision, 0, len(m.revisions))
	for _, r := range m.revisions {
		all = append(all, cloneRevision(r))
	}
	m.mu.Unlock()
	return pageRevisions(all, status, limit, cursor)
}

func (m *memory) UpdateRevision(_ context.Context, r PolicyRevision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.revisions[r.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != r.Version {
		return ErrConflict
	}
	if err := checkUpdateTransition(cur.Status, r.Status); err != nil {
		return err
	}
	cur.Status = r.Status
	cur.Approvals = append([]PolicyApproval(nil), r.Approvals...)
	cur.ActivatedAt, cur.ActivatedBy = utcPtr(r.ActivatedAt), r.ActivatedBy
	cur.Version++
	m.revisions[r.ID] = cur
	return nil
}

func (m *memory) ActiveRevision(ctx context.Context) (*PolicyRevision, error) {
	m.mu.Lock()
	id := m.activeRevision
	m.mu.Unlock()
	if id == "" {
		return nil, ErrNotFound
	}
	return m.GetRevision(ctx, id)
}

func (m *memory) Activate(_ context.Context, id, expectedActiveID, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	target, ok := m.revisions[id]
	if !ok {
		return ErrNotFound
	}
	if m.activeRevision != expectedActiveID {
		return ErrConflict
	}
	if !activatable(target.Status) {
		return ErrInvalidTransition
	}
	if prev, ok := m.revisions[expectedActiveID]; ok {
		prev.Status = revisionSuperseded
		prev.Version++
		m.revisions[prev.ID] = prev
	}
	at = at.UTC()
	target.Status, target.ActivatedAt, target.ActivatedBy = revisionActive, &at, by
	target.Version++
	m.revisions[id] = target
	m.activeRevision = id
	return nil
}
