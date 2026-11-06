package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tombstone reserves a deleted RRset for the team that owned it: until
// ExpiresAt, only that team may create it again.
type Tombstone struct {
	Zone              string
	Host              string
	Type              string
	Team              string
	ContentHash       string // content hash of the RRset when it was deleted
	DeletedBy         string // issuer:id
	DeletedByName     string
	DeletedByCategory string
	DeletedAt         time.Time
	ExpiresAt         time.Time
	RequestID         string
}

// TombstoneStore persists tombstones.
type TombstoneStore interface {
	// PutTombstone creates or replaces the tombstone of an RRset.
	PutTombstone(ctx context.Context, t Tombstone) error
	// GetTombstone returns the tombstone of an RRset, ErrNotFound if none.
	// An expired tombstone may still be returned until it is collected:
	// callers compare ExpiresAt with the time.
	GetTombstone(ctx context.Context, zone, host, typ string) (*Tombstone, error)
	// ListTombstones returns the tombstones of a zone, sorted by host and type.
	ListTombstones(ctx context.Context, zone string) ([]Tombstone, error)
	// DeleteTombstone removes a tombstone; removing an absent one is not an error.
	DeleteTombstone(ctx context.Context, zone, host, typ string) error
	// GCTombstones removes the tombstones expired at now and returns how
	// many were removed. DynamoDB relies on its TTL attribute.
	GCTombstones(ctx context.Context, now time.Time) (int, error)
}

// TransferItem is one RRset of a transfer request.
type TransferItem struct {
	Host        string `json:"host"`
	Type        string `json:"type"`
	ContentHash string `json:"content_hash,omitempty"`
	Tombstone   bool   `json:"tombstone,omitempty"`
}

// Transfer is an ownership transfer request between two teams: RRsets of a
// zone (Kind rrsets), or every RRset of a team (Kind rename, Zone empty).
type Transfer struct {
	ID                string         `json:"id"`
	Kind              string         `json:"kind"`
	Zone              string         `json:"zone,omitempty"`
	FromTeam          string         `json:"from_team"`
	ToTeam            string         `json:"to_team"`
	Items             []TransferItem `json:"items,omitempty"`
	Comment           string         `json:"comment,omitempty"`
	Status            string         `json:"status"`
	Requester         string         `json:"requester"`
	RequesterName     string         `json:"requester_name,omitempty"`
	RequesterCategory string         `json:"requester_category,omitempty"`
	RequesterPerson   string         `json:"requester_person,omitempty"` // person key of the requester (ownership.person_claims)
	CreatedAt         time.Time      `json:"created_at"`
	ExpiresAt         time.Time      `json:"expires_at"`
	DecidedBy         string         `json:"decided_by,omitempty"`
	DecidedByName     string         `json:"decided_by_name,omitempty"`
	DecidedByCategory string         `json:"decided_by_category,omitempty"`
	DecidedAt         *time.Time     `json:"decided_at,omitempty"`
	DecisionComment   string         `json:"decision_comment,omitempty"`
	Moved             int            `json:"moved,omitempty"`
	Error             string         `json:"error,omitempty"`
	Version           int64          `json:"-"`
}

// TransferQuery filters ListTransfers. Limit defaults to 50, capped at 500.
type TransferQuery struct {
	Zone   string
	Status string
	Limit  int
	Cursor string
}

// MaxReassign is the largest number of ownership entries and tombstones
// Reassign changes at once.
const MaxReassign = 100

// TransferStore persists transfer requests and applies them.
type TransferStore interface {
	// CreateTransfer stores a new request; ErrConflict if the id exists.
	CreateTransfer(ctx context.Context, t Transfer) error
	// GetTransfer returns a request, ErrNotFound if unknown.
	GetTransfer(ctx context.Context, id string) (*Transfer, error)
	// ListTransfers returns requests newest first and an opaque cursor for
	// the next page ("" when there is none).
	ListTransfers(ctx context.Context, q TransferQuery) ([]Transfer, string, error)
	// UpdateTransfer writes a request whose Version must match; it is
	// incremented.
	UpdateTransfer(ctx context.Context, t Transfer) error
	// GCTransfers removes the requests whose expiry is before before and
	// returns how many were removed. DynamoDB relies on its TTL attribute.
	GCTransfers(ctx context.Context, before time.Time) (int, error)
	// Reassign changes, in one transaction, ownership entries (each Version
	// must match the stored one, as for Put) and tombstones (each must
	// still belong to from). ErrConflict when one of them changed; at most
	// MaxReassign items.
	Reassign(ctx context.Context, from string, owns []Ownership, tombs []Tombstone) error
}

var errReassignSize = fmt.Errorf("store: at most %d items can be reassigned at once", MaxReassign)

func validateTransfer(t Transfer) error {
	if t.ID == "" || t.Status == "" || t.FromTeam == "" || t.ToTeam == "" || t.CreatedAt.IsZero() || t.ExpiresAt.IsZero() {
		return errors.New("store: transfer id, status, teams, creation and expiry are required")
	}
	return nil
}

func cloneTransfer(t Transfer) Transfer {
	t.Items = append([]TransferItem(nil), t.Items...)
	t.CreatedAt, t.ExpiresAt = t.CreatedAt.UTC(), t.ExpiresAt.UTC()
	t.DecidedAt = utcPtr(t.DecidedAt)
	return t
}

func encodeTransfer(t Transfer) (string, error) {
	b, err := json.Marshal(cloneTransfer(t))
	if err != nil {
		return "", fmt.Errorf("store: encode transfer: %w", err)
	}
	return string(b), nil
}

func decodeTransfer(s string, version int64) (Transfer, error) {
	var t Transfer
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return t, fmt.Errorf("store: decode transfer: %w", err)
	}
	t.Version = version
	return t, nil
}

func transferLimit(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 500:
		return 500
	}
	return n
}

// Transfer cursors are "<created_at unix micros>:<id>", newest first.
func transferCursor(t Transfer) string {
	return encodeCursor(strconv.FormatInt(t.CreatedAt.UTC().UnixMicro(), 10) + ":" + t.ID)
}

func parseTransferCursor(c string) (int64, string, error) {
	raw, err := decodeCursor(c)
	if err != nil || raw == "" {
		return 0, "", err
	}
	t, id, ok := strings.Cut(raw, ":")
	micros, perr := strconv.ParseInt(t, 10, 64)
	if !ok || perr != nil {
		return 0, "", errBadCursor
	}
	return micros, id, nil
}

// pageTransfers filters, sorts and paginates an in-memory list.
func pageTransfers(all []Transfer, q TransferQuery) ([]Transfer, string, error) {
	ct, cid, err := parseTransferCursor(q.Cursor)
	if err != nil {
		return nil, "", err
	}
	sort.Slice(all, func(i, j int) bool {
		ti, tj := all[i].CreatedAt.UTC().UnixMicro(), all[j].CreatedAt.UTC().UnixMicro()
		if ti != tj {
			return ti > tj
		}
		return all[i].ID > all[j].ID
	})
	limit := transferLimit(q.Limit)
	var out []Transfer
	for _, t := range all {
		if (q.Zone != "" && t.Zone != q.Zone) || (q.Status != "" && t.Status != q.Status) {
			continue
		}
		if q.Cursor != "" {
			m := t.CreatedAt.UTC().UnixMicro()
			if m > ct || (m == ct && t.ID >= cid) {
				continue
			}
		}
		if len(out) == limit {
			return out, transferCursor(out[len(out)-1]), nil
		}
		out = append(out, t)
	}
	return out, "", nil
}

func tombKey(zone, host, typ string) memKey { return memKey{zone, host, typ} }

func (m *memory) PutTombstone(_ context.Context, t Tombstone) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tombstones[tombKey(t.Zone, t.Host, t.Type)] = t
	return nil
}

func (m *memory) GetTombstone(_ context.Context, zone, host, typ string) (*Tombstone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tombstones[tombKey(zone, host, typ)]
	if !ok {
		return nil, ErrNotFound
	}
	return &t, nil
}

func (m *memory) ListTombstones(_ context.Context, zone string) ([]Tombstone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Tombstone
	for k, t := range m.tombstones {
		if k.zone == zone {
			out = append(out, t)
		}
	}
	sortTombstones(out)
	return out, nil
}

func sortTombstones(ts []Tombstone) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].Host != ts[j].Host {
			return ts[i].Host < ts[j].Host
		}
		return ts[i].Type < ts[j].Type
	})
}

func (m *memory) DeleteTombstone(_ context.Context, zone, host, typ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tombstones, tombKey(zone, host, typ))
	return nil
}

func (m *memory) GCTombstones(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, t := range m.tombstones {
		if now.After(t.ExpiresAt) {
			delete(m.tombstones, k)
			n++
		}
	}
	return n, nil
}

func (m *memory) CreateTransfer(_ context.Context, t Transfer) error {
	if err := validateTransfer(t); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.transfers[t.ID]; ok {
		return ErrConflict
	}
	t = cloneTransfer(t)
	t.Version = 1
	m.transfers[t.ID] = t
	return nil
}

func (m *memory) GetTransfer(_ context.Context, id string) (*Transfer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.transfers[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := cloneTransfer(t)
	return &c, nil
}

func (m *memory) ListTransfers(_ context.Context, q TransferQuery) ([]Transfer, string, error) {
	m.mu.Lock()
	all := make([]Transfer, 0, len(m.transfers))
	for _, t := range m.transfers {
		all = append(all, cloneTransfer(t))
	}
	m.mu.Unlock()
	return pageTransfers(all, q)
}

func (m *memory) UpdateTransfer(_ context.Context, t Transfer) error {
	if err := validateTransfer(t); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.transfers[t.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != t.Version {
		return ErrConflict
	}
	t = cloneTransfer(t)
	t.Version++
	m.transfers[t.ID] = t
	return nil
}

func (m *memory) GCTransfers(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, t := range m.transfers {
		if t.ExpiresAt.Before(before) {
			delete(m.transfers, id)
			n++
		}
	}
	return n, nil
}

func (m *memory) Reassign(_ context.Context, from string, owns []Ownership, tombs []Tombstone) error {
	if len(owns)+len(tombs) > MaxReassign {
		return errReassignSize
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range owns {
		cur, ok := m.entries[memKey{o.Zone, o.Host, o.Type}]
		if !ok || cur.Version != o.Version {
			return ErrConflict
		}
	}
	for _, t := range tombs {
		cur, ok := m.tombstones[tombKey(t.Zone, t.Host, t.Type)]
		if !ok || cur.Team != from {
			return ErrConflict
		}
	}
	for _, o := range owns {
		o.Version++
		m.entries[memKey{o.Zone, o.Host, o.Type}] = o
	}
	for _, t := range tombs {
		m.tombstones[tombKey(t.Zone, t.Host, t.Type)] = t
	}
	return nil
}

const tombstoneColumns = "zone, host, type, team, content_hash, deleted_by, deleted_by_name, deleted_by_category, deleted_at, expires_at, request_id"

func tombstoneArgs(t Tombstone) []any {
	return []any{t.Zone, t.Host, t.Type, t.Team, t.ContentHash, t.DeletedBy, t.DeletedByName, t.DeletedByCategory,
		micros(t.DeletedAt), micros(t.ExpiresAt), t.RequestID}
}

func scanTombstone(r scanner) (Tombstone, error) {
	var t Tombstone
	var deleted, expires int64
	err := r.Scan(&t.Zone, &t.Host, &t.Type, &t.Team, &t.ContentHash, &t.DeletedBy, &t.DeletedByName, &t.DeletedByCategory,
		&deleted, &expires, &t.RequestID)
	t.DeletedAt, t.ExpiresAt = fromMicros(deleted), fromMicros(expires)
	return t, err
}

func (s *sqlStore) PutTombstone(ctx context.Context, t Tombstone) error {
	_, err := s.exec(ctx, "INSERT INTO ownership_tombstone ("+tombstoneColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "+
		"ON CONFLICT (zone, host, type) DO UPDATE SET team = excluded.team, content_hash = excluded.content_hash, "+
		"deleted_by = excluded.deleted_by, deleted_by_name = excluded.deleted_by_name, deleted_by_category = excluded.deleted_by_category, "+
		"deleted_at = excluded.deleted_at, expires_at = excluded.expires_at, request_id = excluded.request_id", tombstoneArgs(t)...)
	if err != nil {
		return fmt.Errorf("store: put tombstone: %w", err)
	}
	return nil
}

func (s *sqlStore) GetTombstone(ctx context.Context, zone, host, typ string) (*Tombstone, error) {
	row := s.db.QueryRowContext(ctx, s.rebind("SELECT "+tombstoneColumns+" FROM ownership_tombstone WHERE zone = ? AND host = ? AND type = ?"), zone, host, typ)
	t, err := scanTombstone(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get tombstone: %w", err)
	}
	return &t, nil
}

func (s *sqlStore) ListTombstones(ctx context.Context, zone string) ([]Tombstone, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind("SELECT "+tombstoneColumns+" FROM ownership_tombstone WHERE zone = ? ORDER BY host, type"), zone)
	if err != nil {
		return nil, fmt.Errorf("store: list tombstones: %w", err)
	}
	defer rows.Close()
	var out []Tombstone
	for rows.Next() {
		t, err := scanTombstone(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list tombstones: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqlStore) DeleteTombstone(ctx context.Context, zone, host, typ string) error {
	if _, err := s.exec(ctx, "DELETE FROM ownership_tombstone WHERE zone = ? AND host = ? AND type = ?", zone, host, typ); err != nil {
		return fmt.Errorf("store: delete tombstone: %w", err)
	}
	return nil
}

func (s *sqlStore) GCTombstones(ctx context.Context, now time.Time) (int, error) {
	n, err := s.exec(ctx, "DELETE FROM ownership_tombstone WHERE expires_at < ?", micros(now))
	if err != nil {
		return 0, fmt.Errorf("store: gc tombstones: %w", err)
	}
	return int(n), nil
}

func (s *sqlStore) CreateTransfer(ctx context.Context, t Transfer) error {
	if err := validateTransfer(t); err != nil {
		return err
	}
	doc, err := encodeTransfer(t)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, "INSERT INTO ownership_transfer (id, zone, status, created_at, expires_at, document, version) VALUES (?, ?, ?, ?, ?, ?, 1) ON CONFLICT (id) DO NOTHING",
		t.ID, t.Zone, t.Status, micros(t.CreatedAt), micros(t.ExpiresAt), doc)
	if err != nil {
		return fmt.Errorf("store: create transfer: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) GetTransfer(ctx context.Context, id string) (*Transfer, error) {
	var doc string
	var version int64
	err := s.db.QueryRowContext(ctx, s.rebind("SELECT document, version FROM ownership_transfer WHERE id = ?"), id).Scan(&doc, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get transfer: %w", err)
	}
	t, err := decodeTransfer(doc, version)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *sqlStore) ListTransfers(ctx context.Context, q TransferQuery) ([]Transfer, string, error) {
	ct, cid, err := parseTransferCursor(q.Cursor)
	if err != nil {
		return nil, "", err
	}
	query := "SELECT document, version FROM ownership_transfer WHERE 1 = 1"
	var args []any
	if q.Zone != "" {
		query += " AND zone = ?"
		args = append(args, q.Zone)
	}
	if q.Status != "" {
		query += " AND status = ?"
		args = append(args, q.Status)
	}
	if q.Cursor != "" {
		query += " AND (created_at < ? OR (created_at = ? AND id < ?))"
		args = append(args, ct, ct, cid)
	}
	limit := transferLimit(q.Limit)
	query += " ORDER BY created_at DESC, id DESC LIMIT " + strconv.Itoa(limit+1)
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, "", fmt.Errorf("store: list transfers: %w", err)
	}
	defer rows.Close()
	var out []Transfer
	for rows.Next() {
		var doc string
		var version int64
		if err := rows.Scan(&doc, &version); err != nil {
			return nil, "", fmt.Errorf("store: list transfers: %w", err)
		}
		t, err := decodeTransfer(doc, version)
		if err != nil {
			return nil, "", err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("store: list transfers: %w", err)
	}
	if len(out) > limit {
		out = out[:limit]
		return out, transferCursor(out[limit-1]), nil
	}
	return out, "", nil
}

func (s *sqlStore) UpdateTransfer(ctx context.Context, t Transfer) error {
	if err := validateTransfer(t); err != nil {
		return err
	}
	doc, err := encodeTransfer(t)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, "UPDATE ownership_transfer SET status = ?, expires_at = ?, document = ?, version = version + 1 WHERE id = ? AND version = ?",
		t.Status, micros(t.ExpiresAt), doc, t.ID, t.Version)
	if err != nil {
		return fmt.Errorf("store: update transfer: %w", err)
	}
	if n == 0 {
		if _, err := s.GetTransfer(ctx, t.ID); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) GCTransfers(ctx context.Context, before time.Time) (int, error) {
	n, err := s.exec(ctx, "DELETE FROM ownership_transfer WHERE expires_at < ?", micros(before))
	if err != nil {
		return 0, fmt.Errorf("store: gc transfers: %w", err)
	}
	return int(n), nil
}

func (s *sqlStore) Reassign(ctx context.Context, from string, owns []Ownership, tombs []Tombstone) error {
	if len(owns)+len(tombs) > MaxReassign {
		return errReassignSize
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: reassign: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	execTx := func(q string, args ...any) (int64, error) {
		res, err := tx.ExecContext(ctx, s.rebind(q), args...)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	for _, o := range owns {
		args := ownershipArgs(o, o.Version+1)[3:]
		args = append(args, o.Zone, o.Host, o.Type, o.Version)
		n, err := execTx(`UPDATE ownership SET owner = ?, created_by = ?, created_by_name = ?, created_by_category = ?,
			updated_by = ?, updated_by_name = ?, updated_by_category = ?, created_at = ?, updated_at = ?, request_id = ?,
			content_hash = ?, pending_hash = ?, state = ?, adopted = ?, expires_at = ?, version = ?
			WHERE zone = ? AND host = ? AND type = ? AND version = ?`, args...)
		if err != nil {
			return fmt.Errorf("store: reassign: %w", err)
		}
		if n == 0 {
			return ErrConflict
		}
	}
	for _, t := range tombs {
		n, err := execTx(`UPDATE ownership_tombstone SET team = ?, content_hash = ?, deleted_by = ?, deleted_by_name = ?,
			deleted_by_category = ?, deleted_at = ?, expires_at = ?, request_id = ?
			WHERE zone = ? AND host = ? AND type = ? AND team = ?`,
			t.Team, t.ContentHash, t.DeletedBy, t.DeletedByName, t.DeletedByCategory, micros(t.DeletedAt), micros(t.ExpiresAt), t.RequestID,
			t.Zone, t.Host, t.Type, from)
		if err != nil {
			return fmt.Errorf("store: reassign: %w", err)
		}
		if n == 0 {
			return ErrConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: reassign: %w", err)
	}
	return nil
}
