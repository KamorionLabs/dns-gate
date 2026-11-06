package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// APIKey is a gate-issued API key (internal/apikey), bound to one team and
// one role. SecretHash is the hex SHA-256 of the current key; after a
// rotation PreviousHash stays valid until PreviousExpiresAt (the overlap
// period). A revoked key is kept, for the listing and the audit trail.
type APIKey struct {
	ID                string
	Name              string
	Description       string
	Team              string
	Role              string
	SecretHash        string
	PreviousHash      string
	PreviousExpiresAt *time.Time
	ExpiresAt         *time.Time
	AllowedCIDRs      []string
	CreatedAt         time.Time
	CreatedBy         string // issuer:id
	CreatedByName     string
	RotatedAt         *time.Time
	RevokedAt         *time.Time
	RevokedBy         string // issuer:id
	LastUsedAt        *time.Time
	LastUsedIP        string
	Version           int64 // optimistic concurrency
}

// APIKeyStore persists API keys. Implemented by every Store backend.
type APIKeyStore interface {
	// CreateAPIKey stores a new key with Version 1; ErrConflict if the id
	// exists.
	CreateAPIKey(ctx context.Context, k APIKey) error
	// GetAPIKey returns a key, ErrNotFound if unknown.
	GetAPIKey(ctx context.Context, id string) (*APIKey, error)
	// ListAPIKeys returns every key, oldest first.
	ListAPIKeys(ctx context.Context) ([]APIKey, error)
	// UpdateAPIKey writes the mutable fields of a key (name, description,
	// hashes, expiries, CIDRs, rotation and revocation); k.Version must
	// match the stored one, which becomes k.Version + 1. Team, role,
	// creation and last use never change.
	UpdateAPIKey(ctx context.Context, k APIKey) error
	// TouchAPIKey records the last use of a key, without version check;
	// ErrNotFound if unknown.
	TouchAPIKey(ctx context.Context, id string, at time.Time, ip string) error

	// PutACMERegistration creates (Version 0, ErrConflict if it exists) or
	// updates (Version must match) a registration; the stored Version
	// becomes Version + 1.
	PutACMERegistration(ctx context.Context, r ACMERegistration) error
	// GetACMERegistration returns a registration of a key, ErrNotFound if
	// unknown.
	GetACMERegistration(ctx context.Context, keyID, subdomain string) (*ACMERegistration, error)
	// ListACMERegistrations returns the registrations of a key, by domain.
	ListACMERegistrations(ctx context.Context, keyID string) ([]ACMERegistration, error)
	// DeleteACMERegistration removes a registration; no error if absent.
	DeleteACMERegistration(ctx context.Context, keyID, subdomain string) error
	// PurgeACMERegistrations removes the registrations whose ExpiresAt is
	// before now and returns how many were removed. DynamoDB relies on its
	// TTL attribute and removes nothing.
	PurgeACMERegistrations(ctx context.Context, now time.Time) (int, error)
}

// Origins of ACME registrations.
const (
	// ACMEOriginAPI: created with the key (acme_domains), kept in sync with it.
	ACMEOriginAPI = "api"
	// ACMEOriginClient: created by an acme-dns client (/register, or the
	// domain name used as subdomain).
	ACMEOriginClient = "client"
	// ACMEOriginHTTPReq: the values an owner wrote through httpreq.
	ACMEOriginHTTPReq = "httpreq"
)

// ACMERegistration maps an acme-dns subdomain to the domain whose
// _acme-challenge TXT RRset it writes. Values are the TXT values the
// registration wrote, oldest first: like acme-dns, only the two most recent
// are kept in the RRset.
type ACMERegistration struct {
	// KeyID is the owner: the id of an API key, or issuer:id of a token
	// subject, whose registrations are named after their domain.
	KeyID     string
	Subdomain string
	Domain    string
	Origin    string // ACMEOrigin*, ACMEOriginClient when empty
	AllowFrom []string
	Values    []string
	CreatedAt time.Time
	UpdatedAt time.Time
	// ExpiresAt, when set, is when PurgeACMERegistrations (or the DynamoDB
	// TTL) removes an idle registration.
	ExpiresAt *time.Time
	Version   int64
}

// MaxACMEValues is the number of TXT values an acme-dns registration keeps.
const MaxACMEValues = 2

func validateACMERegistration(r ACMERegistration) error {
	if r.KeyID == "" || r.Subdomain == "" || r.Domain == "" || r.CreatedAt.IsZero() {
		return errors.New("store: acme registration key id, subdomain, domain and creation time are required")
	}
	return nil
}

func cloneACMERegistration(r ACMERegistration) ACMERegistration {
	r.AllowFrom = append([]string{}, r.AllowFrom...)
	r.Values = append([]string{}, r.Values...)
	r.CreatedAt, r.UpdatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC(), cloneTime(r.ExpiresAt)
	if r.Origin == "" {
		r.Origin = ACMEOriginClient
	}
	return r
}

func sortACMERegistrations(rs []ACMERegistration) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Domain != rs[j].Domain {
			return rs[i].Domain < rs[j].Domain
		}
		return rs[i].Subdomain < rs[j].Subdomain
	})
}

type memRegKey struct{ key, sub string }

func (m *memory) PutACMERegistration(_ context.Context, r ACMERegistration) error {
	if err := validateACMERegistration(r); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acmeRegs == nil {
		m.acmeRegs = map[memRegKey]ACMERegistration{}
	}
	k := memRegKey{r.KeyID, r.Subdomain}
	cur, exists := m.acmeRegs[k]
	switch {
	case r.Version == 0 && exists:
		return ErrConflict
	case r.Version != 0 && (!exists || cur.Version != r.Version):
		return ErrConflict
	}
	n := cloneACMERegistration(r)
	n.Version = r.Version + 1
	m.acmeRegs[k] = n
	return nil
}

func (m *memory) GetACMERegistration(_ context.Context, keyID, subdomain string) (*ACMERegistration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.acmeRegs[memRegKey{keyID, subdomain}]
	if !ok {
		return nil, ErrNotFound
	}
	r = cloneACMERegistration(r)
	return &r, nil
}

func (m *memory) ListACMERegistrations(_ context.Context, keyID string) ([]ACMERegistration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ACMERegistration{}
	for k, r := range m.acmeRegs {
		if k.key == keyID {
			out = append(out, cloneACMERegistration(r))
		}
	}
	sortACMERegistrations(out)
	return out, nil
}

func (m *memory) DeleteACMERegistration(_ context.Context, keyID, subdomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.acmeRegs, memRegKey{keyID, subdomain})
	return nil
}

func (m *memory) PurgeACMERegistrations(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, r := range m.acmeRegs {
		if r.ExpiresAt != nil && r.ExpiresAt.Before(now) {
			delete(m.acmeRegs, k)
			n++
		}
	}
	return n, nil
}

var (
	_ APIKeyStore = (*memory)(nil)
	_ APIKeyStore = (*sqlStore)(nil)
	_ APIKeyStore = (*dynamo)(nil)
)

func validateAPIKey(k APIKey) error {
	if k.ID == "" || k.Team == "" || k.Role == "" || k.SecretHash == "" || k.CreatedAt.IsZero() {
		return errors.New("store: api key id, team, role, secret hash and creation time are required")
	}
	return nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func cloneAPIKey(k APIKey) APIKey {
	k.AllowedCIDRs = append([]string{}, k.AllowedCIDRs...)
	k.CreatedAt = k.CreatedAt.UTC()
	k.PreviousExpiresAt, k.ExpiresAt = cloneTime(k.PreviousExpiresAt), cloneTime(k.ExpiresAt)
	k.RotatedAt, k.RevokedAt, k.LastUsedAt = cloneTime(k.RotatedAt), cloneTime(k.RevokedAt), cloneTime(k.LastUsedAt)
	return k
}

func encodeStrings(c []string) (string, error) {
	if c == nil {
		c = []string{}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("store: encode string list: %w", err)
	}
	return string(b), nil
}

func decodeStrings(s string) ([]string, error) {
	out := []string{}
	if s == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("store: decode string list: %w", err)
	}
	return out, nil
}

func sortAPIKeys(keys []APIKey) {
	sort.Slice(keys, func(i, j int) bool {
		if !keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].CreatedAt.Before(keys[j].CreatedAt)
		}
		return keys[i].ID < keys[j].ID
	})
}

func (m *memory) CreateAPIKey(_ context.Context, k APIKey) error {
	if err := validateAPIKey(k); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.apiKeys == nil {
		m.apiKeys = map[string]APIKey{}
	}
	if _, ok := m.apiKeys[k.ID]; ok {
		return ErrConflict
	}
	k = cloneAPIKey(k)
	k.Version = 1
	m.apiKeys[k.ID] = k
	return nil
}

func (m *memory) GetAPIKey(_ context.Context, id string) (*APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return nil, ErrNotFound
	}
	k = cloneAPIKey(k)
	return &k, nil
}

func (m *memory) ListAPIKeys(context.Context) ([]APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]APIKey, 0, len(m.apiKeys))
	for _, k := range m.apiKeys {
		out = append(out, cloneAPIKey(k))
	}
	sortAPIKeys(out)
	return out, nil
}

func (m *memory) UpdateAPIKey(_ context.Context, k APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.apiKeys[k.ID]
	if !ok || cur.Version != k.Version {
		return ErrConflict
	}
	n := cloneAPIKey(k)
	n.Team, n.Role, n.CreatedAt, n.CreatedBy, n.CreatedByName = cur.Team, cur.Role, cur.CreatedAt, cur.CreatedBy, cur.CreatedByName
	n.LastUsedAt, n.LastUsedIP = cur.LastUsedAt, cur.LastUsedIP
	n.Version = cur.Version + 1
	m.apiKeys[k.ID] = n
	return nil
}

func (m *memory) TouchAPIKey(_ context.Context, id string, at time.Time, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return ErrNotFound
	}
	k.LastUsedAt, k.LastUsedIP = cloneTime(&at), ip
	m.apiKeys[id] = k
	return nil
}

const apiKeyColumns = "id, name, description, team, role, secret_hash, previous_hash, previous_expires_at, expires_at, allowed_cidrs, created_at, created_by, created_by_name, rotated_at, revoked_at, revoked_by, last_used_at, last_used_ip, version"

func scanAPIKey(r scanner) (APIKey, error) {
	var k APIKey
	var cidrs string
	var created int64
	var prevExp, exp, rotated, revoked, used sql.NullInt64
	if err := r.Scan(&k.ID, &k.Name, &k.Description, &k.Team, &k.Role, &k.SecretHash, &k.PreviousHash, &prevExp, &exp,
		&cidrs, &created, &k.CreatedBy, &k.CreatedByName, &rotated, &revoked, &k.RevokedBy, &used, &k.LastUsedIP, &k.Version); err != nil {
		return k, err
	}
	k.CreatedAt = fromMicros(created)
	var err error
	if k.AllowedCIDRs, err = decodeStrings(cidrs); err != nil {
		return k, err
	}
	for _, f := range []struct {
		v   sql.NullInt64
		dst **time.Time
	}{{prevExp, &k.PreviousExpiresAt}, {exp, &k.ExpiresAt}, {rotated, &k.RotatedAt}, {revoked, &k.RevokedAt}, {used, &k.LastUsedAt}} {
		if f.v.Valid {
			t := fromMicros(f.v.Int64)
			*f.dst = &t
		}
	}
	return k, nil
}

func (s *sqlStore) CreateAPIKey(ctx context.Context, k APIKey) error {
	if err := validateAPIKey(k); err != nil {
		return err
	}
	cidrs, err := encodeStrings(k.AllowedCIDRs)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, "INSERT INTO api_key ("+apiKeyColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
		k.ID, k.Name, k.Description, k.Team, k.Role, k.SecretHash, k.PreviousHash, nullMicros(k.PreviousExpiresAt), nullMicros(k.ExpiresAt),
		cidrs, micros(k.CreatedAt), k.CreatedBy, k.CreatedByName, nullMicros(k.RotatedAt), nullMicros(k.RevokedAt), k.RevokedBy,
		nullMicros(k.LastUsedAt), k.LastUsedIP, 1)
	if err != nil {
		return fmt.Errorf("store: create api key: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) GetAPIKey(ctx context.Context, id string) (*APIKey, error) {
	k, err := scanAPIKey(s.db.QueryRowContext(ctx, s.rebind("SELECT "+apiKeyColumns+" FROM api_key WHERE id = ?"), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get api key: %w", err)
	}
	return &k, nil
}

func (s *sqlStore) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+apiKeyColumns+" FROM api_key ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("store: list api keys: %w", err)
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list api keys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *sqlStore) UpdateAPIKey(ctx context.Context, k APIKey) error {
	cidrs, err := encodeStrings(k.AllowedCIDRs)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, `UPDATE api_key SET name = ?, description = ?, secret_hash = ?, previous_hash = ?, previous_expires_at = ?,
expires_at = ?, allowed_cidrs = ?, rotated_at = ?, revoked_at = ?, revoked_by = ?, version = version + 1 WHERE id = ? AND version = ?`,
		k.Name, k.Description, k.SecretHash, k.PreviousHash, nullMicros(k.PreviousExpiresAt), nullMicros(k.ExpiresAt), cidrs,
		nullMicros(k.RotatedAt), nullMicros(k.RevokedAt), k.RevokedBy, k.ID, k.Version)
	if err != nil {
		return fmt.Errorf("store: update api key: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) TouchAPIKey(ctx context.Context, id string, at time.Time, ip string) error {
	n, err := s.exec(ctx, "UPDATE api_key SET last_used_at = ?, last_used_ip = ? WHERE id = ?", micros(at), ip, id)
	if err != nil {
		return fmt.Errorf("store: touch api key: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const acmeRegColumns = "key_id, subdomain, domain, origin, allow_from, txt_values, created_at, updated_at, expires_at, version"

func scanACMERegistration(r scanner) (ACMERegistration, error) {
	var reg ACMERegistration
	var allow, values string
	var created, updated int64
	var expires sql.NullInt64
	if err := r.Scan(&reg.KeyID, &reg.Subdomain, &reg.Domain, &reg.Origin, &allow, &values, &created, &updated, &expires, &reg.Version); err != nil {
		return reg, err
	}
	reg.CreatedAt, reg.UpdatedAt = fromMicros(created), fromMicros(updated)
	if expires.Valid {
		t := fromMicros(expires.Int64)
		reg.ExpiresAt = &t
	}
	var err error
	if reg.AllowFrom, err = decodeStrings(allow); err != nil {
		return reg, err
	}
	reg.Values, err = decodeStrings(values)
	return reg, err
}

func (s *sqlStore) PutACMERegistration(ctx context.Context, r ACMERegistration) error {
	if err := validateACMERegistration(r); err != nil {
		return err
	}
	allow, err := encodeStrings(r.AllowFrom)
	if err != nil {
		return err
	}
	values, err := encodeStrings(r.Values)
	if err != nil {
		return err
	}
	origin := r.Origin
	if origin == "" {
		origin = ACMEOriginClient
	}
	var n int64
	if r.Version == 0 {
		n, err = s.exec(ctx, "INSERT INTO acme_registration ("+acmeRegColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key_id, subdomain) DO NOTHING",
			r.KeyID, r.Subdomain, r.Domain, origin, allow, values, micros(r.CreatedAt), micros(r.UpdatedAt), nullMicros(r.ExpiresAt), 1)
	} else {
		n, err = s.exec(ctx, "UPDATE acme_registration SET domain = ?, origin = ?, allow_from = ?, txt_values = ?, updated_at = ?, expires_at = ?, version = ? WHERE key_id = ? AND subdomain = ? AND version = ?",
			r.Domain, origin, allow, values, micros(r.UpdatedAt), nullMicros(r.ExpiresAt), r.Version+1, r.KeyID, r.Subdomain, r.Version)
	}
	if err != nil {
		return fmt.Errorf("store: put acme registration: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) GetACMERegistration(ctx context.Context, keyID, subdomain string) (*ACMERegistration, error) {
	r, err := scanACMERegistration(s.db.QueryRowContext(ctx, s.rebind("SELECT "+acmeRegColumns+" FROM acme_registration WHERE key_id = ? AND subdomain = ?"), keyID, subdomain))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get acme registration: %w", err)
	}
	return &r, nil
}

func (s *sqlStore) ListACMERegistrations(ctx context.Context, keyID string) ([]ACMERegistration, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind("SELECT "+acmeRegColumns+" FROM acme_registration WHERE key_id = ? ORDER BY domain, subdomain"), keyID)
	if err != nil {
		return nil, fmt.Errorf("store: list acme registrations: %w", err)
	}
	defer rows.Close()
	out := []ACMERegistration{}
	for rows.Next() {
		r, err := scanACMERegistration(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list acme registrations: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqlStore) DeleteACMERegistration(ctx context.Context, keyID, subdomain string) error {
	if _, err := s.exec(ctx, "DELETE FROM acme_registration WHERE key_id = ? AND subdomain = ?", keyID, subdomain); err != nil {
		return fmt.Errorf("store: delete acme registration: %w", err)
	}
	return nil
}

func (s *sqlStore) PurgeACMERegistrations(ctx context.Context, now time.Time) (int, error) {
	n, err := s.exec(ctx, "DELETE FROM acme_registration WHERE expires_at IS NOT NULL AND expires_at < ?", micros(now))
	if err != nil {
		return 0, fmt.Errorf("store: purge acme registrations: %w", err)
	}
	return int(n), nil
}
