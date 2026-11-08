package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OAuthGrant is the consent of a user to a declared OAuth client
// (oauth.clients): one per client and subject. It is the family of the
// refresh tokens of the client for the subject: only the hashes of the
// current and previous refresh tokens are kept.
type OAuthGrant struct {
	ID          string
	ClientID    string
	Subject     string // issuer:id
	SubjectName string
	Issuer      string // issuer name of the session the grant comes from
	// Session is the JSON of the session snapshot (claims, AMR), opaque to
	// the store.
	Session  []byte
	AuthTime int64 // unix seconds of the last sign-in at the gate, 0 if unknown
	Scopes   []string

	CreatedAt   time.Time
	ConsentedAt time.Time
	LastUsedAt  time.Time
	ExpiresAt   time.Time
	ClaimsAt    time.Time

	// Generation counts the refresh tokens issued; BaseGeneration is the
	// generation of the last consent. A token of a generation between
	// BaseGeneration and Generation-1 is a reused one.
	Generation     int64
	BaseGeneration int64
	RefreshHash    string
	PreviousHash   string
	RotatedAt      *time.Time
	// Pending is the sealed answer of the last rotation, served again
	// during the grace window.
	Pending string

	RevokedAt    *time.Time
	RevokedBy    string
	RevokeReason string
	Version      int64
}

// Active reports whether the grant is neither revoked nor expired at now.
func (g *OAuthGrant) Active(now time.Time) bool {
	return g.RevokedAt == nil && now.Before(g.ExpiresAt)
}

// OAuthGrantQuery filters ListOAuthGrants; empty fields match everything.
type OAuthGrantQuery struct {
	ClientID string
	Subject  string
}

// OAuthCode is a single-use authorization code of a declared client, keyed
// by the SHA-256 of the code. Data is opaque to the store.
type OAuthCode struct {
	Hash      string
	ClientID  string
	Data      []byte
	ExpiresAt time.Time
}

// OAuthGrantRetention is how long a revoked or expired grant is kept for
// the listing and the audit trail before PurgeOAuth removes it.
const OAuthGrantRetention = 30 * 24 * time.Hour

// OAuthStore persists the grants, authorization codes and client assertion
// ids of the gate authorization server. Implemented by every Store backend.
type OAuthStore interface {
	// CreateOAuthGrant stores a new grant with Version 1; ErrConflict if
	// the id exists.
	CreateOAuthGrant(ctx context.Context, g OAuthGrant) error
	// GetOAuthGrant returns a grant, ErrNotFound if unknown.
	GetOAuthGrant(ctx context.Context, id string) (*OAuthGrant, error)
	// ListOAuthGrants returns the matching grants, newest first.
	ListOAuthGrants(ctx context.Context, q OAuthGrantQuery) ([]OAuthGrant, error)
	// UpdateOAuthGrant writes every field but the id, client, subject and
	// creation time; g.Version must match the stored one, which becomes
	// g.Version + 1 (ErrConflict otherwise).
	UpdateOAuthGrant(ctx context.Context, g OAuthGrant) error
	// PutOAuthCode stores a code; ErrConflict if the hash exists.
	PutOAuthCode(ctx context.Context, c OAuthCode) error
	// TakeOAuthCode removes and returns a code, atomically: two concurrent
	// calls never both get it. ErrNotFound when unknown or already taken;
	// the caller checks the expiry.
	TakeOAuthCode(ctx context.Context, hash string) (*OAuthCode, error)
	// UseOAuthJTI records a client assertion id until exp; ErrConflict when
	// it is recorded and not expired at now (a replay).
	UseOAuthJTI(ctx context.Context, key string, exp, now time.Time) error
	// PurgeOAuth removes expired codes and assertion ids, and the grants
	// revoked or expired for OAuthGrantRetention. DynamoDB relies on its
	// TTL attribute and removes nothing.
	PurgeOAuth(ctx context.Context, now time.Time) (int, error)
}

var (
	_ OAuthStore = (*memory)(nil)
	_ OAuthStore = (*sqlStore)(nil)
	_ OAuthStore = (*dynamo)(nil)
)

func validateOAuthGrant(g OAuthGrant) error {
	if g.ID == "" || g.ClientID == "" || g.Subject == "" || g.Issuer == "" || g.CreatedAt.IsZero() || g.ExpiresAt.IsZero() {
		return errors.New("store: oauth grant id, client, subject, issuer, creation and expiry are required")
	}
	return nil
}

func cloneOAuthGrant(g OAuthGrant) OAuthGrant {
	g.Session = append([]byte(nil), g.Session...)
	g.Scopes = append([]string{}, g.Scopes...)
	g.CreatedAt, g.ConsentedAt, g.LastUsedAt = g.CreatedAt.UTC(), g.ConsentedAt.UTC(), g.LastUsedAt.UTC()
	g.ExpiresAt, g.ClaimsAt = g.ExpiresAt.UTC(), g.ClaimsAt.UTC()
	g.RotatedAt, g.RevokedAt = cloneTime(g.RotatedAt), cloneTime(g.RevokedAt)
	return g
}

func sortOAuthGrants(gs []OAuthGrant) {
	sort.Slice(gs, func(i, j int) bool {
		if !gs[i].CreatedAt.Equal(gs[j].CreatedAt) {
			return gs[i].CreatedAt.After(gs[j].CreatedAt)
		}
		return gs[i].ID > gs[j].ID
	})
}

func (q OAuthGrantQuery) match(g OAuthGrant) bool {
	return (q.ClientID == "" || g.ClientID == q.ClientID) && (q.Subject == "" || g.Subject == q.Subject)
}

func oauthGrantPurgeable(g OAuthGrant, now time.Time) bool {
	end := g.ExpiresAt
	if g.RevokedAt != nil && g.RevokedAt.Before(end) {
		end = *g.RevokedAt
	}
	return end.Add(OAuthGrantRetention).Before(now)
}

type memJTI struct{ exp time.Time }

func (m *memory) CreateOAuthGrant(_ context.Context, g OAuthGrant) error {
	if err := validateOAuthGrant(g); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.grants == nil {
		m.grants = map[string]OAuthGrant{}
	}
	if _, ok := m.grants[g.ID]; ok {
		return ErrConflict
	}
	g = cloneOAuthGrant(g)
	g.Version = 1
	m.grants[g.ID] = g
	return nil
}

func (m *memory) GetOAuthGrant(_ context.Context, id string) (*OAuthGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, ErrNotFound
	}
	g = cloneOAuthGrant(g)
	return &g, nil
}

func (m *memory) ListOAuthGrants(_ context.Context, q OAuthGrantQuery) ([]OAuthGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OAuthGrant{}
	for _, g := range m.grants {
		if q.match(g) {
			out = append(out, cloneOAuthGrant(g))
		}
	}
	sortOAuthGrants(out)
	return out, nil
}

func (m *memory) UpdateOAuthGrant(_ context.Context, g OAuthGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.grants[g.ID]
	if !ok || cur.Version != g.Version {
		return ErrConflict
	}
	n := cloneOAuthGrant(g)
	n.ClientID, n.Subject, n.CreatedAt = cur.ClientID, cur.Subject, cur.CreatedAt
	n.Version = cur.Version + 1
	m.grants[g.ID] = n
	return nil
}

func (m *memory) PutOAuthCode(_ context.Context, c OAuthCode) error {
	if c.Hash == "" || c.ClientID == "" {
		return errors.New("store: oauth code hash and client are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.codes == nil {
		m.codes = map[string]OAuthCode{}
	}
	if _, ok := m.codes[c.Hash]; ok {
		return ErrConflict
	}
	c.Data = append([]byte(nil), c.Data...)
	m.codes[c.Hash] = c
	return nil
}

func (m *memory) TakeOAuthCode(_ context.Context, hash string) (*OAuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[hash]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.codes, hash)
	return &c, nil
}

func (m *memory) UseOAuthJTI(_ context.Context, key string, exp, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.jtis == nil {
		m.jtis = map[string]memJTI{}
	}
	if cur, ok := m.jtis[key]; ok && !cur.exp.Before(now) {
		return ErrConflict
	}
	m.jtis[key] = memJTI{exp: exp}
	return nil
}

func (m *memory) PurgeOAuth(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, c := range m.codes {
		if c.ExpiresAt.Before(now) {
			delete(m.codes, k)
			n++
		}
	}
	for k, j := range m.jtis {
		if j.exp.Before(now) {
			delete(m.jtis, k)
			n++
		}
	}
	for k, g := range m.grants {
		if oauthGrantPurgeable(g, now) {
			delete(m.grants, k)
			n++
		}
	}
	return n, nil
}

const oauthGrantColumns = "id, client_id, subject, subject_name, issuer, session_data, auth_time, scopes, created_at, consented_at, last_used_at, expires_at, claims_at, generation, base_generation, refresh_hash, previous_hash, rotated_at, pending, revoked_at, revoked_by, revoke_reason, version"

func scanOAuthGrant(r scanner) (OAuthGrant, error) {
	var g OAuthGrant
	var session, scopes string
	var created, consented, used, expires, claimsAt int64
	var rotated, revoked sql.NullInt64
	if err := r.Scan(&g.ID, &g.ClientID, &g.Subject, &g.SubjectName, &g.Issuer, &session, &g.AuthTime, &scopes, &created, &consented, &used, &expires, &claimsAt,
		&g.Generation, &g.BaseGeneration, &g.RefreshHash, &g.PreviousHash, &rotated, &g.Pending, &revoked, &g.RevokedBy, &g.RevokeReason, &g.Version); err != nil {
		return g, err
	}
	g.Session = []byte(session)
	g.CreatedAt, g.ConsentedAt, g.LastUsedAt, g.ExpiresAt, g.ClaimsAt = fromMicros(created), fromMicros(consented), fromMicros(used), fromMicros(expires), fromMicros(claimsAt)
	for _, f := range []struct {
		v   sql.NullInt64
		dst **time.Time
	}{{rotated, &g.RotatedAt}, {revoked, &g.RevokedAt}} {
		if f.v.Valid {
			t := fromMicros(f.v.Int64)
			*f.dst = &t
		}
	}
	var err error
	g.Scopes, err = decodeStrings(scopes)
	return g, err
}

func (s *sqlStore) CreateOAuthGrant(ctx context.Context, g OAuthGrant) error {
	if err := validateOAuthGrant(g); err != nil {
		return err
	}
	scopes, err := encodeStrings(g.Scopes)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, "INSERT INTO oauth_grant ("+oauthGrantColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
		g.ID, g.ClientID, g.Subject, g.SubjectName, g.Issuer, string(g.Session), g.AuthTime, scopes, micros(g.CreatedAt), micros(g.ConsentedAt), micros(g.LastUsedAt),
		micros(g.ExpiresAt), micros(g.ClaimsAt), g.Generation, g.BaseGeneration, g.RefreshHash, g.PreviousHash, nullMicros(g.RotatedAt), g.Pending,
		nullMicros(g.RevokedAt), g.RevokedBy, g.RevokeReason, 1)
	if err != nil {
		return fmt.Errorf("store: create oauth grant: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) GetOAuthGrant(ctx context.Context, id string) (*OAuthGrant, error) {
	g, err := scanOAuthGrant(s.db.QueryRowContext(ctx, s.rebind("SELECT "+oauthGrantColumns+" FROM oauth_grant WHERE id = ?"), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get oauth grant: %w", err)
	}
	return &g, nil
}

func (s *sqlStore) ListOAuthGrants(ctx context.Context, q OAuthGrantQuery) ([]OAuthGrant, error) {
	var where []string
	var args []any
	if q.ClientID != "" {
		where, args = append(where, "client_id = ?"), append(args, q.ClientID)
	}
	if q.Subject != "" {
		where, args = append(where, "subject = ?"), append(args, q.Subject)
	}
	query := "SELECT " + oauthGrantColumns + " FROM oauth_grant"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(query+" ORDER BY created_at DESC, id DESC"), args...)
	if err != nil {
		return nil, fmt.Errorf("store: list oauth grants: %w", err)
	}
	defer rows.Close()
	out := []OAuthGrant{}
	for rows.Next() {
		g, err := scanOAuthGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list oauth grants: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *sqlStore) UpdateOAuthGrant(ctx context.Context, g OAuthGrant) error {
	scopes, err := encodeStrings(g.Scopes)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, `UPDATE oauth_grant SET subject_name = ?, issuer = ?, session_data = ?, auth_time = ?, scopes = ?, consented_at = ?, last_used_at = ?,
expires_at = ?, claims_at = ?, generation = ?, base_generation = ?, refresh_hash = ?, previous_hash = ?, rotated_at = ?, pending = ?, revoked_at = ?,
revoked_by = ?, revoke_reason = ?, version = version + 1 WHERE id = ? AND version = ?`,
		g.SubjectName, g.Issuer, string(g.Session), g.AuthTime, scopes, micros(g.ConsentedAt), micros(g.LastUsedAt), micros(g.ExpiresAt), micros(g.ClaimsAt),
		g.Generation, g.BaseGeneration, g.RefreshHash, g.PreviousHash, nullMicros(g.RotatedAt), g.Pending, nullMicros(g.RevokedAt), g.RevokedBy, g.RevokeReason,
		g.ID, g.Version)
	if err != nil {
		return fmt.Errorf("store: update oauth grant: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) PutOAuthCode(ctx context.Context, c OAuthCode) error {
	if c.Hash == "" || c.ClientID == "" {
		return errors.New("store: oauth code hash and client are required")
	}
	n, err := s.exec(ctx, "INSERT INTO oauth_code (hash, client_id, data, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT (hash) DO NOTHING",
		c.Hash, c.ClientID, string(c.Data), micros(c.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: put oauth code: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) TakeOAuthCode(ctx context.Context, hash string) (*OAuthCode, error) {
	c := OAuthCode{Hash: hash}
	var data string
	var exp int64
	err := s.db.QueryRowContext(ctx, s.rebind("DELETE FROM oauth_code WHERE hash = ? RETURNING client_id, data, expires_at"), hash).Scan(&c.ClientID, &data, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: take oauth code: %w", err)
	}
	c.Data, c.ExpiresAt = []byte(data), fromMicros(exp)
	return &c, nil
}

func (s *sqlStore) UseOAuthJTI(ctx context.Context, key string, exp, now time.Time) error {
	n, err := s.exec(ctx, "INSERT INTO oauth_jti (jti, expires_at) VALUES (?, ?) ON CONFLICT (jti) DO UPDATE SET expires_at = excluded.expires_at WHERE oauth_jti.expires_at < ?",
		key, micros(exp), micros(now))
	if err != nil {
		return fmt.Errorf("store: use oauth jti: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) PurgeOAuth(ctx context.Context, now time.Time) (int, error) {
	total := 0
	cut := micros(now.Add(-OAuthGrantRetention))
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"DELETE FROM oauth_code WHERE expires_at < ?", []any{micros(now)}},
		{"DELETE FROM oauth_jti WHERE expires_at < ?", []any{micros(now)}},
		{"DELETE FROM oauth_grant WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)", []any{cut, cut}},
	} {
		n, err := s.exec(ctx, q.sql, q.args...)
		if err != nil {
			return total, fmt.Errorf("store: purge oauth: %w", err)
		}
		total += int(n)
	}
	return total, nil
}
