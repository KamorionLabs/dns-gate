package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

//go:embed migrations
var migrationsFS embed.FS

// SQLiteConfig configures the SQLite backend.
type SQLiteConfig struct {
	Path           string        // database file, on a persistent volume
	AuditRetention time.Duration // default 400 days
}

// PostgresConfig configures the PostgreSQL backend.
type PostgresConfig struct {
	DSN            string        // e.g. postgres://user:pass@host:5432/db?sslmode=require
	AuditRetention time.Duration // default 400 days
	MaxConns       int           // default 10
}

type dialect string

const (
	dialectSQLite   dialect = "sqlite"
	dialectPostgres dialect = "postgres"
)

const auditPurgeEvery = time.Hour

type sqlStore struct {
	db        *sql.DB
	dialect   dialect
	retention time.Duration
	now       func() time.Time

	purgeMu   sync.Mutex
	lastPurge time.Time
}

// NewSQLite opens (and migrates) a SQLite database. SQLite allows a single
// gate replica: run it with replicas=1 and a persistent volume.
func NewSQLite(ctx context.Context, cfg SQLiteConfig) (Store, error) {
	if cfg.Path == "" {
		return nil, errors.New("store: sqlite path is required")
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+cfg.Path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	// One connection: SQLite has a single writer, and this avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	return openSQL(ctx, db, dialectSQLite, cfg.AuditRetention)
}

// NewPostgres opens (and migrates) a PostgreSQL database. Several gate
// replicas may share it.
func NewPostgres(ctx context.Context, cfg PostgresConfig) (Store, error) {
	if cfg.DSN == "" {
		return nil, errors.New("store: postgres dsn is required")
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	max := cfg.MaxConns
	if max <= 0 {
		max = 10
	}
	db.SetMaxOpenConns(max)
	db.SetMaxIdleConns(max)
	db.SetConnMaxLifetime(30 * time.Minute)
	return openSQL(ctx, db, dialectPostgres, cfg.AuditRetention)
}

func openSQL(ctx context.Context, db *sql.DB, d dialect, retention time.Duration) (*sqlStore, error) {
	s := &sqlStore{db: db, dialect: d, retention: auditRetention(retention), now: time.Now}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: connect %s: %w", d, err)
	}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *sqlStore) Close() error { return s.db.Close() }

// rebind turns ? placeholders into $n for PostgreSQL.
func (s *sqlStore) rebind(q string) string {
	if s.dialect != dialectPostgres {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *sqlStore) exec(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.rebind(q), args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// migrate applies embedded migrations in one transaction, recording them in
// schema_migrations.
func (s *sqlStore) migrate(ctx context.Context) error {
	dir := "migrations/" + string(s.dialect)
	entries, err := fs.ReadDir(migrationsFS, dir)
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if s.dialect == dialectPostgres {
		// Serializes concurrent replicas starting together; released at commit.
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(4203571)"); err != nil {
			return fmt.Errorf("store: migrate lock: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL)"); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	applied := map[int]bool{}
	rows, err := tx.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("store: migrate: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: bad migration name %s", name)
		}
		if applied[v] {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, dir+"/"+name)
		if err != nil {
			return err
		}
		for _, stmt := range splitStatements(string(body)) {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("store: migration %s: %w", name, err)
			}
		}
		if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"), v, s.now().UTC().UnixMicro()); err != nil {
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
	}
	return tx.Commit()
}

func splitStatements(body string) []string {
	var out []string
	for _, part := range strings.Split(body, ";") {
		var lines []string
		for _, l := range strings.Split(part, "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "--") {
				lines = append(lines, l)
			}
		}
		if len(lines) > 0 {
			out = append(out, strings.Join(lines, "\n"))
		}
	}
	return out
}

func micros(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixMicro()
}

func fromMicros(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).UTC()
}

const ownershipColumns = "zone, host, type, owner, created_by, created_by_name, created_by_category, updated_by, updated_by_name, updated_by_category, created_at, updated_at, request_id, content_hash, pending_hash, state, adopted, expires_at, version, transfer_id"

func ownershipArgs(o Ownership, version int64) []any {
	var expires any
	if o.ExpiresAt != nil {
		expires = micros(*o.ExpiresAt)
	}
	adopted := 0
	if o.Adopted {
		adopted = 1
	}
	return []any{o.Zone, o.Host, o.Type, o.Owner, o.CreatedBy, o.CreatedByName, o.CreatedByCategory,
		o.UpdatedBy, o.UpdatedByName, o.UpdatedByCategory, micros(o.CreatedAt), micros(o.UpdatedAt),
		o.RequestID, o.ContentHash, o.PendingHash, string(o.State), adopted, expires, version, o.TransferID}
}

type scanner interface{ Scan(dest ...any) error }

func scanOwnership(r scanner) (Ownership, error) {
	var o Ownership
	var created, updated int64
	var expires sql.NullInt64
	var state string
	var adopted int
	err := r.Scan(&o.Zone, &o.Host, &o.Type, &o.Owner, &o.CreatedBy, &o.CreatedByName, &o.CreatedByCategory,
		&o.UpdatedBy, &o.UpdatedByName, &o.UpdatedByCategory, &created, &updated, &o.RequestID,
		&o.ContentHash, &o.PendingHash, &state, &adopted, &expires, &o.Version, &o.TransferID)
	if err != nil {
		return o, err
	}
	o.CreatedAt, o.UpdatedAt, o.State, o.Adopted = fromMicros(created), fromMicros(updated), State(state), adopted != 0
	if expires.Valid {
		t := fromMicros(expires.Int64)
		o.ExpiresAt = &t
	}
	return o, nil
}

func (s *sqlStore) Get(ctx context.Context, zone, host, typ string) (*Ownership, error) {
	row := s.db.QueryRowContext(ctx, s.rebind("SELECT "+ownershipColumns+" FROM ownership WHERE zone = ? AND host = ? AND type = ?"), zone, host, typ)
	o, err := scanOwnership(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get: %w", err)
	}
	return &o, nil
}

func (s *sqlStore) List(ctx context.Context, zone string) ([]Ownership, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind("SELECT "+ownershipColumns+" FROM ownership WHERE zone = ? ORDER BY host, type"), zone)
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	defer rows.Close()
	var out []Ownership
	for rows.Next() {
		o, err := scanOwnership(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *sqlStore) Put(ctx context.Context, o Ownership) error {
	var n int64
	var err error
	if o.Version == 0 {
		n, err = s.exec(ctx, "INSERT INTO ownership ("+ownershipColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (zone, host, type) DO NOTHING",
			ownershipArgs(o, 1)...)
	} else {
		args := ownershipArgs(o, o.Version+1)[3:]
		args = append(args, o.Zone, o.Host, o.Type, o.Version)
		n, err = s.exec(ctx, `UPDATE ownership SET owner = ?, created_by = ?, created_by_name = ?, created_by_category = ?,
			updated_by = ?, updated_by_name = ?, updated_by_category = ?, created_at = ?, updated_at = ?, request_id = ?,
			content_hash = ?, pending_hash = ?, state = ?, adopted = ?, expires_at = ?, version = ?, transfer_id = ?
			WHERE zone = ? AND host = ? AND type = ? AND version = ?`, args...)
	}
	if err != nil {
		return fmt.Errorf("store: put: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) Delete(ctx context.Context, zone, host, typ string, version int64) error {
	n, err := s.exec(ctx, "DELETE FROM ownership WHERE zone = ? AND host = ? AND type = ? AND version = ?", zone, host, typ, version)
	if err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	if n > 0 {
		return nil
	}
	if _, err := s.Get(ctx, zone, host, typ); errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return ErrConflict
}

func (s *sqlStore) ZoneVersion(ctx context.Context, zone string) (int64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, s.rebind("SELECT version FROM zone_meta WHERE zone = ?"), zone).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: zone version: %w", err)
	}
	return v, nil
}

func (s *sqlStore) BumpZoneVersion(ctx context.Context, zone string, expected int64) (int64, error) {
	n, err := s.exec(ctx, "UPDATE zone_meta SET version = ? WHERE zone = ? AND version = ?", expected+1, zone, expected)
	if err == nil && n == 0 && expected == 0 {
		n, err = s.exec(ctx, "INSERT INTO zone_meta (zone, version) VALUES (?, ?) ON CONFLICT (zone) DO NOTHING", zone, 1)
	}
	if err != nil {
		return 0, fmt.Errorf("store: bump zone version: %w", err)
	}
	if n == 0 {
		return 0, ErrConflict
	}
	return expected + 1, nil
}

func (s *sqlStore) Lock(ctx context.Context, zone, holder string, ttl time.Duration) error {
	now := s.now()
	n, err := s.exec(ctx, `INSERT INTO zone_lock (zone, holder, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (zone) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
		WHERE zone_lock.holder = excluded.holder OR zone_lock.expires_at < ?`,
		zone, holder, micros(now.Add(ttl)), micros(now))
	if err != nil {
		return fmt.Errorf("store: lock: %w", err)
	}
	if n == 0 {
		return ErrLockHeld
	}
	return nil
}

func (s *sqlStore) Unlock(ctx context.Context, zone, holder string) error {
	if _, err := s.exec(ctx, "DELETE FROM zone_lock WHERE zone = ? AND holder = ?", zone, holder); err != nil {
		return fmt.Errorf("store: unlock: %w", err)
	}
	return nil
}

// AppendAudit inserts the event and, at most once per hour per process,
// deletes events older than the retention.
func (s *sqlStore) AppendAudit(ctx context.Context, e audit.Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("store: encode audit: %w", err)
	}
	if _, err := s.exec(ctx, `INSERT INTO audit (time, request_id, zone, subject, subject_name, subject_category, decision, event)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, micros(e.Time), e.RequestID, e.Zone, e.Subject, e.SubjectName,
		e.SubjectCategory, e.Decision, string(body)); err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	s.purgeMu.Lock()
	due := s.now().Sub(s.lastPurge) >= auditPurgeEvery
	if due {
		s.lastPurge = s.now()
	}
	s.purgeMu.Unlock()
	if due {
		if _, err := s.PurgeAudit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// PurgeAudit deletes audit events older than the retention.
func (s *sqlStore) PurgeAudit(ctx context.Context) (int64, error) {
	n, err := s.exec(ctx, "DELETE FROM audit WHERE time < ?", micros(s.now().Add(-s.retention)))
	if err != nil {
		return 0, fmt.Errorf("store: purge audit: %w", err)
	}
	return n, nil
}

// SQL audit cursors are "<time micros>:<id>".
func (s *sqlStore) ListAudit(ctx context.Context, q AuditQuery) ([]audit.Event, string, error) {
	after, err := decodeCursor(q.Cursor)
	if err != nil {
		return nil, "", err
	}
	var curTime, curID int64
	if after != "" {
		t, id, ok := strings.Cut(after, ":")
		if curTime, err = strconv.ParseInt(t, 10, 64); !ok || err != nil {
			return nil, "", errBadCursor
		}
		if curID, err = strconv.ParseInt(id, 10, 64); err != nil {
			return nil, "", errBadCursor
		}
	}
	limit := auditLimit(q)
	where := []string{"1 = 1"}
	var args []any
	add := func(cond string, vals ...any) { where = append(where, cond); args = append(args, vals...) }
	if q.Zone != "" {
		add("zone = ?", q.Zone)
	}
	if q.Decision != "" {
		add("decision = ?", q.Decision)
	}
	if q.Category != "" {
		add("subject_category = ?", q.Category)
	}
	if q.Subject != "" {
		p := likePattern(q.Subject)
		add(`(LOWER(subject) LIKE ? ESCAPE '\' OR LOWER(subject_name) LIKE ? ESCAPE '\')`, p, p)
	}
	if !q.Since.IsZero() {
		add("time >= ?", micros(q.Since))
	}
	if !q.Until.IsZero() {
		add("time <= ?", micros(q.Until))
	}
	const batch = 200
	var out []audit.Event
	var lastTime, lastID int64
	for {
		conds := append([]string(nil), where...)
		qargs := append([]any(nil), args...)
		if after != "" {
			conds = append(conds, "(time < ? OR (time = ? AND id < ?))")
			qargs = append(qargs, curTime, curTime, curID)
		}
		qargs = append(qargs, batch)
		rows, err := s.db.QueryContext(ctx, s.rebind("SELECT id, time, event FROM audit WHERE "+strings.Join(conds, " AND ")+" ORDER BY time DESC, id DESC LIMIT ?"), qargs...)
		if err != nil {
			return nil, "", fmt.Errorf("store: list audit: %w", err)
		}
		n := 0
		for rows.Next() {
			n++
			var id, t int64
			var body string
			if err := rows.Scan(&id, &t, &body); err != nil {
				rows.Close()
				return nil, "", fmt.Errorf("store: list audit: %w", err)
			}
			curTime, curID, after = t, id, "set"
			var e audit.Event
			if err := json.Unmarshal([]byte(body), &e); err != nil {
				rows.Close()
				return nil, "", fmt.Errorf("store: decode audit: %w", err)
			}
			if !matchAudit(e, q) {
				continue
			}
			if len(out) == limit {
				rows.Close()
				return out, encodeCursor(fmt.Sprintf("%d:%d", lastTime, lastID)), nil
			}
			out = append(out, e)
			lastTime, lastID = t, id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, "", fmt.Errorf("store: list audit: %w", err)
		}
		if n < batch {
			return out, "", nil
		}
	}
}
