package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const revisionColumns = "id, parent_id, document, author, author_name, author_cat, created_at, comment, status, approvals, activated_at, activated_by, version"

func scanRevision(r scanner) (PolicyRevision, error) {
	var rev PolicyRevision
	var doc, approvals string
	var created int64
	var activated sql.NullInt64
	if err := r.Scan(&rev.ID, &rev.ParentID, &doc, &rev.Author, &rev.AuthorName, &rev.AuthorCat, &created,
		&rev.Comment, &rev.Status, &approvals, &activated, &rev.ActivatedBy, &rev.Version); err != nil {
		return rev, err
	}
	rev.Document, rev.CreatedAt = []byte(doc), fromMicros(created)
	if err := json.Unmarshal([]byte(approvals), &rev.Approvals); err != nil {
		return rev, fmt.Errorf("decode approvals: %w", err)
	}
	if activated.Valid {
		t := fromMicros(activated.Int64)
		rev.ActivatedAt = &t
	}
	return rev, nil
}

func encodeApprovals(a []PolicyApproval) (string, error) {
	if a == nil {
		a = []PolicyApproval{}
	}
	b, err := json.Marshal(a)
	return string(b), err
}

func nullMicros(t *time.Time) any {
	if t == nil {
		return nil
	}
	return micros(*t)
}

func (s *sqlStore) CreateRevision(ctx context.Context, r PolicyRevision) error {
	if err := validateNewRevision(r); err != nil {
		return err
	}
	approvals, err := encodeApprovals(r.Approvals)
	if err != nil {
		return err
	}
	n, err := s.exec(ctx, "INSERT INTO policy_revision ("+revisionColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
		r.ID, r.ParentID, string(r.Document), r.Author, r.AuthorName, r.AuthorCat, micros(r.CreatedAt), r.Comment,
		r.Status, approvals, nullMicros(r.ActivatedAt), r.ActivatedBy, 1)
	if err != nil {
		return fmt.Errorf("store: create revision: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) GetRevision(ctx context.Context, id string) (*PolicyRevision, error) {
	rev, err := scanRevision(s.db.QueryRowContext(ctx, s.rebind("SELECT "+revisionColumns+" FROM policy_revision WHERE id = ?"), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get revision: %w", err)
	}
	return &rev, nil
}

func (s *sqlStore) ListRevisions(ctx context.Context, status string, limit int, cursor string) ([]PolicyRevision, string, error) {
	ct, cid, err := parseRevisionCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	limit = revisionLimit(limit)
	q := "SELECT " + revisionColumns + " FROM policy_revision WHERE 1 = 1"
	var args []any
	if status != "" {
		q += " AND status = ?"
		args = append(args, status)
	}
	if cursor != "" {
		q += " AND (created_at < ? OR (created_at = ? AND id < ?))"
		args = append(args, ct, ct, cid)
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, s.rebind(q), args...)
	if err != nil {
		return nil, "", fmt.Errorf("store: list revisions: %w", err)
	}
	defer rows.Close()
	var out []PolicyRevision
	for rows.Next() {
		rev, err := scanRevision(rows)
		if err != nil {
			return nil, "", fmt.Errorf("store: list revisions: %w", err)
		}
		out = append(out, rev)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(out) > limit {
		out = out[:limit]
		return out, revisionCursor(out[limit-1]), nil
	}
	return out, "", nil
}

func (s *sqlStore) UpdateRevision(ctx context.Context, r PolicyRevision) error {
	cur, err := s.GetRevision(ctx, r.ID)
	if err != nil {
		return err
	}
	if cur.Version != r.Version {
		return ErrConflict
	}
	if err := checkUpdateTransition(cur.Status, r.Status); err != nil {
		return err
	}
	approvals, err := encodeApprovals(r.Approvals)
	if err != nil {
		return err
	}
	// The status condition keeps a concurrent Activate from being overwritten.
	n, err := s.exec(ctx, `UPDATE policy_revision SET status = ?, approvals = ?, activated_at = ?, activated_by = ?, version = ?
		WHERE id = ? AND version = ? AND status = ?`,
		r.Status, approvals, nullMicros(r.ActivatedAt), r.ActivatedBy, r.Version+1, r.ID, r.Version, cur.Status)
	if err != nil {
		return fmt.Errorf("store: update revision: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *sqlStore) ActiveRevision(ctx context.Context) (*PolicyRevision, error) {
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT revision_id FROM policy_active WHERE k = 1").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: active revision: %w", err)
	}
	return s.GetRevision(ctx, id)
}

func (s *sqlStore) Activate(ctx context.Context, id, expectedActiveID, by string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: activate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	execTx := func(q string, args ...any) (int64, error) {
		res, err := tx.ExecContext(ctx, s.rebind(q), args...)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	var status string
	err = tx.QueryRowContext(ctx, s.rebind("SELECT status FROM policy_revision WHERE id = ?"), id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: activate: %w", err)
	}
	// Pointer first: concurrent activations serialize on this row.
	var n int64
	if expectedActiveID == "" {
		n, err = execTx("INSERT INTO policy_active (k, revision_id) VALUES (1, ?) ON CONFLICT (k) DO NOTHING", id)
	} else {
		n, err = execTx("UPDATE policy_active SET revision_id = ? WHERE k = 1 AND revision_id = ?", id, expectedActiveID)
	}
	if err != nil {
		return fmt.Errorf("store: activate: %w", err)
	}
	if n == 0 {
		return ErrConflict
	}
	n, err = execTx("UPDATE policy_revision SET status = ?, activated_at = ?, activated_by = ?, version = version + 1 WHERE id = ? AND status IN (?, ?)",
		revisionActive, micros(at), by, id, revisionProposed, revisionApproved)
	if err != nil {
		return fmt.Errorf("store: activate: %w", err)
	}
	if n == 0 {
		if !activatable(status) {
			return ErrInvalidTransition
		}
		return ErrConflict
	}
	if expectedActiveID != "" {
		if _, err := execTx("UPDATE policy_revision SET status = ?, version = version + 1 WHERE id = ?", revisionSuperseded, expectedActiveID); err != nil {
			return fmt.Errorf("store: activate: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: activate: %w", err)
	}
	return nil
}
