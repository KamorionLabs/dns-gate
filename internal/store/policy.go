package store

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Revision statuses, mirrored from uiapi to keep the store free of UI types.
const (
	revisionProposed   = "proposed"
	revisionApproved   = "approved"
	revisionActive     = "active"
	revisionSuperseded = "superseded"
)

const (
	defaultRevisionLimit = 50
	maxRevisionLimit     = 500
)

func revisionLimit(n int) int {
	switch {
	case n <= 0:
		return defaultRevisionLimit
	case n > maxRevisionLimit:
		return maxRevisionLimit
	}
	return n
}

// checkUpdateTransition enforces that only Activate moves revisions into or
// out of the active/superseded states.
func checkUpdateTransition(stored, next string) error {
	if stored == next {
		return nil
	}
	if stored == revisionActive || stored == revisionSuperseded || next == revisionActive || next == revisionSuperseded {
		return ErrInvalidTransition
	}
	return nil
}

func activatable(status string) bool { return status == revisionProposed || status == revisionApproved }

// Revision cursors are "<created_at unix micros>:<id>", newest first.
func revisionCursor(r PolicyRevision) string {
	return encodeCursor(strconv.FormatInt(r.CreatedAt.UTC().UnixMicro(), 10) + ":" + r.ID)
}

func parseRevisionCursor(c string) (int64, string, error) {
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

// newerFirst orders revisions by creation time then id, descending.
func newerFirst(a, b PolicyRevision) bool {
	ta, tb := a.CreatedAt.UTC().UnixMicro(), b.CreatedAt.UTC().UnixMicro()
	if ta != tb {
		return ta > tb
	}
	return a.ID > b.ID
}

// pageRevisions filters, sorts and paginates an in-memory revision list.
func pageRevisions(all []PolicyRevision, status string, limit int, cursor string) ([]PolicyRevision, string, error) {
	ct, cid, err := parseRevisionCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	sort.Slice(all, func(i, j int) bool { return newerFirst(all[i], all[j]) })
	limit = revisionLimit(limit)
	var out []PolicyRevision
	for _, r := range all {
		if status != "" && r.Status != status {
			continue
		}
		if cursor != "" {
			t := r.CreatedAt.UTC().UnixMicro()
			if t > ct || (t == ct && r.ID >= cid) {
				continue
			}
		}
		if len(out) == limit {
			return out, revisionCursor(out[len(out)-1]), nil
		}
		out = append(out, r)
	}
	return out, "", nil
}

func cloneRevision(r PolicyRevision) PolicyRevision {
	r.Document = append([]byte(nil), r.Document...)
	r.Approvals = append([]PolicyApproval(nil), r.Approvals...)
	if r.ActivatedAt != nil {
		t := *r.ActivatedAt
		r.ActivatedAt = &t
	}
	return r
}

func validateNewRevision(r PolicyRevision) error {
	if r.ID == "" {
		return fmt.Errorf("store: revision id is required")
	}
	if r.Status == revisionActive || r.Status == revisionSuperseded {
		return ErrInvalidTransition
	}
	return nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
