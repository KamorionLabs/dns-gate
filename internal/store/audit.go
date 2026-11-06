package store

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 500
	auditTimeLayout   = "2006-01-02T15:04:05.000000000Z"
)

var errBadCursor = errors.New("store: invalid audit cursor")

// auditSortKey orders events chronologically as a string. The event id
// makes it unique; events recorded before event ids use the request id.
func auditSortKey(e audit.Event) string {
	id := e.EventID
	if id == "" {
		id = e.RequestID
	}
	return e.Time.UTC().Format(auditTimeLayout) + "#" + id
}

func encodeCursor(sk string) string { return base64.RawURLEncoding.EncodeToString([]byte(sk)) }

func decodeCursor(c string) (string, error) {
	if c == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", errBadCursor
	}
	return string(b), nil
}

func auditLimit(q AuditQuery) int {
	switch {
	case q.Limit <= 0:
		return defaultAuditLimit
	case q.Limit > maxAuditLimit:
		return maxAuditLimit
	}
	return q.Limit
}

// matchAudit applies every filter except Zone and the cursor.
func matchAudit(e audit.Event, q AuditQuery) bool {
	if q.Zone != "" && e.Zone != q.Zone {
		return false
	}
	if q.Decision != "" && e.Decision != q.Decision {
		return false
	}
	if q.Category != "" && e.SubjectCategory != q.Category {
		return false
	}
	if q.Subject != "" && !containsFold(e.Subject, q.Subject) && !containsFold(e.SubjectName, q.Subject) {
		return false
	}
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Time.After(q.Until) {
		return false
	}
	if q.Host == "" && q.Type == "" {
		return true
	}
	for _, c := range e.Changes {
		if (q.Host == "" || strings.EqualFold(c.Host, q.Host)) && (q.Type == "" || strings.EqualFold(c.Type, q.Type)) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// likePattern builds a lowercase substring pattern for LIKE ... ESCAPE '\'.
func likePattern(sub string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(sub)) + "%"
}

func auditRetention(d time.Duration) time.Duration {
	if d <= 0 {
		return 400 * 24 * time.Hour
	}
	return d
}
