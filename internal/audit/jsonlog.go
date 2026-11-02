package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"
)

// JSONLogger writes one JSON object per line.
type JSONLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() time.Time
}

// NewJSON returns a logger writing to w (stdout in production).
func NewJSON(w io.Writer) *JSONLogger {
	return &JSONLogger{enc: json.NewEncoder(w), now: time.Now}
}

// Log writes the event, filling Time when zero.
func (l *JSONLogger) Log(_ context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(struct {
		Type string `json:"type"`
		Event
	}{"audit", e})
}

// Appender persists events (store.Store implements it).
type Appender interface {
	AppendAudit(ctx context.Context, e Event) error
}

// Tee writes every event to a primary logger and appends it to a store.
// A store failure is logged, never propagated: the request already happened.
type Tee struct {
	Primary  Logger
	Store    Appender
	ErrorLog *slog.Logger
}

// Log implements Logger.
func (t *Tee) Log(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if t.Primary != nil {
		t.Primary.Log(ctx, e)
	}
	if t.Store == nil {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := t.Store.AppendAudit(sctx, e); err != nil && t.ErrorLog != nil {
		t.ErrorLog.Error("audit store append failed", "request_id", e.RequestID, "err", err)
	}
}
