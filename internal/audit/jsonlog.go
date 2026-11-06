package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// Output formats of the stdout lines (audit.format). The store always keeps
// the native event.
const (
	FormatNative = "native"
	FormatECS    = "ecs"
	FormatOCSF   = "ocsf"
)

// GenesisHash is the prev_hash of the first event of a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Options configure a JSONLogger.
type Options struct {
	// Format is native (default), ecs or ocsf.
	Format string
	// HashChain adds instance_id, seq, prev_hash and hash to every line.
	HashChain bool
	// InstanceID names the chain; a new UUIDv7 when empty.
	InstanceID string
}

// JSONLogger writes one JSON object per line.
type JSONLogger struct {
	mu     sync.Mutex
	w      io.Writer
	now    func() time.Time
	format string
	chain  bool
	inst   string
	seq    int64
	prev   string
}

// NewJSON returns a logger writing native lines to w (stdout in production).
func NewJSON(w io.Writer) *JSONLogger {
	l, _ := NewJSONWith(w, Options{})
	return l
}

// NewJSONWith returns a logger writing to w in the given format.
func NewJSONWith(w io.Writer, o Options) (*JSONLogger, error) {
	switch o.Format {
	case "":
		o.Format = FormatNative
	case FormatNative, FormatECS, FormatOCSF:
	default:
		return nil, fmt.Errorf("audit: unknown format %q (native, ecs or ocsf)", o.Format)
	}
	l := &JSONLogger{w: w, now: time.Now, format: o.Format, chain: o.HashChain, inst: o.InstanceID, prev: GenesisHash}
	if l.chain && l.inst == "" {
		l.inst = NewID(time.Now())
	}
	return l, nil
}

// InstanceID returns the id of the hash chain, empty without one.
func (l *JSONLogger) InstanceID() string {
	if !l.chain {
		return ""
	}
	return l.inst
}

// Log completes the event (Prepare) and writes it.
func (l *JSONLogger) Log(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	Prepare(ctx, &e)
	b, err := l.render(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.chain {
		if b, err = l.link(b); err != nil {
			return
		}
	}
	_, _ = l.w.Write(append(b, '\n'))
}

func (l *JSONLogger) render(e Event) ([]byte, error) {
	switch l.format {
	case FormatECS:
		return json.Marshal(ToECS(e))
	case FormatOCSF:
		return json.Marshal(ToOCSF(e))
	}
	return json.Marshal(struct {
		Type string `json:"type"`
		Event
	}{"audit", e})
}

// link appends the chain fields to a rendered object; the caller holds mu.
func (l *JSONLogger) link(b []byte) ([]byte, error) {
	seq := l.seq + 1
	b = appendFields(b, `"instance_id":`+strconv.Quote(l.inst)+`,"seq":`+strconv.FormatInt(seq, 10)+`,"prev_hash":"`+l.prev+`"`)
	sum, err := hashObject(b)
	if err != nil {
		return nil, err
	}
	l.seq, l.prev = seq, sum
	return appendFields(b, `"hash":"`+sum+`"`), nil
}

// appendFields inserts members before the closing brace of a JSON object.
func appendFields(obj []byte, members string) []byte {
	obj = bytes.TrimRight(obj, " \n")
	out := make([]byte, 0, len(obj)+len(members)+1)
	out = append(out, obj[:len(obj)-1]...)
	if len(obj) > 2 {
		out = append(out, ',')
	}
	out = append(out, members...)
	return append(out, '}')
}

// hashObject is the SHA-256 (hex) of the canonical form of a JSON object
// without its "hash" member.
func hashObject(b []byte) (string, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return "", err
	}
	delete(m, "hash")
	c, err := canonical(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// canonical encodes v with sorted object keys, no insignificant whitespace,
// no HTML escaping and normalized numbers, so that a line re-serialized by
// a log pipeline hashes the same.
func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalize(v)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
	case []any:
		for i, e := range x {
			x[i] = normalize(e)
		}
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return json.Number(strconv.FormatInt(i, 10))
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return x
		}
		if f < 1<<53 && f > -(1<<53) && f == float64(int64(f)) {
			return json.Number(strconv.FormatInt(int64(f), 10))
		}
		return json.Number(strconv.FormatFloat(f, 'g', -1, 64))
	}
	return v
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
	Prepare(ctx, &e)
	if t.Primary != nil {
		t.Primary.Log(ctx, e)
	}
	if t.Store == nil {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := t.Store.AppendAudit(sctx, e); err != nil && t.ErrorLog != nil {
		t.ErrorLog.Error("audit store append failed", "request_id", e.RequestID, "event_id", e.EventID, "err", err)
	}
}
