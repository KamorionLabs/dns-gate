package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
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

// Hash algorithms of a chain (hash_alg).
const (
	HashSHA256     = "sha256"      // anyone can recompute the chain
	HashHMACSHA256 = "hmac-sha256" // keyed: recomputing needs the chain key
)

// Options configure a JSONLogger.
type Options struct {
	// Format is native (default), ecs or ocsf.
	Format string
	// HashChain adds instance_id, seq, prev_hash, hash_alg and hash to every
	// line.
	HashChain bool
	// InstanceID names the chain; a new UUIDv7 when empty.
	InstanceID string
	// ChainKey makes the chain an HMAC-SHA256 (audit.hash_chain_key).
	ChainKey []byte
	// ErrorLog reports lines that could not be rendered.
	ErrorLog *slog.Logger
}

// JSONLogger writes one JSON object per line.
type JSONLogger struct {
	mu     sync.Mutex
	w      io.Writer
	now    func() time.Time
	format string
	chain  bool
	key    []byte
	inst   string
	seq    int64
	prev   string
	errLog *slog.Logger
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
	if len(o.ChainKey) > 0 && len(o.ChainKey) < 16 {
		return nil, fmt.Errorf("audit: chain key of %d bytes, at least 16 expected", len(o.ChainKey))
	}
	l := &JSONLogger{w: w, now: time.Now, format: o.Format, chain: o.HashChain, key: o.ChainKey, inst: o.InstanceID, prev: GenesisHash, errLog: o.ErrorLog}
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

// Log completes the event (Prepare) and writes it. A line that cannot be
// rendered is replaced by a minimal native line with render_error, so that
// the event and its place in the chain are not lost.
func (l *JSONLogger) Log(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	Prepare(ctx, &e)
	b, err := l.render(e)
	if err != nil {
		b = l.fallback(e, err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.chain {
		linked, err := l.link(b)
		if err != nil {
			linked, err = l.link(l.fallback(e, err))
		}
		if err != nil {
			l.report(e, err)
		} else {
			b = linked
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

// fallback is the line of an event that could not be rendered: the native
// identification fields and the error.
func (l *JSONLogger) fallback(e Event, cause error) []byte {
	l.report(e, cause)
	b, err := json.Marshal(struct {
		Type          string    `json:"type"`
		SchemaVersion string    `json:"schema_version"`
		EventID       string    `json:"event_id"`
		Time          time.Time `json:"time"`
		RequestID     string    `json:"request_id"`
		Subject       string    `json:"subject"`
		Action        string    `json:"action"`
		Zone          string    `json:"zone,omitempty"`
		Decision      string    `json:"decision"`
		Reason        string    `json:"reason,omitempty"`
		RenderError   string    `json:"render_error"`
	}{"audit", e.SchemaVersion, e.EventID, e.Time, e.RequestID, e.Subject, e.Action, e.Zone, e.Decision, e.Reason, cause.Error()})
	if err != nil {
		return []byte(`{"type":"audit","render_error":"unencodable event"}`)
	}
	return b
}

func (l *JSONLogger) report(e Event, err error) {
	if l.errLog != nil {
		l.errLog.Error("audit event not rendered as configured", "event_id", e.EventID, "action", e.Action, "err", err)
	}
}

// link appends the chain fields to a rendered object; the caller holds mu.
func (l *JSONLogger) link(b []byte) ([]byte, error) {
	seq := l.seq + 1
	inst, err := json.Marshal(l.inst)
	if err != nil {
		return nil, err
	}
	alg := HashSHA256
	if len(l.key) > 0 {
		alg = HashHMACSHA256
	}
	b = appendFields(b, `"instance_id":`+string(inst)+`,"seq":`+strconv.FormatInt(seq, 10)+`,"prev_hash":"`+l.prev+`","hash_alg":"`+alg+`"`)
	sum, err := hashObject(b, l.key)
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

// hashObject is the SHA-256 (hex), or the HMAC-SHA256 with key, of the
// canonical form of a JSON object without its "hash" member. Objects with
// a duplicated member, at any depth, are refused: decoders disagree on
// which value counts.
func hashObject(b []byte, key []byte) (string, error) {
	if err := noDuplicateKeys(b); err != nil {
		return "", err
	}
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
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write(c)
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// noDuplicateKeys walks the tokens of a JSON value and fails on an object
// with the same member twice.
func noDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	type frame struct {
		keys   map[string]bool
		object bool
		key    bool // next string token of an object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if top != nil && top.object {
					top.key = true
				}
				stack = append(stack, &frame{keys: map[string]bool{}, object: t == '{', key: t == '{'})
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
				continue
			}
		case string:
			if top != nil && top.object && top.key {
				if top.keys[t] {
					return fmt.Errorf("duplicate member %q", t)
				}
				top.keys[t] = true
				top.key = false
				continue
			}
		}
		if top != nil && top.object {
			top.key = true
		}
	}
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
