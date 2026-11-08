// Package audit emits structured audit events.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// SchemaVersion is the version of the event schema (docs/AUDIT.md,
// api/audit-event.schema.json). Adding optional fields keeps it; renaming,
// removing or changing the meaning of a field increments it.
const SchemaVersion = "1"

// Authentication methods (Event.AuthMethod).
const (
	AuthOIDC          = "oidc"           // bearer JWT of a configured issuer
	AuthOIDCSession   = "oidc-session"   // UI session cookie of an OIDC login
	AuthSAMLSession   = "saml-session"   // UI session cookie of a SAML login
	AuthGateToken     = "gate-token"     // bearer JWT signed by the gate issuer
	AuthTokenExchange = "token-exchange" // token exchange request, or a gate token it issued
	AuthAPIKey        = "api-key"        // gate API key (dgk_...)
	AuthVirtualKey    = "virtual-key"    // X-App-Id / X-Api-Key virtual key
	// AuthOAuthDelegated is a bearer JWT of a configured issuer issued to a
	// delegated client (issuers[].delegated_clients).
	AuthOAuthDelegated = "oauth-delegated"
)

// SetClient records on the event the delegated client its subject acted
// through; an empty id leaves the event unchanged.
func (e *Event) SetClient(id, name string) {
	if id == "" {
		return
	}
	if name == "" {
		name = id
	}
	e.ClientID, e.Actor = id, &Actor{Type: ActorOAuthClient, ID: id, Name: name}
}

// ActorOAuthClient is the actor type of a delegated client.
const ActorOAuthClient = "oauth_client"

// Actor is the application acting for the subject of an event.
type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// MaxUserAgent is the length (bytes) user agents are truncated to.
const MaxUserAgent = 256

// Event is one audit record (JSON line).
type Event struct {
	SchemaVersion   string           `json:"schema_version,omitempty"`
	EventID         string           `json:"event_id,omitempty"`
	Time            time.Time        `json:"time"`
	RequestID       string           `json:"request_id"`
	Subject         string           `json:"subject"` // issuer:id
	SubjectName     string           `json:"subject_name,omitempty"`
	SubjectCategory string           `json:"subject_category,omitempty"` // human | pipeline | key
	AuthMethod      string           `json:"auth_method,omitempty"`
	ClientID        string           `json:"client_id,omitempty"`
	Actor           *Actor           `json:"actor,omitempty"`
	SourceIP        string           `json:"source_ip,omitempty"`
	UserAgent       string           `json:"user_agent,omitempty"`
	Teams           []string         `json:"teams,omitempty"`
	Action          string           `json:"action"` // operationId or gate action
	Zone            string           `json:"zone,omitempty"`
	Provider        string           `json:"provider,omitempty"` // id of the provider of the zone
	Decision        string           `json:"decision"`           // allow | deny | error
	Reason          string           `json:"reason,omitempty"`
	Changes         []uiapi.Change   `json:"changes,omitempty"`
	SnapshotID      uiapi.SnapshotID `json:"snapshot_id,omitempty"` // provider snapshot before a write
	Extra           map[string]any   `json:"extra,omitempty"`

	// captured: the request context was taken when the event was built
	// (Capture); Prepare must not fill it from the emitting context.
	captured bool
}

// Logger records events. Implementations must be safe for concurrent use.
type Logger interface {
	Log(ctx context.Context, e Event)
}

// Prepare completes an event before it is written: time, schema version,
// event id and the request context (source address, user agent,
// authentication method) when the event does not carry them. Events of
// system actors (gate:*) and captured events take nothing from ctx. It is
// idempotent, so the same id reaches stdout and the store.
func Prepare(ctx context.Context, e *Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.SchemaVersion == "" {
		e.SchemaVersion = SchemaVersion
	}
	if e.EventID == "" {
		e.EventID = NewID(e.Time)
	}
	if ri := requestFrom(ctx); ri != nil && !e.captured && e.SubjectCategory != "system" {
		if e.SourceIP == "" {
			e.SourceIP = ri.sourceIP
		}
		if e.UserAgent == "" {
			e.UserAgent = ri.userAgent
		}
		if e.AuthMethod == "" {
			e.AuthMethod = ri.method()
		}
		if e.ClientID == "" && e.Subject == "" {
			ri.clientInto(e)
		}
		ri.grantInto(e)
	}
	e.UserAgent = Truncate(e.UserAgent, MaxUserAgent)
}

// Capture records the request context of ctx in an event that may be
// emitted later, under another request (aggregated refusals): Prepare then
// keeps it instead of filling it from the emitting context. The event id is
// still assigned when the event is emitted.
func Capture(ctx context.Context, e *Event) {
	if ri := requestFrom(ctx); ri != nil {
		e.SourceIP, e.UserAgent, e.AuthMethod = ri.sourceIP, ri.userAgent, ri.method()
		if e.ClientID == "" && e.Subject == "" {
			ri.clientInto(e)
		}
		ri.grantInto(e)
	}
	e.captured = true
}

// NewID returns a UUIDv7 (RFC 9562): 48 bits of Unix milliseconds of t,
// then random bits. Ids sort by time at the millisecond.
func NewID(t time.Time) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.UnixMilli()))
	copy(b[:6], ts[2:])
	b[6] = 0x70 | (b[6] & 0x0f)
	b[8] = 0x80 | (b[8] & 0x3f)
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:], b[10:])
	return string(out[:])
}

// Truncate drops control characters and cuts s to at most n bytes without
// splitting a UTF-8 sequence.
func Truncate(s string, n int) string {
	if s == "" {
		return s
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Request is the context of an HTTP request recorded in its events.
type Request struct {
	SourceIP  string
	UserAgent string
}

type requestInfo struct {
	sourceIP, userAgent string
	mu                  sync.Mutex
	auth                string
	clientID            string
	clientName          string
	grantID             string
	scopes              []string
}

// grantInto adds the OAuth grant and scopes of the request to an event of
// its client (extra.grant_id, extra.scopes), unless the event sets them.
func (r *requestInfo) grantInto(e *Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.grantID == "" || e.ClientID != r.clientID {
		return
	}
	if _, ok := e.Extra["grant_id"]; ok {
		return
	}
	extra := map[string]any{"grant_id": r.grantID, "scopes": append([]string{}, r.scopes...)}
	for k, v := range e.Extra {
		extra[k] = v
	}
	e.Extra = extra
}

func (r *requestInfo) clientInto(e *Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clientID != "" {
		e.ClientID = r.clientID
		e.Actor = &Actor{Type: ActorOAuthClient, ID: r.clientID, Name: r.clientName}
	}
}

func (r *requestInfo) method() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.auth
}

type ctxKey struct{}

// WithRequest attaches the request context to ctx: the events logged with
// ctx, or a context derived from it, carry it.
func WithRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, ctxKey{}, &requestInfo{sourceIP: r.SourceIP, userAgent: Truncate(r.UserAgent, MaxUserAgent)})
}

// SetAuthMethod records how the request of ctx authenticates. It is set
// when the credential is read, before it is verified, so failed attempts
// carry it too. No-op without WithRequest.
func SetAuthMethod(ctx context.Context, method string) {
	if ri := requestFrom(ctx); ri != nil {
		ri.mu.Lock()
		ri.auth = method
		ri.mu.Unlock()
	}
}

// SetClient records the delegated client the request of ctx authenticates
// through: its events carry client_id and the actor. The id and name come
// from the configuration, never from token claims. No-op without
// WithRequest.
func SetClient(ctx context.Context, id, name string) {
	if ri := requestFrom(ctx); ri != nil {
		ri.mu.Lock()
		ri.clientID, ri.clientName = id, name
		ri.mu.Unlock()
	}
}

// SetGrant records the OAuth grant of the gate authorization server and
// the scopes the request authenticates with: the events of its client
// carry them in extra.grant_id and extra.scopes. No-op without
// WithRequest.
func SetGrant(ctx context.Context, grantID string, scopes []string) {
	if ri := requestFrom(ctx); ri != nil {
		ri.mu.Lock()
		ri.grantID, ri.scopes = grantID, append([]string(nil), scopes...)
		ri.mu.Unlock()
	}
}

// AuthMethodFrom returns the authentication method recorded in ctx.
func AuthMethodFrom(ctx context.Context) string {
	if ri := requestFrom(ctx); ri != nil {
		return ri.method()
	}
	return ""
}

func requestFrom(ctx context.Context) *requestInfo {
	if ctx == nil {
		return nil
	}
	ri, _ := ctx.Value(ctxKey{}).(*requestInfo)
	return ri
}
