package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// ReloadInterval is how often each replica checks the active revision.
const ReloadInterval = 10 * time.Second

// ActiveSource returns the active managed revision (store.PolicyStore).
type ActiveSource interface {
	ActiveRevision(ctx context.Context) (*store.PolicyRevision, error)
}

// Holder keeps the current compiled policy. Replicas poll the active
// revision id and recompile on change; evaluation reads an atomic pointer.
type Holder struct {
	cfg  *config.Config
	base uiapi.PolicyDocument
	disc Discovery
	cur  atomic.Pointer[Snapshot]
	mu   sync.Mutex // serializes refreshes
}

// NewHolder compiles the base layer.
func NewHolder(c *config.Config) (*Holder, error) {
	h := &Holder{cfg: c, base: BaseDocument(c)}
	h.cur.Store(compile(c, h.base, nil, "", nil))
	return h, nil
}

// SetDiscovery attaches the account zone list (zones_discovery): discovered
// zones that are not managed become readable. Call it before serving.
func (h *Holder) SetDiscovery(d Discovery) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disc = d
	cur := h.Current()
	h.cur.Store(compile(h.cfg, h.base, cur.Managed, cur.RevisionID, d))
}

// Discovery returns the account zone list, nil without zones_discovery.
func (h *Holder) Discovery() Discovery { return h.disc }

// Config returns the loaded configuration.
func (h *Holder) Config() *config.Config { return h.cfg }

// Current returns the current snapshot.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Base returns the base document.
func (h *Holder) Base() uiapi.PolicyDocument { return h.base }

// Compile validates and compiles a managed document against the base.
func (h *Holder) Compile(doc *uiapi.PolicyDocument, revisionID string) (*Snapshot, []uiapi.ValidationError) {
	if doc == nil {
		return compile(h.cfg, h.base, nil, "", h.disc), nil
	}
	if errs := ValidateManaged(h.cfg, h.base, *doc); len(errs) > 0 {
		return nil, errs
	}
	return compile(h.cfg, h.base, doc, revisionID, h.disc), nil
}

// CompileUnchecked compiles without validation (impact of old revisions,
// explain on a proposal that no longer validates).
func (h *Holder) CompileUnchecked(doc *uiapi.PolicyDocument, revisionID string) *Snapshot {
	return compile(h.cfg, h.base, doc, revisionID, h.disc)
}

// Refresh loads the active revision and swaps the snapshot when it changed.
func (h *Holder) Refresh(ctx context.Context, src ActiveSource) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rev, err := src.ActiveRevision(ctx)
	if errors.Is(err, store.ErrNotFound) {
		if h.Current().RevisionID != "" {
			h.cur.Store(compile(h.cfg, h.base, nil, "", h.disc))
		}
		return nil
	}
	if err != nil {
		return err
	}
	if rev.ID == h.Current().RevisionID {
		return nil
	}
	doc, err := DecodeDocument(rev.Document)
	if err != nil {
		return fmt.Errorf("revision %s: %w", rev.ID, err)
	}
	snap, errs := h.Compile(&doc, rev.ID)
	if len(errs) > 0 {
		// The base changed since activation: keep serving the previous
		// snapshot rather than silently dropping managed grants.
		return fmt.Errorf("revision %s no longer valid against the base policy: %s: %s", rev.ID, errs[0].Path, errs[0].Message)
	}
	h.cur.Store(snap)
	return nil
}

// Run refreshes every interval until ctx is done.
func (h *Holder) Run(ctx context.Context, src ActiveSource, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		every = ReloadInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := h.Refresh(ctx, src); err != nil && ctx.Err() == nil {
			log.Error("policy refresh failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// DecodeDocument parses a stored managed document strictly.
func DecodeDocument(b []byte) (uiapi.PolicyDocument, error) {
	var d uiapi.PolicyDocument
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	Normalize(&d)
	return d, nil
}

// Normalize replaces nil collections with empty ones.
func Normalize(d *uiapi.PolicyDocument) {
	if d.Groups == nil {
		d.Groups = map[string]uiapi.Group{}
	}
	if d.Roles == nil {
		d.Roles = map[string]uiapi.Role{}
	}
	if d.Bindings == nil {
		d.Bindings = []uiapi.Binding{}
	}
	if d.VirtualKeys == nil {
		d.VirtualKeys = []uiapi.VirtualKey{}
	}
	if d.Delegated != nil && len(d.Delegated.Roles) == 0 && len(d.Delegated.Bindings) == 0 {
		d.Delegated = nil
	}
	if len(d.Zones) == 0 {
		d.Zones = nil
		return
	}
	zones := make([]string, len(d.Zones)) // copy: documents are shared by snapshots
	for i, z := range d.Zones {
		zones[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
	}
	d.Zones = zones
}
