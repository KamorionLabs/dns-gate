package zonewrite

import (
	"context"
	"log/slog"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/audit"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// Config wires the engine.
type Config struct {
	Client       *eurodns.Client // upstream EuroDNS client (API key auth, shared transport)
	Store        store.Store
	Authz        policy.Authorizer
	Audit        audit.Logger
	Zones        []string      // managed zones; any other zone is refused
	Holder       string        // lock holder id (pod name)
	LockTTL      time.Duration // default 60s
	LockWait     time.Duration // default 30s
	CheckOnWrite bool          // call EuroDNS check before every save (default true in config)
	Now          func() time.Time
	Logger       *slog.Logger
}

// New builds the engine.
func New(cfg Config) (Engine, error) { return newEngine(cfg) }

// RunReconciler calls Reconcile for every managed zone every interval until
// ctx is done, staying within the upstream rate limit.
func RunReconciler(ctx context.Context, e Engine, zones []string, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		for _, z := range zones {
			if ctx.Err() != nil {
				return
			}
			if err := e.Reconcile(ctx, z); err != nil {
				log.Warn("reconcile failed", "zone", z, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
