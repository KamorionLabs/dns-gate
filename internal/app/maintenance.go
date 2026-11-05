package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// PlanGCInterval is how often Run deletes the expired MCP plans.
const PlanGCInterval = 10 * time.Minute

// discoveryRetry is the age after which a failed zone listing is retried.
const discoveryRetry = 5 * time.Minute

// Maintenance runs one pass of the background work, for runtimes without
// long-lived goroutines (AWS Lambda, called by a schedule): policy refresh,
// zone discovery when older than its period, reconcile of every managed
// zone, then the expired plan GC. Every step runs even if a previous one
// failed; the errors are joined.
func (a *App) Maintenance(ctx context.Context) error {
	var errs []error
	if err := a.Policy.Refresh(ctx, a.Store); err != nil {
		errs = append(errs, fmt.Errorf("policy refresh: %w", err))
	}
	if a.Discovery != nil {
		if err := a.refreshDiscovery(ctx); err != nil {
			errs = append(errs, fmt.Errorf("zone discovery: %w", err))
		}
	}
	for _, z := range a.authz.ManagedZones() {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("reconcile: %w", err))
			break
		}
		if err := a.Engine.Reconcile(ctx, z); err != nil {
			a.log.Warn("reconcile failed", "zone", z, "error", err)
			errs = append(errs, fmt.Errorf("reconcile %s: %w", z, err))
		}
	}
	if a.PlanGC != nil {
		if err := a.PlanGC(ctx); err != nil {
			errs = append(errs, fmt.Errorf("plan gc: %w", err))
		}
	}
	return errors.Join(errs...)
}

// LambdaHandler is Handler for AWS Lambda, where no goroutine runs between
// invocations: before each request the policy is refreshed when older than
// the reload interval and the zone discovery when older than its period.
// Failures are logged and the request is served with the current state.
func (a *App) LambdaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.refreshStale(r.Context())
		a.handler.ServeHTTP(w, r)
	})
}

func (a *App) refreshStale(ctx context.Context) {
	if err := a.Policy.RefreshIfStale(ctx, a.Store, a.opts.PolicyReloadInterval); err != nil {
		a.log.Error("policy refresh failed", "err", err)
	}
	if a.Discovery != nil {
		if err := a.refreshDiscovery(ctx); err != nil {
			a.log.Warn("zone discovery failed", "error", err)
		}
	}
}

func (a *App) refreshDiscovery(ctx context.Context) error {
	age := a.Config.ZonesDiscovery.Refresh.D()
	if a.Discovery.Status().Err != nil {
		age = min(age, discoveryRetry)
	}
	return a.Discovery.RefreshIfOlder(ctx, age)
}

func (a *App) runPlanGC(ctx context.Context, gc func(context.Context) error) {
	t := time.NewTicker(PlanGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := gc(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("plan gc failed", "error", err)
		}
	}
}
