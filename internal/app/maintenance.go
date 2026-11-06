package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
)

// PlanGCInterval is how often Run deletes the expired RRset plans.
const PlanGCInterval = 15 * time.Minute

// Maintenance runs one pass of the background work, for runtimes without
// long-lived goroutines (AWS Lambda, called by a schedule): policy refresh,
// zone discovery when older than its period, reconcile of every managed
// zone, the retry of approved transfers left applying, then the expired plan
// GC. Every step runs even if a previous one
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
	if err := a.RetryTransfers(ctx); err != nil {
		errs = append(errs, fmt.Errorf("transfer retry: %w", err))
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
	return a.Discovery.RefreshDue(ctx)
}

// TransferRetryInterval is how often Run retries the approved transfers
// whose apply did not finish.
const TransferRetryInterval = time.Minute

// RetryTransfers applies the approved ownership transfers left applying
// (zone locked, store unavailable, gate restarted during the apply).
func (a *App) RetryTransfers(ctx context.Context) error {
	r, ok := a.Engine.(zonewrite.TransferRetrier)
	if !ok {
		return nil
	}
	n, err := r.RetryTransfers(ctx)
	if n > 0 {
		a.log.Info("transfers applied on retry", "applied", n)
	}
	return err
}

func (a *App) runTransferRetry(ctx context.Context) {
	t := time.NewTicker(TransferRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := a.RetryTransfers(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("transfer retry failed", "error", err)
		}
	}
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
