// Package app wires the gate components from a configuration. It is shared
// by the eurodns-gate command and the end-to-end tests.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/KamorionLabs/eurodns-gate/internal/audit"
	"github.com/KamorionLabs/eurodns-gate/internal/authn"
	"github.com/KamorionLabs/eurodns-gate/internal/config"
	"github.com/KamorionLabs/eurodns-gate/internal/policy"
	"github.com/KamorionLabs/eurodns-gate/internal/server"
	"github.com/KamorionLabs/eurodns-gate/internal/store"
	"github.com/KamorionLabs/eurodns-gate/internal/version"
	"github.com/KamorionLabs/eurodns-gate/internal/zonewrite"
	"github.com/KamorionLabs/eurodns-gate/web"
	eurodns "github.com/KamorionLabs/eurodns-go"
)

// Options tune runtime behaviour that is not part of the configuration file.
type Options struct {
	// PolicyReloadInterval overrides policy.ReloadInterval (tests).
	PolicyReloadInterval time.Duration
	// Holder is the lock holder id; defaults to POD_NAME or the hostname.
	Holder string
	// AuditOutput receives the JSON audit lines; defaults to stdout.
	AuditOutput *os.File
}

// App is a wired gate.
type App struct {
	Config  *config.Config
	Store   store.Store
	Engine  zonewrite.Engine
	Policy  *policy.Holder
	handler http.Handler
	opts    Options
	log     *slog.Logger
}

// New builds every component; background loops start with Run.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) (*App, error) {
	transport := eurodns.NewTransport(
		eurodns.WithAuth(eurodns.APIKeyAuth{AppID: cfg.Upstream.AppID, APIKey: cfg.Upstream.APIKey}),
		eurodns.WithRateLimit(cfg.Upstream.Rate.Every.D(), cfg.Upstream.Rate.Burst),
		eurodns.WithMaxRetries(*cfg.Upstream.MaxRetries),
		eurodns.WithUserAgent("eurodns-gate/"+version.Version),
	)
	client, err := eurodns.New(
		eurodns.WithBaseURL(cfg.Upstream.BaseURL),
		eurodns.WithTransport(transport),
		eurodns.WithUserAgent("eurodns-gate/"+version.Version),
	)
	if err != nil {
		return nil, err
	}

	if cfg.SingleReplicaStore() {
		if n, err := strconv.Atoi(os.Getenv("EURODNS_GATE_REPLICAS")); err == nil && n > 1 {
			log.Error("store does not support several replicas: ownership and locks would diverge", "store", cfg.Store.Type, "replicas", n)
		}
	}

	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	out := opts.AuditOutput
	if out == nil {
		out = os.Stdout
	}
	auditLog := &audit.Tee{Primary: audit.NewJSON(out), Store: st, ErrorLog: log}
	holder, err := policy.NewHolder(cfg)
	if err != nil {
		return nil, err
	}
	if err := holder.Refresh(ctx, st); err != nil {
		log.Error("managed policy not loaded, serving the base policy", "err", err)
	}
	authz := policy.New(holder)
	if opts.Holder == "" {
		opts.Holder = os.Getenv("POD_NAME")
	}
	if opts.Holder == "" {
		opts.Holder, _ = os.Hostname()
	}
	eng, err := zonewrite.New(zonewrite.Config{
		Client:       client,
		Store:        st,
		Authz:        authz,
		Audit:        auditLog,
		Zones:        cfg.Zones,
		Holder:       opts.Holder,
		LockTTL:      cfg.Lock.TTL.D(),
		LockWait:     cfg.Lock.Wait.D(),
		CheckOnWrite: *cfg.CheckOnWrite,
		Now:          time.Now,
		Logger:       log,
	})
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}

	an, err := authn.New(cfg, &http.Client{Timeout: 10 * time.Second}, holder)
	if err != nil {
		return nil, err
	}
	srv, err := server.New(server.Config{
		Config:      cfg,
		Authn:       an,
		Authz:       authz,
		Engine:      eng,
		Audit:       auditLog,
		AuditReader: st,
		Upstream:    transport,
		Policy:      holder,
		PolicyStore: st,
		Ownership:   st,
		Ops:         eng,
		Terraform:   server.InventoryTerraform(eng),
		UIFiles:     web.FS(),
		Log:         log,
	})
	if err != nil {
		return nil, err
	}
	return &App{Config: cfg, Store: st, Engine: eng, Policy: holder, handler: srv.Handler(), opts: opts, log: log}, nil
}

// Handler is the HTTP handler of the gate.
func (a *App) Handler() http.Handler { return a.handler }

// Run starts the policy reload and reconcile loops; they stop with ctx.
func (a *App) Run(ctx context.Context) {
	go a.Policy.Run(ctx, a.Store, a.opts.PolicyReloadInterval, a.log)
	go zonewrite.RunReconciler(ctx, a.Engine, a.Config.Zones, a.Config.ReconcileInterval.D(), a.log)
}

func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (store.Store, error) {
	switch cfg.Store.Type {
	case "sqlite":
		return store.NewSQLite(ctx, store.SQLiteConfig{
			Path:           cfg.Store.SQLite.Path,
			AuditRetention: cfg.Store.AuditRetention.D(),
		})
	case "postgres":
		return store.NewPostgres(ctx, store.PostgresConfig{
			DSN:            cfg.Store.Postgres.DSN,
			AuditRetention: cfg.Store.AuditRetention.D(),
			MaxConns:       cfg.Store.Postgres.MaxConns,
		})
	case "dynamodb":
		return store.NewDynamoDB(ctx, store.DynamoDBConfig{
			Table:          cfg.Store.DynamoDB.Table,
			Region:         cfg.Store.DynamoDB.Region,
			Endpoint:       cfg.Store.DynamoDB.Endpoint,
			AuditRetention: cfg.Store.AuditRetention.D(),
		})
	default:
		log.Warn("memory store: ownership is lost on restart, use it for tests only")
		return store.NewMemory(), nil
	}
}
