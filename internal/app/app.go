// Package app wires the gate components from a configuration. It is shared
// by the dns-gate command and the end-to-end tests.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/authn"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/discovery"
	"github.com/KamorionLabs/dns-gate/internal/eurodnsapi"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/provider"
	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	route53prov "github.com/KamorionLabs/dns-gate/internal/provider/route53"
	"github.com/KamorionLabs/dns-gate/internal/server"
	"github.com/KamorionLabs/dns-gate/internal/store"
	"github.com/KamorionLabs/dns-gate/internal/version"
	"github.com/KamorionLabs/dns-gate/internal/zonewrite"
	"github.com/KamorionLabs/dns-gate/web"
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
	Config *config.Config
	Store  store.Store
	Engine zonewrite.Engine
	Policy *policy.Holder
	// Discovery lists the zones of every provider account and resolves the
	// provider of each zone.
	Discovery *discovery.Discoverer
	authz     *policy.Engine
	handler   http.Handler
	opts      Options
	log       *slog.Logger

	// PlanGC deletes the expired RRset plans of MCP and of the REST API;
	// Run and Maintenance call it when set. New sets it to GCPlans.
	PlanGC func(context.Context) error
}

// New builds every component; background loops start with Run.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) (*App, error) {
	var sources []discovery.Source
	hasEuroDNS := false
	for _, pc := range cfg.Providers {
		p, err := newProvider(ctx, pc)
		if err != nil {
			return nil, err
		}
		hasEuroDNS = hasEuroDNS || pc.Kind == config.KindEuroDNS
		sources = append(sources, discovery.Source{Provider: p, Include: pc.Zones.Include, Exclude: pc.Zones.Exclude, Refresh: pc.Zones.Refresh.D()})
	}
	disc := discovery.New(discovery.Config{Sources: sources, Logger: log})

	if cfg.SingleReplicaStore() {
		if n, err := strconv.Atoi(os.Getenv("DNS_GATE_REPLICAS")); err == nil && n > 1 {
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
	holder.SetDiscovery(disc)
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
		Providers:    disc,
		Store:        st,
		Authz:        authz,
		Audit:        auditLog,
		ZoneSet:      authz,
		UnmanagedTTL: cfg.ReconcileInterval.D(),
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
	scfg := server.Config{
		Config:      cfg,
		Authn:       an,
		Authz:       authz,
		Engine:      eng,
		Audit:       auditLog,
		AuditReader: st,
		Policy:      holder,
		PolicyStore: st,
		Ownership:   st,
		Ops:         eng,
		Terraform:   server.InventoryTerraform(eng),
		Plans:       st,
		Versions:    st,
		UIFiles:     web.FS(),
		Discovery:   disc,
		Log:         log,
	}
	if hasEuroDNS {
		scfg.EuroDNS = eurodnsapi.New(eurodnsapi.Config{Engine: eng, Authz: authz, Providers: disc, Log: log})
	}
	srv, err := server.New(scfg)
	if err != nil {
		return nil, err
	}
	a := &App{Config: cfg, Store: st, Engine: eng, Policy: holder, Discovery: disc, authz: authz, handler: srv.Handler(), opts: opts, log: log}
	a.PlanGC = a.GCPlans
	return a, nil
}

// GCPlans purges the expired RRset plans of the store.
func (a *App) GCPlans(ctx context.Context) error {
	n, err := a.Store.GCPlans(ctx, time.Now())
	if n > 0 {
		a.log.Info("plan gc", "removed", n)
	}
	return err
}

// Handler is the HTTP handler of the gate.
func (a *App) Handler() http.Handler { return a.handler }

// Run starts the policy reload, zone discovery, reconcile and plan GC
// loops; they stop with ctx. Reconcile follows the managed zones of the
// current policy. It is the container mode; Maintenance is the one-pass
// equivalent for AWS Lambda.
func (a *App) Run(ctx context.Context) {
	go a.Policy.Run(ctx, a.Store, a.opts.PolicyReloadInterval, a.log)
	if a.Discovery != nil {
		go a.Discovery.Run(ctx)
	}
	go zonewrite.RunReconciler(ctx, a.Engine, a.authz.ManagedZones, a.Config.ReconcileInterval.D(), a.log)
	if a.PlanGC != nil {
		go a.runPlanGC(ctx, a.PlanGC)
	}
}

// newProvider builds the adapter of a configured provider.
func newProvider(ctx context.Context, pc config.Provider) (provider.Provider, error) {
	switch pc.Kind {
	case config.KindEuroDNS:
		e := pc.EuroDNS
		return eurodnsprov.New(pc.ID, eurodnsprov.Config{
			BaseURL: e.BaseURL, AppID: e.AppID, APIKey: e.APIKey,
			RateEvery: e.Rate.Every.D(), RateBurst: e.Rate.Burst, MaxRetries: *e.MaxRetries,
			UserAgent: "dns-gate/" + version.Version,
		})
	case config.KindRoute53:
		r := pc.Route53
		if r == nil {
			r = &config.Route53Config{}
		}
		return route53prov.New(ctx, pc.ID, route53prov.Config{
			Region: r.Region, AssumeRoleARN: r.AssumeRoleARN, ExternalID: r.ExternalID,
			HostedZones: r.HostedZones, IncludePrivate: r.IncludePrivate,
		})
	}
	return nil, fmt.Errorf("provider %s: unknown kind %q", pc.ID, pc.Kind)
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
