// Package app wires the gate components from a configuration. It is shared
// by the dns-gate command and the end-to-end tests.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/KamorionLabs/dns-gate/internal/identity"
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
	// TransferRetryInterval overrides TransferRetryInterval (tests).
	TransferRetryInterval time.Duration
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
	now       func() time.Time

	// PlanGC deletes the expired RRset plans of MCP and of the REST API;
	// Run and Maintenance call it when set. New sets it to GCPlans.
	PlanGC func(context.Context) error
}

// New builds every component; background loops start with Run.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) (*App, error) {
	for _, w := range cfg.Warnings {
		log.Warn("configuration accepted with a warning", "warning", w)
	}
	var sources []discovery.Source
	var accounts []provider.Provider
	profiles := map[string]bool{}
	hasEuroDNS := false
	for _, pc := range cfg.Providers {
		p, err := newProvider(ctx, pc)
		if err != nil {
			return nil, err
		}
		hasEuroDNS = hasEuroDNS || pc.Kind == config.KindEuroDNS
		accounts = append(accounts, p)
		if pc.EuroDNS != nil && pc.EuroDNS.ZoneProfiles {
			profiles[pc.ID] = true
		}
		sources = append(sources, discovery.Source{Provider: p, Include: pc.Zones.Include, Exclude: pc.Zones.Exclude,
			Folders: pc.Zones.Folders, Refresh: pc.Zones.Refresh.D()})
	}

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
	disc := discovery.New(discovery.Config{Sources: sources, Logger: log, OnFolderChange: folderChangeAudit(auditLog, time.Now)})
	holder, err := policy.NewHolder(cfg)
	if err != nil {
		return nil, err
	}
	holder.SetDiscovery(disc)
	if err := holder.Refresh(ctx, st); err != nil {
		log.Error("managed policy not loaded: serving the base policy only, the grants of the managed layer are missing", "err", err)
	}
	authz := policy.New(holder)
	if opts.Holder == "" {
		opts.Holder = os.Getenv("POD_NAME")
	}
	if opts.Holder == "" {
		opts.Holder, _ = os.Hostname()
	}
	keys, _ := st.(store.APIKeyStore)
	an, err := authn.New(cfg, &http.Client{Timeout: 10 * time.Second}, holder)
	if err != nil {
		return nil, err
	}
	if keys != nil {
		an.SetAPIKeys(keys, auditLog)
	}
	an.SetLogger(log)
	eng, err := zonewrite.New(zonewrite.Config{
		Guard:                   server.ACMEGuard(keys),
		Providers:               disc,
		Store:                   st,
		Authz:                   authz,
		Audit:                   auditLog,
		ZoneSet:                 authz,
		UnmanagedTTL:            cfg.ReconcileInterval.D(),
		Holder:                  opts.Holder,
		LockTTL:                 cfg.Lock.TTL.D(),
		LockWait:                cfg.Lock.Wait.D(),
		CheckOnWrite:            *cfg.CheckOnWrite,
		EphemeralLifetimeFactor: cfg.Limits.EphemeralLifetimeFactor,
		TombstoneTTL:            cfg.TombstoneTTL(),
		TransferTTL:             cfg.Ownership.TransferTTL.D(),
		Teams:                   authz,
		Rebinder:                an,
		PersonClaims:            cfg.Ownership.PersonClaims,
		MachineApprovers:        cfg.Ownership.MachineApprovers,
		PersonIssuers:           cfg.Ownership.PersonIssuers,
		UntrustedEmail:          untrustedEmail(cfg),
		RequireSecondApprover:   cfg.Ownership.RequireSecondApprover,
		Now:                     time.Now,
		Logger:                  log,
	})
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
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
		APIKeys:     keys,
		Tombstones:  st,
		UIFiles:     web.FS(),
		Discovery:   disc,
		Log:         log,
	}
	if tr, ok := eng.(zonewrite.Transfers); ok {
		scfg.Transfers = tr
	}
	if hasEuroDNS {
		scfg.EuroDNS = eurodnsapi.New(eurodnsapi.Config{Engine: eng, Authz: authz, Providers: disc, Accounts: accounts, ZoneProfiles: profiles, Log: log})
	}
	srv, err := server.New(scfg)
	if err != nil {
		return nil, err
	}
	a := &App{Config: cfg, Store: st, Engine: eng, Policy: holder, Discovery: disc, authz: authz, handler: srv.Handler(), opts: opts, log: log, now: time.Now}
	a.PlanGC = a.GCPlans
	return a, nil
}

// ActionZoneFolderChanged is the audit action of a zone found in another
// provider folder than at the previous listing: the rules selecting zones by
// folder apply from then on.
const ActionZoneFolderChanged = "gate.zone.folder_changed"

// folderChangeAudit records the folder changes found by discovery.
func folderChangeAudit(l audit.Logger, now func() time.Time) func(context.Context, discovery.FolderChange) {
	return func(ctx context.Context, c discovery.FolderChange) {
		l.Log(ctx, audit.Event{
			Time: now().UTC(), Subject: "gate:discovery", SubjectName: "gate:discovery", SubjectCategory: identity.CategorySystem,
			Action: ActionZoneFolderChanged, Zone: c.Zone, Provider: c.Provider, Decision: "allow",
			Extra: map[string]any{"old": c.Old, "new": c.New},
		})
	}
}

// untrustedEmail lists the issuers whose email claim must not identify a
// person (issuers[].email_trusted: false).
func untrustedEmail(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	for _, is := range cfg.AllIssuers() {
		if is.EmailTrusted != nil && !*is.EmailTrusted {
			out[is.Name] = true
		}
	}
	return out
}

// CheckManagedPolicy validates the active managed revision of the store of
// cfg against the base policy of cfg (dns-gate --check): it returns the
// problems that would keep the gate from serving it, none when there is no
// active revision. The error tells that the store could not be read.
func CheckManagedPolicy(ctx context.Context, cfg *config.Config) ([]string, error) {
	st, err := openStore(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, err
	}
	if c, ok := st.(io.Closer); ok {
		defer c.Close()
	}
	rev, err := st.ActiveRevision(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, err := policy.DecodeDocument(rev.Document)
	if err != nil {
		return []string{fmt.Sprintf("active revision %s: %v", rev.ID, err)}, nil
	}
	h, err := policy.NewHolder(cfg)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range policy.ValidateManaged(cfg, h.Base(), doc) {
		out = append(out, fmt.Sprintf("active revision %s: %s: %s", rev.ID, e.Path, e.Message))
	}
	return out, nil
}

// GCPlans purges the expired RRset plans, the idle ACME registrations, the
// expired tombstones and the transfer requests expired for longer than
// store.TransferRetention.
func (a *App) GCPlans(ctx context.Context) error {
	now := a.now()
	n, err := a.Store.GCPlans(ctx, now)
	if n > 0 {
		a.log.Info("plan gc", "removed", n)
	}
	if keys, ok := a.Store.(store.APIKeyStore); ok {
		m, perr := keys.PurgeACMERegistrations(ctx, now)
		if m > 0 {
			a.log.Info("acme registration gc", "removed", m)
		}
		err = errors.Join(err, perr)
	}
	nt, terr := a.Store.GCTombstones(ctx, now)
	if nt > 0 {
		a.log.Info("tombstone gc", "removed", nt)
	}
	nr, rerr := a.Store.GCTransfers(ctx, now.Add(-store.TransferRetention))
	if nr > 0 {
		a.log.Info("transfer gc", "removed", nr)
	}
	return errors.Join(err, terr, rerr)
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
	go a.WarnUndeclaredOwners(ctx)
	go a.runTransferRetry(ctx)
}

// WarnUndeclaredOwners logs a warning for each team owning RRsets in a
// managed zone that the policy neither declares nor names (migration to the
// teams block): such a team is declared automatically until the block
// exists, and owns RRsets nobody may change once it does.
func (a *App) WarnUndeclaredOwners(ctx context.Context) {
	snap := a.Policy.Current()
	seen := map[string]bool{}
	for _, z := range a.authz.ManagedZones() {
		list, err := a.Store.List(ctx, z)
		if err != nil {
			a.log.Warn("ownership scan failed", "zone", z, "error", err)
			continue
		}
		for _, o := range list {
			if seen[o.Owner] {
				continue
			}
			seen[o.Owner] = true
			if _, known := snap.TeamInfo(o.Owner, nil, false); known {
				continue
			}
			if snap.StrictTeams() {
				a.log.Warn("team owns RRsets but is not declared: nobody can change them until it is declared or renamed", "team", o.Owner, "zone", z)
			} else {
				a.log.Warn("team owns RRsets but is not declared under teams: declared automatically for now", "team", o.Owner, "zone", z)
			}
		}
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
