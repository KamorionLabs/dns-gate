// Command dns-gate runs the gate: an OIDC-authenticated, RBAC-enforcing
// proxy in front of the EuroDNS API that only modifies the records it owns.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/app"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/lambdarun"
	"github.com/KamorionLabs/dns-gate/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dns-gate:", err)
		os.Exit(1)
	}
}

func run() error {
	defaultURI := os.Getenv(config.EnvConfigURI)
	if defaultURI == "" {
		defaultURI = os.Getenv("DNS_GATE_CONFIG")
	}
	if defaultURI == "" {
		defaultURI = "/etc/dns-gate/config.yaml"
	}
	configURI := flag.String("config", defaultURI, "configuration: file path, s3://bucket/key or ssm:/parameter/name (env DNS_GATE_CONFIG_URI or DNS_GATE_CONFIG)")
	checkOnly := flag.Bool("check", false, "validate the configuration and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	src := &config.Sources{}
	loaded, err := src.LoadSecretsFromEnv(ctx)
	if err != nil {
		return err
	}
	if len(loaded) > 0 {
		log.Info("secrets loaded into the environment", "secret", os.Getenv(config.EnvSecretsARN), "variables", loaded)
	}
	cfg, err := src.Load(ctx, *configURI)
	if err != nil {
		return err
	}
	if *checkOnly {
		fmt.Println("configuration OK")
		return nil
	}

	if lambdarun.Enabled() {
		return runLambda(ctx, cfg, log)
	}

	gate, err := app.New(ctx, cfg, log, app.Options{})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen.Address,
		Handler:           gate.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second, // zone writes queue behind the upstream rate limit
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	gate.Run(ctx)

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "address", cfg.Listen.Address, "version", version.Version, "zones", cfg.Zones)
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(sctx); err != nil {
			return err
		}
	}
	return nil
}

// runLambda serves API Gateway and scheduled events; no goroutine outlives
// an invocation, the background work runs from the maintenance event.
func runLambda(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	gate, err := app.New(ctx, cfg, log, app.Options{Holder: lambdarun.InstanceID()})
	if err != nil {
		return err
	}
	log.Info("lambda ready", "version", version.Version, "zones", cfg.Zones)
	lambdarun.Start(&lambdarun.Handler{HTTP: gate.LambdaHandler(), Maintenance: gate.Maintenance, Log: log})
	return nil
}
