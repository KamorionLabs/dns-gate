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
	"github.com/KamorionLabs/dns-gate/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dns-gate:", err)
		os.Exit(1)
	}
}

func run() error {
	defaultPath := os.Getenv("DNS_GATE_CONFIG")
	if defaultPath == "" {
		defaultPath = "/etc/dns-gate/config.yaml"
	}
	configPath := flag.String("config", defaultPath, "configuration file (env DNS_GATE_CONFIG)")
	checkOnly := flag.Bool("check", false, "validate the configuration and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *checkOnly {
		fmt.Println("configuration OK")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
