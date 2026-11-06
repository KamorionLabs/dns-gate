// Command quickstart runs a local sandbox for the dns-gate quickstart: an
// in-memory EuroDNS API holding the zone example.com, and a local OpenID
// issuer that signs tokens for any subject. Start the gate next to it with
// examples/quickstart/config.yaml (see docs/quickstart.md).
//
// Nothing here talks to a real DNS provider or identity provider.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/oidctest"
	"github.com/KamorionLabs/eurodns-go"
	"github.com/KamorionLabs/eurodns-go/eurodnstest"
)

const (
	providerAddr = "127.0.0.1:8053"
	issuerAddr   = "127.0.0.1:8090"
	audience     = "dns-gate"
)

var subjectRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func main() {
	dir := flag.String("dir", filepath.Join(os.TempDir(), "dns-gate-quickstart"), "directory for the generated gate keys")
	user := flag.String("ui-user", "alice", "subject signed in to the web UI")
	flag.Parse()
	if err := run(*dir, *user); err != nil {
		log.Fatal(err)
	}
}

func run(dir, uiUser string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fake := eurodnstest.NewServer(eurodnstest.Options{})
	fake.Seed(&eurodns.Zone{Name: "example.com", Records: []eurodns.Record{
		{Type: "A", Host: "", TTL: 3600, RData: "192.0.2.10"},
		{Type: "MX", Host: "", TTL: 3600, RData: "10 mx.example.net."},
		{Type: "TXT", Host: "", TTL: 3600, RData: `"v=spf1 -all"`},
		{Type: "CNAME", Host: "www", TTL: 3600, RData: "web.example.net."},
	}})
	providerHandler := fake.Config.Handler
	fake.Close()

	idp := oidctest.New()
	idpHandler := idp.Config.Handler
	idp.Close()
	idp.URL = "http://" + issuerAddr
	idp.LoginClaims = map[string]any{"sub": uiUser, "name": uiUser}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /mint", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		if !subjectRE.MatchString(sub) {
			http.Error(w, "sub: a lowercase name expected, e.g. /mint?sub=alice", http.StatusBadRequest)
			return
		}
		now := time.Now()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, idp.Sign(map[string]any{
			"sub": sub, "name": sub, "aud": audience,
			"auth_time": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}))
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		idp.LoginClaims["auth_time"] = time.Now().Unix()
		idpHandler.ServeHTTP(w, r)
	})
	mux.Handle("/", idpHandler)

	env, err := writeKeys(dir)
	if err != nil {
		return err
	}

	servers := []*http.Server{
		{Addr: providerAddr, Handler: providerHandler, ReadHeaderTimeout: 10 * time.Second},
		{Addr: issuerAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second},
	}
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errCh <- s.ListenAndServe() }()
	}

	fmt.Printf(`dns-gate quickstart sandbox
  EuroDNS API (in memory, zone example.com)  http://%s
  OpenID issuer                              http://%s
  token for a subject                        curl -s 'http://%s/mint?sub=alice'

Start the gate in another terminal, from the repository root:

%s  go run ./cmd/dns-gate -config examples/quickstart/config.yaml

Ctrl-C stops the sandbox; the zone is lost.
`, providerAddr, issuerAddr, issuerAddr, env)

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return nil
}

// writeKeys writes the UI session key and the gate token signing key, and
// returns the environment the gate needs.
func writeKeys(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	sessionFile := filepath.Join(dir, "session-key")
	signingFile := filepath.Join(dir, "token-signing-key.pem")
	if err := os.WriteFile(sessionFile, []byte(hex.EncodeToString(session)), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(signingFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return "", err
	}
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return fmt.Sprintf("  export EURODNS_API_KEY=quickstart\n  export DNS_GATE_SESSION_KEY_FILE=%s\n  export DNS_GATE_TOKEN_SIGNING_KEY_FILE=%s\n",
		q(sessionFile), q(signingFile)), nil
}
