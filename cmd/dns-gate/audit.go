package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
)

const auditUsage = `usage: dns-gate audit verify [-json] [-allow-unchained] [-require-genesis] [-key-file file] [file ...]

Checks the hash chains of an export of audit lines (audit.hash_chain: true):
JSON lines as written on stdout, container log lines wrapping them, or
CloudWatch Logs documents (subscription payloads, filter-log-events output).
Reads the standard input without file. Exits 1 when a chain has a gap or an
altered, reordered or conflicting event, when audit lines without chain
members are mixed with chained ones, or when no chained event is found.

Keyed chains (audit.hash_chain_key) need the key: -key-file, or the
DNS_GATE_AUDIT_CHAIN_KEY or DNS_GATE_AUDIT_CHAIN_KEY_FILE variable (32 bytes,
hex or base64).
`

// runAudit serves "dns-gate audit ...".
func runAudit(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprint(stderr, auditUsage)
		return errors.New("audit: unknown or missing subcommand")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, auditUsage) }
	asJSON := fs.Bool("json", false, "print the report as JSON")
	allowUnchained := fs.Bool("allow-unchained", false, "accept audit lines without chain members next to chained ones")
	requireGenesis := fs.Bool("require-genesis", false, "fail a chain that does not start at seq 1 in the input")
	keyFile := fs.String("key-file", "", "file holding the chain key of keyed chains")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	key, err := chainKey(*keyFile)
	if err != nil {
		return err
	}
	var readers []io.Reader
	for _, name := range fs.Args() {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		readers = append(readers, f)
	}
	in := stdin
	if len(readers) > 0 {
		in = io.MultiReader(withNewlines(readers)...)
	}
	rep, err := audit.VerifyWith(in, audit.VerifyOptions{AllowUnchained: *allowUnchained, RequireGenesis: *requireGenesis, Key: key})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		rep.WriteText(stdout)
	}
	if !rep.OK() {
		return errors.New("audit verification failed")
	}
	return nil
}

// withNewlines separates the files so that a file without a final newline
// does not merge its last line with the first line of the next one.
func withNewlines(rs []io.Reader) []io.Reader {
	out := make([]io.Reader, 0, 2*len(rs))
	for _, r := range rs {
		out = append(out, r, strings.NewReader("\n"))
	}
	return out
}

// chainKey reads the chain key from a file or the environment.
func chainKey(file string) ([]byte, error) {
	v := ""
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		v = string(b)
	case os.Getenv(config.EnvAuditChainKey) != "":
		v = os.Getenv(config.EnvAuditChainKey)
	case os.Getenv(config.EnvAuditChainKey+"_FILE") != "":
		b, err := os.ReadFile(os.Getenv(config.EnvAuditChainKey + "_FILE"))
		if err != nil {
			return nil, err
		}
		v = string(b)
	default:
		return nil, nil
	}
	k, err := config.DecodeKey(strings.TrimSpace(v))
	if err != nil {
		return nil, fmt.Errorf("audit chain key: %w", err)
	}
	return k, nil
}
