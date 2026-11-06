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
)

const auditUsage = `usage: dns-gate audit verify [-json] [file ...]

Checks the hash chains of an export of audit lines (audit.hash_chain: true):
JSON lines as written on stdout, container log lines wrapping them, or
CloudWatch Logs documents (subscription payloads, filter-log-events output).
Reads the standard input without file. Exits 1 when a chain has a gap or an
altered, reordered or conflicting event, or when no chained event is found.
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
	if err := fs.Parse(args[1:]); err != nil {
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
	rep, err := audit.Verify(in)
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
