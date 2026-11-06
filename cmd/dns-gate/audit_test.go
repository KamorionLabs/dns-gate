package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

func TestAuditVerifyCommand(t *testing.T) {
	var buf bytes.Buffer
	l, err := audit.NewJSONWith(&buf, audit.Options{HashChain: true, InstanceID: "pod-1/x"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		l.Log(context.Background(), audit.Event{Action: "applyRRsets", Decision: "allow"})
	}
	lines := strings.SplitAfter(buf.String(), "\n")
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "b.jsonl")
	_ = os.WriteFile(a, []byte(lines[0]+lines[1]), 0o600)
	_ = os.WriteFile(b, []byte(strings.TrimSuffix(lines[2], "\n")), 0o600)

	var out, errOut bytes.Buffer
	if err := runAudit([]string{"verify", a, b}, nil, &out, &errOut); err != nil || !strings.Contains(out.String(), "chain pod-1/x: OK, 3 events") {
		t.Fatalf("files: %v\n%s%s", err, out.String(), errOut.String())
	}

	out.Reset()
	in := strings.NewReader(lines[0] + lines[2])
	if err := runAudit([]string{"verify", "-json"}, in, &out, &errOut); err == nil {
		t.Fatal("gap not reported")
	}
	var rep audit.VerifyReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || len(rep.Chains) != 1 || len(rep.Chains[0].Gaps) != 1 {
		t.Fatalf("json report %s: %v", out.String(), err)
	}

	if err := runAudit([]string{"check"}, nil, &out, &errOut); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}
