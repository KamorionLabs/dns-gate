package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
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

func TestAuditVerifyKeyAndUnchained(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	var buf bytes.Buffer
	l, _ := audit.NewJSONWith(&buf, audit.Options{HashChain: true, InstanceID: "i", ChainKey: key})
	l.Log(context.Background(), audit.Event{Action: "a", Decision: "allow"})
	audit.NewJSON(&buf).Log(context.Background(), audit.Event{Action: "injected", Decision: "allow"})
	dir := t.TempDir()
	kf := filepath.Join(dir, "key")
	_ = os.WriteFile(kf, []byte(hex.EncodeToString(key)+"\n"), 0o600)
	var out bytes.Buffer
	run := func(args ...string) error {
		out.Reset()
		return runAudit(append([]string{"verify"}, args...), strings.NewReader(buf.String()), &out, &out)
	}
	if err := run("-key-file", kf); err == nil || !strings.Contains(out.String(), "without chain members") {
		t.Fatalf("injected line: %v %s", err, out.String())
	}
	if err := run("-key-file", kf, "-allow-unchained"); err != nil {
		t.Fatalf("allowed: %v %s", err, out.String())
	}
	if err := run("-allow-unchained"); err == nil || !strings.Contains(out.String(), "key_required") {
		t.Fatalf("no key: %v %s", err, out.String())
	}
	t.Setenv(config.EnvAuditChainKey, hex.EncodeToString(key))
	if err := run("-allow-unchained", "-require-genesis"); err != nil {
		t.Fatalf("key from the environment: %v %s", err, out.String())
	}
}
