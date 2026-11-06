//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

// scenarioAuditChain checks the stdout audit stream of every previous
// scenario: one intact hash chain for the gate, every line valid against the
// published JSON Schema.
func (e *env) scenarioAuditChain(t *testing.T) {
	f, err := os.Open(e.auditBuf.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := audit.Verify(f)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	rep.WriteText(&b)
	if !rep.OK() || rep.Events < 50 {
		t.Fatalf("audit chain:\n%s", b.String())
	}
	var main *audit.ChainReport
	for _, c := range rep.Chains {
		if strings.HasPrefix(c.InstanceID, "e2e/") {
			main = c
		}
	}
	if main == nil || main.FirstSeq != 1 || main.Events < 50 {
		t.Fatalf("gate chain missing:\n%s", b.String())
	}
	t.Logf("%s", b.String())

	raw, err := os.ReadFile("../api/audit-event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var sch jsonschema.Schema
	if err := json.Unmarshal(raw, &sch); err != nil {
		t.Fatal(err)
	}
	rs, err := sch.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	actions := map[string]bool{}
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v", sc.Bytes(), err)
		}
		if err := rs.Validate(m); err != nil {
			t.Errorf("schema: %v\n%s", err, sc.Bytes())
		}
		actions[m["action"].(string)] = true
		if m["request_id"] != "" && m["subject"] != "gate:reconciler" && m["source_ip"] == nil && !strings.HasPrefix(m["action"].(string), "gate.") {
			t.Errorf("request event without source_ip: %s", sc.Bytes())
		}
	}
	t.Logf("actions: %v", actions)
}
