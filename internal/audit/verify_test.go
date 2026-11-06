package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
)

func chainLines(t *testing.T, format, inst string, n int) []string {
	t.Helper()
	var buf bytes.Buffer
	l, err := NewJSONWith(&buf, Options{Format: format, HashChain: true, InstanceID: inst})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		l.Log(context.Background(), Event{RequestID: fmt.Sprintf("r%d", i), Subject: "idp:a", Action: "applyRRsets", Zone: "example.com", Decision: "allow",
			Extra: map[string]any{"n": i, "ratio": 0.5, "html": "<b>&</b>"}})
	}
	return strings.Split(strings.TrimSpace(buf.String()), "\n")
}

func verify(t *testing.T, lines []string) *VerifyReport {
	t.Helper()
	rep, err := Verify(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestChainIntact(t *testing.T) {
	for _, f := range []string{FormatNative, FormatECS, FormatOCSF} {
		lines := chainLines(t, f, "i-1", 5)
		var first map[string]any
		_ = json.Unmarshal([]byte(lines[0]), &first)
		if first["seq"] != float64(1) || first["prev_hash"] != GenesisHash || first["instance_id"] != "i-1" || len(first["hash"].(string)) != 64 {
			t.Fatalf("%s: first line %v", f, first)
		}
		rep := verify(t, append([]string{`{"level":"INFO","msg":"app log"}`, "not json"}, lines...))
		if !rep.OK() || rep.Events != 5 || rep.Skipped != 2 || len(rep.Chains) != 1 || rep.Chains[0].LastSeq != 5 {
			var b bytes.Buffer
			rep.WriteText(&b)
			t.Fatalf("%s: %s", f, b.String())
		}
	}
}

func TestChainSurvivesReserialization(t *testing.T) {
	lines := chainLines(t, FormatNative, "i-1", 3)
	var m map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &m)
	pretty, _ := json.MarshalIndent(m, "", " ")
	lines[1] = strings.ReplaceAll(string(pretty), "\n", "")
	if rep := verify(t, lines); !rep.OK() {
		t.Fatalf("reformatted line rejected: %+v", rep.Chains[0])
	}
}

func TestChainTampering(t *testing.T) {
	lines := chainLines(t, FormatNative, "i-1", 6)

	altered := append([]string(nil), lines...)
	altered[2] = strings.Replace(altered[2], `"decision":"allow"`, `"decision":"deny"`, 1)
	rep := verify(t, altered)
	if rep.OK() || rep.Chains[0].Problems[0].Kind != ProblemAltered || rep.Chains[0].Problems[0].Seq != 3 {
		t.Fatalf("altered: %+v", rep.Chains[0])
	}

	deleted := append(append([]string(nil), lines[:2]...), lines[4:]...)
	rep = verify(t, deleted)
	if rep.OK() || len(rep.Chains[0].Gaps) != 1 || rep.Chains[0].Gaps[0] != (Gap{From: 3, To: 4}) || len(rep.Chains[0].Problems) != 0 {
		t.Fatalf("gap: %+v", rep.Chains[0])
	}

	// A forged event re-hashed with a valid hash still breaks the link of
	// the next event.
	var m map[string]any
	_ = json.Unmarshal([]byte(lines[2]), &m)
	m["decision"] = "deny"
	delete(m, "hash")
	b, _ := json.Marshal(m)
	sum, _ := hashObject(b, nil)
	m["hash"] = sum
	b, _ = json.Marshal(m)
	forged := append([]string(nil), lines...)
	forged[2] = string(b)
	rep = verify(t, forged)
	if rep.OK() || len(rep.Chains[0].Problems) != 1 || rep.Chains[0].Problems[0].Kind != ProblemLink || rep.Chains[0].Problems[0].Seq != 4 {
		t.Fatalf("forged: %+v", rep.Chains[0])
	}

	conflict := append(append([]string(nil), lines...), string(b))
	rep = verify(t, conflict)
	if rep.OK() || rep.Chains[0].Problems[0].Kind != ProblemConflict {
		t.Fatalf("conflict: %+v", rep.Chains[0])
	}

	dup := append(append([]string(nil), lines...), lines[1], lines[3])
	rep = verify(t, dup)
	if !rep.OK() || rep.Chains[0].Duplicates != 2 {
		t.Fatalf("duplicates: %+v", rep.Chains[0])
	}

	var g map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &g)
	g["prev_hash"] = strings.Repeat("a", 64)
	delete(g, "hash")
	b, _ = json.Marshal(g)
	sum, _ = hashObject(b, nil)
	g["hash"] = sum
	b, _ = json.Marshal(g)
	rep = verify(t, []string{string(b)})
	if rep.OK() || rep.Chains[0].Problems[0].Kind != ProblemGenesis {
		t.Fatalf("genesis: %+v", rep.Chains[0])
	}
}

func TestChainPartialAndWrapped(t *testing.T) {
	a := chainLines(t, FormatNative, "i-a", 4)
	b := chainLines(t, FormatECS, "i-b", 3)
	var in []string
	for _, l := range a[1:] {
		w, _ := json.Marshal(map[string]any{"log": l, "stream": "stdout"})
		in = append(in, string(w))
	}
	var evs []map[string]any
	for i, l := range b {
		evs = append(evs, map[string]any{"id": fmt.Sprint(i), "timestamp": 1, "message": l})
	}
	cw, _ := json.Marshal(map[string]any{"messageType": "DATA_MESSAGE", "logGroup": "/aws/lambda/dns-gate", "logEvents": evs})
	in = append(in, string(cw))
	rep := verify(t, in)
	if !rep.OK() || len(rep.Chains) != 2 || rep.Events != 6 {
		t.Fatalf("partial: %+v", rep)
	}
	for _, c := range rep.Chains {
		if c.InstanceID == "i-a" && c.FirstSeq != 2 {
			t.Fatalf("partial chain %+v", c)
		}
	}
	var out bytes.Buffer
	rep.WriteText(&out)
	if !strings.Contains(out.String(), "starts after seq 1") {
		t.Fatal(out.String())
	}
}

func TestVerifyWithoutChain(t *testing.T) {
	var buf bytes.Buffer
	NewJSON(&buf).Log(context.Background(), Event{Action: "x", Decision: "allow"})
	rep, err := Verify(&buf)
	if err != nil || rep.OK() || rep.Unchained != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestChainConcurrent(t *testing.T) {
	var buf bytes.Buffer
	l, _ := NewJSONWith(&buf, Options{HashChain: true})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Log(context.Background(), Event{RequestID: fmt.Sprint(i), Action: "a", Decision: "allow"})
		}(i)
	}
	wg.Wait()
	rep, err := Verify(&buf)
	if err != nil || !rep.OK() || rep.Chains[0].Events != 50 || rep.Chains[0].InstanceID != l.InstanceID() {
		t.Fatalf("%+v %v", rep, err)
	}
}

// A duplicated member is ambiguous (decoders keep the first or the last):
// verify marks the line altered, whichever value the hash covered.
func TestVerifyRejectsDuplicateKeys(t *testing.T) {
	lines := chainLines(t, FormatNative, "i-1", 3)
	for _, forged := range []string{
		strings.Replace(lines[1], `{`, `{"decision":"deny",`, 1),
		strings.Replace(lines[1], `"extra":{`, `"extra":{"n":7,`, 1),
	} {
		in := append([]string(nil), lines...)
		in[1] = forged
		rep := verify(t, in)
		if rep.OK() || len(rep.Chains[0].Problems) == 0 || rep.Chains[0].Problems[0].Kind != ProblemAltered || rep.Chains[0].Problems[0].Seq != 2 {
			t.Fatalf("duplicate keys accepted: %+v", rep.Chains[0])
		}
	}
	if _, err := hashObject([]byte(`{"a":1,"a":2}`), nil); err == nil {
		t.Fatal("hashObject accepts duplicate keys")
	}
}

// Audit lines without a chain among chained ones are injected lines.
func TestVerifyUnchainedAmongChains(t *testing.T) {
	lines := chainLines(t, FormatNative, "i-1", 2)
	var buf bytes.Buffer
	NewJSON(&buf).Log(context.Background(), Event{Action: "applyRRsets", Decision: "allow"})
	in := append(lines, strings.TrimSpace(buf.String()))
	if rep := verify(t, in); rep.OK() {
		t.Fatal("unchained line accepted among chains")
	}
	rep, err := VerifyWith(strings.NewReader(strings.Join(in, "\n")), VerifyOptions{AllowUnchained: true})
	if err != nil || !rep.OK() {
		t.Fatalf("allow unchained: %+v %v", rep, err)
	}
	rep, err = VerifyWith(strings.NewReader(strings.Join(lines[1:], "\n")), VerifyOptions{RequireGenesis: true})
	if err != nil || rep.OK() {
		t.Fatalf("require genesis: %+v %v", rep, err)
	}
}

// With a key, the chain is an HMAC: recomputing it without the key fails.
func TestKeyedChain(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var buf bytes.Buffer
	l, err := NewJSONWith(&buf, Options{HashChain: true, InstanceID: "i-k", ChainKey: key})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		l.Log(context.Background(), Event{Action: "applyRRsets", Decision: "allow"})
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var m map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &m)
	if m["hash_alg"] != HashHMACSHA256 {
		t.Fatalf("hash_alg %v", m["hash_alg"])
	}
	if rep, _ := VerifyWith(strings.NewReader(buf.String()), VerifyOptions{Key: key}); !rep.OK() {
		t.Fatalf("keyed chain rejected: %+v", rep.Chains[0])
	}
	if rep, _ := VerifyWith(strings.NewReader(buf.String()), VerifyOptions{}); rep.OK() {
		t.Fatal("keyed chain verified without the key")
	}
	if rep, _ := VerifyWith(strings.NewReader(buf.String()), VerifyOptions{Key: bytes.Repeat([]byte{8}, 32)}); rep.OK() {
		t.Fatal("keyed chain verified with another key")
	}
	// A forger without the key recomputes plain SHA-256 hashes.
	m["decision"] = "deny"
	delete(m, "hash")
	b, _ := json.Marshal(m)
	sum, _ := hashObject(b, nil)
	m["hash"] = sum
	b, _ = json.Marshal(m)
	lines[0] = string(b)
	if rep, _ := VerifyWith(strings.NewReader(strings.Join(lines, "\n")), VerifyOptions{Key: key}); rep.OK() {
		t.Fatal("forged line accepted")
	}
}

type errLog struct{ msgs []string }

func (e *errLog) Write(p []byte) (int, error) { e.msgs = append(e.msgs, string(p)); return len(p), nil }

// A line that cannot be rendered is still written, chained, with
// render_error, and reported on the error log.
func TestRenderFailureFallback(t *testing.T) {
	var buf bytes.Buffer
	el := &errLog{}
	l, _ := NewJSONWith(&buf, Options{HashChain: true, InstanceID: `i-"q"`, ErrorLog: slog.New(slog.NewJSONHandler(el, nil))})
	l.Log(context.Background(), Event{RequestID: "r1", Action: "applyRRsets", Decision: "allow", Extra: map[string]any{"bad": math.NaN()}})
	l.Log(context.Background(), Event{RequestID: "r2", Action: "applyRRsets", Decision: "allow"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"render_error"`) || !strings.Contains(lines[0], `"request_id":"r1"`) || len(el.msgs) != 1 {
		t.Fatalf("fallback: %q, errors %q", lines, el.msgs)
	}
	var fb map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &fb)
	if err := schema(t).Validate(fb); err != nil {
		t.Fatalf("fallback line: %v", err)
	}
	rep := verify(t, lines)
	if !rep.OK() || rep.Chains[0].InstanceID != `i-"q"` {
		t.Fatalf("chain: %+v", rep.Chains)
	}
}

// The chained example of docs/AUDIT.md verifies and matches the schema.
func TestDocumentedExample(t *testing.T) {
	doc, err := os.ReadFile("../../docs/AUDIT.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i := strings.Index(s, `{"type":"audit","schema_version":"1","event_id":"01a1b0d2-9a40`)
	j := strings.Index(s[i:], "\n```")
	if i < 0 || j < 0 {
		t.Fatal("example not found")
	}
	line := strings.ReplaceAll(s[i:i+j], "\n", "")
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	if err := schema(t).Validate(m); err != nil {
		t.Fatal(err)
	}
	if rep := verify(t, []string{line}); !rep.OK() {
		t.Fatalf("%+v", rep.Chains)
	}
}
