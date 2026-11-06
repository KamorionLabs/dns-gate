package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// Problems found by Verify.
const (
	ProblemAltered  = "altered"      // the hash does not match the content of the event
	ProblemLink     = "broken_link"  // prev_hash is not the hash of the previous event
	ProblemConflict = "seq_conflict" // two different events with the same seq
	ProblemGenesis  = "bad_genesis"  // the first event of a chain does not start from GenesisHash
	ProblemKey      = "key_required" // keyed chain (hmac-sha256) checked without the key
	ProblemUnkeyed  = "unkeyed"      // plain sha256 event while the chain key was given
	ProblemStart    = "no_genesis"   // RequireGenesis: the chain does not start at seq 1
)

// VerifyOptions tune Verify.
type VerifyOptions struct {
	// AllowUnchained accepts audit lines without chain members next to
	// chained ones (otherwise they are injected lines and fail).
	AllowUnchained bool
	// RequireGenesis fails a chain whose first event in the input is not
	// seq 1 (an export expected to hold whole chains).
	RequireGenesis bool
	// Key is the chain key (audit.hash_chain_key) of keyed chains.
	Key []byte
}

// Problem is a tamper finding on one event.
type Problem struct {
	Kind    string `json:"kind"`
	Seq     int64  `json:"seq"`
	EventID string `json:"event_id,omitempty"`
	Line    int    `json:"line"`
}

// Gap is a range of missing events (inclusive).
type Gap struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// ChainReport is the result for one instance.
type ChainReport struct {
	InstanceID string    `json:"instance_id"`
	Events     int       `json:"events"`
	FirstSeq   int64     `json:"first_seq"`
	LastSeq    int64     `json:"last_seq"`
	FirstTime  string    `json:"first_time,omitempty"`
	LastTime   string    `json:"last_time,omitempty"`
	Duplicates int       `json:"duplicates,omitempty"`
	Gaps       []Gap     `json:"gaps,omitempty"`
	Problems   []Problem `json:"problems,omitempty"`
}

// OK reports a chain without gap nor problem.
func (c *ChainReport) OK() bool { return len(c.Gaps) == 0 && len(c.Problems) == 0 }

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Lines     int            `json:"lines"`
	Events    int            `json:"events"`    // audit events read
	Unchained int            `json:"unchained"` // audit events without chain fields
	Skipped   int            `json:"skipped"`   // lines that are not audit events
	Chains    []*ChainReport `json:"chains"`
	OKResult  bool           `json:"ok"`

	opts VerifyOptions
}

// OK reports whether at least one chained event was read, every chain is
// complete and intact, and no unchained audit line was mixed in (unless
// allowed).
func (r *VerifyReport) OK() bool {
	if len(r.Chains) == 0 || (r.Unchained > 0 && !r.opts.AllowUnchained) {
		return false
	}
	for _, c := range r.Chains {
		if !c.OK() {
			return false
		}
	}
	return true
}

type chained struct {
	seq            int64
	hash, prev, id string
	alg            string
	line           int
	altered        bool
	time           string
	instance       string
}

// Verify reads an export of audit lines and checks their hash chains. It
// accepts JSON lines as written by the gate, lines wrapping them in a "log"
// or "message" string (container log collectors), and CloudWatch Logs
// documents with a "logEvents" or "events" array (subscription payloads,
// filter-log-events output). Other lines are skipped. Events may come in any
// order and from several instances.
func Verify(r io.Reader) (*VerifyReport, error) { return VerifyWith(r, VerifyOptions{}) }

// VerifyWith is Verify with options.
func VerifyWith(r io.Reader, opts VerifyOptions) (*VerifyReport, error) {
	rep := &VerifyReport{opts: opts}
	byInst := map[string][]chained{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		rep.Lines++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		objs := extract(line, 0)
		if len(objs) == 0 {
			rep.Skipped++
			continue
		}
		for _, raw := range objs {
			rep.Events++
			c, ok := readChained(raw, opts.Key)
			if !ok {
				rep.Unchained++
				continue
			}
			c.line = rep.Lines
			byInst[c.instance] = append(byInst[c.instance], c)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	insts := make([]string, 0, len(byInst))
	for k := range byInst {
		insts = append(insts, k)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		rep.Chains = append(rep.Chains, checkChain(inst, byInst[inst], opts))
	}
	sort.SliceStable(rep.Chains, func(i, j int) bool { return rep.Chains[i].FirstTime < rep.Chains[j].FirstTime })
	rep.OKResult = rep.OK()
	return rep, nil
}

// extract returns the audit objects of a line.
func extract(line []byte, depth int) [][]byte {
	if depth > 2 || len(line) == 0 || line[0] != '{' {
		return nil
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(line, &probe) != nil {
		return nil
	}
	if t, ok := probe["type"]; ok && string(t) == `"audit"` {
		return [][]byte{line}
	}
	for _, k := range []string{"logEvents", "events"} {
		if raw, ok := probe[k]; ok {
			var evs []struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(raw, &evs) != nil {
				continue
			}
			var out [][]byte
			for _, ev := range evs {
				out = append(out, extract(bytes.TrimSpace([]byte(ev.Message)), depth+1)...)
			}
			return out
		}
	}
	for _, k := range []string{"log", "message"} {
		if raw, ok := probe[k]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				return extract(bytes.TrimSpace([]byte(s)), depth+1)
			}
		}
	}
	return nil
}

func readChained(raw []byte, key []byte) (chained, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return chained{}, false
	}
	var c chained
	if json.Unmarshal(m["instance_id"], &c.instance) != nil || c.instance == "" ||
		json.Unmarshal(m["hash"], &c.hash) != nil || json.Unmarshal(m["prev_hash"], &c.prev) != nil {
		return chained{}, false
	}
	var n json.Number
	if json.Unmarshal(m["seq"], &n) != nil {
		return chained{}, false
	}
	seq, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return chained{}, false
	}
	c.seq = seq
	c.id = firstString(m, "event_id")
	if c.id == "" {
		if meta, ok := m["metadata"]; ok {
			var md struct {
				UID string `json:"uid"`
			}
			_ = json.Unmarshal(meta, &md)
			c.id = md.UID
		}
	}
	if c.id == "" {
		if ev, ok := m["event"]; ok {
			var e struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(ev, &e)
			c.id = e.ID
		}
	}
	c.time = firstString(m, "time", "@timestamp")
	if c.time == "" {
		var ms int64
		if json.Unmarshal(m["time"], &ms) == nil && ms > 0 {
			c.time = fmt.Sprint(ms)
		}
	}
	c.alg = firstString(m, "hash_alg")
	if c.alg == "" {
		c.alg = HashSHA256
	}
	var k []byte
	if c.alg == HashHMACSHA256 {
		if len(key) == 0 {
			return c, true
		}
		k = key
	}
	sum, err := hashObject(raw, k)
	c.altered = err != nil || sum != c.hash || (c.alg != HashSHA256 && c.alg != HashHMACSHA256)
	return c, true
}

func firstString(m map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		var s string
		if raw, ok := m[k]; ok && json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}

func checkChain(inst string, evs []chained, opts VerifyOptions) *ChainReport {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].seq < evs[j].seq })
	rep := &ChainReport{InstanceID: inst}
	var uniq []chained
	for _, e := range evs {
		if n := len(uniq); n > 0 && uniq[n-1].seq == e.seq {
			if uniq[n-1].hash == e.hash && !e.altered {
				rep.Duplicates++
				continue
			}
			rep.Problems = append(rep.Problems, Problem{Kind: ProblemConflict, Seq: e.seq, EventID: e.id, Line: e.line})
			continue
		}
		uniq = append(uniq, e)
	}
	rep.Events = len(uniq)
	if len(uniq) == 0 {
		return rep
	}
	rep.FirstSeq, rep.LastSeq = uniq[0].seq, uniq[len(uniq)-1].seq
	rep.FirstTime, rep.LastTime = uniq[0].time, uniq[len(uniq)-1].time
	if opts.RequireGenesis && rep.FirstSeq != 1 {
		rep.Problems = append(rep.Problems, Problem{Kind: ProblemStart, Seq: rep.FirstSeq, EventID: uniq[0].id, Line: uniq[0].line})
	}
	for i, e := range uniq {
		switch {
		case e.alg == HashHMACSHA256 && len(opts.Key) == 0:
			rep.Problems = append(rep.Problems, Problem{Kind: ProblemKey, Seq: e.seq, EventID: e.id, Line: e.line})
		case e.alg == HashSHA256 && len(opts.Key) > 0:
			rep.Problems = append(rep.Problems, Problem{Kind: ProblemUnkeyed, Seq: e.seq, EventID: e.id, Line: e.line})
		case e.altered:
			rep.Problems = append(rep.Problems, Problem{Kind: ProblemAltered, Seq: e.seq, EventID: e.id, Line: e.line})
		}
		if i == 0 {
			if e.seq == 1 && e.prev != GenesisHash {
				rep.Problems = append(rep.Problems, Problem{Kind: ProblemGenesis, Seq: e.seq, EventID: e.id, Line: e.line})
			}
			continue
		}
		prev := uniq[i-1]
		if e.seq != prev.seq+1 {
			rep.Gaps = append(rep.Gaps, Gap{From: prev.seq + 1, To: e.seq - 1})
			continue
		}
		if e.prev != prev.hash {
			rep.Problems = append(rep.Problems, Problem{Kind: ProblemLink, Seq: e.seq, EventID: e.id, Line: e.line})
		}
	}
	sort.SliceStable(rep.Problems, func(i, j int) bool { return rep.Problems[i].Seq < rep.Problems[j].Seq })
	return rep
}

// WriteText prints a human-readable report.
func (r *VerifyReport) WriteText(w io.Writer) {
	fmt.Fprintf(w, "lines: %d, audit events: %d, unchained: %d, skipped lines: %d, chains: %d\n",
		r.Lines, r.Events, r.Unchained, r.Skipped, len(r.Chains))
	for _, c := range r.Chains {
		state := "OK"
		if !c.OK() {
			state = "FAILED"
		}
		fmt.Fprintf(w, "chain %s: %s, %d events, seq %d..%d", c.InstanceID, state, c.Events, c.FirstSeq, c.LastSeq)
		if c.FirstTime != "" {
			fmt.Fprintf(w, ", %s .. %s", c.FirstTime, c.LastTime)
		}
		if c.FirstSeq > 1 {
			fmt.Fprintf(w, " (starts after seq 1: earlier events not in the export)")
		}
		if c.Duplicates > 0 {
			fmt.Fprintf(w, ", %d duplicate(s) ignored", c.Duplicates)
		}
		fmt.Fprintln(w)
		for _, g := range c.Gaps {
			if g.From == g.To {
				fmt.Fprintf(w, "  gap: event %d missing\n", g.From)
			} else {
				fmt.Fprintf(w, "  gap: events %d..%d missing (%d)\n", g.From, g.To, g.To-g.From+1)
			}
		}
		for _, p := range c.Problems {
			fmt.Fprintf(w, "  %s: seq %d, event %s, line %d\n", p.Kind, p.Seq, p.EventID, p.Line)
		}
	}
	if r.Unchained > 0 && len(r.Chains) > 0 && !r.opts.AllowUnchained {
		fmt.Fprintf(w, "FAILED: %d audit line(s) without chain members among chained ones (injected lines? -allow-unchained to accept)\n", r.Unchained)
	}
	if len(r.Chains) == 0 {
		fmt.Fprintln(w, "no hash-chained audit event found (audit.hash_chain: true?)")
	}
}
