package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type failingStore struct{ n int }

func (f *failingStore) AppendAudit(context.Context, Event) error { f.n++; return errors.New("down") }

func TestTee(t *testing.T) {
	var buf bytes.Buffer
	st := &failingStore{}
	tee := &Tee{Primary: NewJSON(&buf), Store: st}
	tee.Log(context.Background(), Event{RequestID: "r1", Decision: "allow"})
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["type"] != "audit" || line["request_id"] != "r1" || line["time"] == nil {
		t.Fatalf("line %v", line)
	}
	if st.n != 1 {
		t.Fatal("store not called")
	}
}
