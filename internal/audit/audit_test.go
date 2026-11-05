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

// Events stored before the provider-neutral model carry a numeric EuroDNS
// snapshot id; they must still decode.
func TestSnapshotIDCompat(t *testing.T) {
	var old Event
	if err := json.Unmarshal([]byte(`{"request_id":"r","decision":"allow","snapshot_id":884301}`), &old); err != nil || old.SnapshotID != "884301" {
		t.Fatalf("numeric id: %q %v", old.SnapshotID, err)
	}
	b, _ := json.Marshal(Event{SnapshotID: "42", Provider: "eurodns"})
	var back Event
	if err := json.Unmarshal(b, &back); err != nil || back.SnapshotID != "42" || back.Provider != "eurodns" || !bytes.Contains(b, []byte(`"snapshot_id":"42"`)) {
		t.Fatalf("round trip %s: %v", b, err)
	}
	if b, _ := json.Marshal(Event{}); bytes.Contains(b, []byte("snapshot_id")) || bytes.Contains(b, []byte("provider")) {
		t.Fatalf("empty fields must be omitted: %s", b)
	}
}
