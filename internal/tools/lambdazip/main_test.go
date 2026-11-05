package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootstrapModeIgnoresDiskMode(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bootstrap-0700")
	if err := os.WriteFile(bin, []byte("\x7fELF binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	out := filepath.Join(dir, "dns-gate_1.2.3_lambda_arm64.zip")
	if err := run(out, bin); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "bootstrap" {
		t.Fatalf("entries %v", zr.File)
	}
	f := zr.File[0]
	if f.Mode().Perm() != 0o755 || !f.Mode().IsRegular() {
		t.Fatalf("mode %v", f.Mode())
	}
	if f.Modified.Unix() != 1700000000 {
		t.Errorf("modified %v", f.Modified)
	}
	rc, _ := f.Open()
	body, _ := io.ReadAll(rc)
	if string(body) != "\x7fELF binary" {
		t.Fatalf("body %q", body)
	}
	sum := sha256.Sum256(raw)
	line, err := os.ReadFile(out + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(sum[:]) + "  dns-gate_1.2.3_lambda_arm64.zip\n"; string(line) != want {
		t.Fatalf("sha256 file %q, want %q", line, want)
	}
	var again bytes.Buffer
	if err := Write(&again, []byte("\x7fELF binary"), f.Modified); err != nil || !bytes.Equal(again.Bytes(), raw) {
		t.Fatal("same input and time must give the same zip")
	}
}

func TestEmptyBinaryRefused(t *testing.T) {
	if err := Write(io.Discard, nil, time.Time{}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatal(err)
	}
}
