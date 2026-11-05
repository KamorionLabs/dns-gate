// Command lambdazip packages a Lambda bootstrap binary: a zip whose single
// entry is "bootstrap" with mode 0755 set explicitly, whatever the file mode
// on disk (exFAT volumes report 0700), plus a sha256sum file next to it.
//
//	go run ./internal/tools/lambdazip -o dist/x.zip dist/lambda/bootstrap
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// entryName is the executable name the provided.al2023 runtime starts.
const entryName = "bootstrap"

// entryMode is the mode of the bootstrap entry.
const entryMode = 0o755

func main() {
	out := flag.String("o", "", "zip file to write")
	flag.Parse()
	if *out == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: lambdazip -o <zip> <bootstrap binary>")
		os.Exit(2)
	}
	if err := run(*out, flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, "lambdazip:", err)
		os.Exit(1)
	}
}

func run(out, binary string) error {
	data, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	mod, err := modTime(binary)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := Write(&buf, data, mod); err != nil {
		return err
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(buf.Bytes())
	line := hex.EncodeToString(sum[:]) + "  " + filepath.Base(out) + "\n"
	return os.WriteFile(out+".sha256", []byte(line), 0o644)
}

// modTime is SOURCE_DATE_EPOCH when set (reproducible builds), else the
// modification time of the binary.
func modTime(path string) (time.Time, error) {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH: %w", err)
		}
		return time.Unix(sec, 0).UTC(), nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime().UTC(), nil
}

// Write writes a zip holding data as an executable "bootstrap" entry.
func Write(w io.Writer, data []byte, mod time.Time) error {
	if len(data) == 0 {
		return errors.New("empty binary")
	}
	zw := zip.NewWriter(w)
	h := &zip.FileHeader{Name: entryName, Method: zip.Deflate, Modified: mod}
	h.SetMode(entryMode)
	f, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return zw.Close()
}
