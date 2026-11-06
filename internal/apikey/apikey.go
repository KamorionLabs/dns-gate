// Package apikey formats and checks gate-issued API keys.
//
// A key reads dgk_<id>_<secret>: id is 16 lowercase hex characters, the
// public key id (acme-dns user name, basic auth user name, X-App-Id), and
// secret 43 base64url characters (32 random bytes). Only the hex SHA-256 of
// the whole key is stored; the key itself is shown once, at creation and at
// each rotation.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Prefix starts every gate-issued API key.
const Prefix = "dgk_"

const (
	idLen     = 16
	secretLen = 43
)

// NewID returns a random key id.
func NewID() string {
	var b [idLen / 2]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NewSecret returns a new key for id.
func NewSecret(id string) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return Prefix + id + "_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// ValidID reports whether id has the format of a key id.
func ValidID(id string) bool {
	if len(id) != idLen {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Looks reports whether token has the gate API key prefix.
func Looks(token string) bool { return strings.HasPrefix(token, Prefix) }

// Parse returns the key id of a well-formed key.
func Parse(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, Prefix)
	if !ok || len(rest) != idLen+1+secretLen || rest[idLen] != '_' {
		return "", false
	}
	id := rest[:idLen]
	if !ValidID(id) {
		return "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(rest[idLen+1:]); err != nil {
		return "", false
	}
	return id, true
}

// Hash returns the lowercase hex SHA-256 of a key, the stored form.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Match compares a key with a stored hash in constant time.
func Match(token, hash string) bool {
	want, err := hex.DecodeString(hash)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(want, sum[:]) == 1
}
