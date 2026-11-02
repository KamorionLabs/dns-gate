package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// sealer encrypts and authenticates cookie payloads with AES-256-GCM. The
// cookie name is bound as additional data so a value cannot be replayed
// under another cookie.
type sealer struct {
	aead cipher.AEAD
}

func newSealer(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(name string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, []byte(name))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (s *sealer) open(name, value string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return errors.New("invalid cookie")
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if err != nil {
		return errors.New("invalid cookie")
	}
	return json.Unmarshal(plain, v)
}

// session is the content of the session cookie. Only the claims used for
// binding are kept; roles and teams are recomputed on every request so
// configuration changes apply immediately.
type session struct {
	Issuer  string         `json:"iss"`
	Claims  map[string]any `json:"c"`
	Expires int64          `json:"exp"`
	// AuthTime is when the user last authenticated at the IdP: the ID token
	// auth_time, or the login time of a forced re-authentication. 0 when
	// unknown (a silent SSO login): edits then require a re-authentication.
	AuthTime int64    `json:"at,omitempty"`
	AMR      []string `json:"amr,omitempty"`
}

// loginState is the short-lived cookie of an ongoing login.
type loginState struct {
	Reauth   bool   `json:"r,omitempty"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Expires  int64  `json:"exp"`
}

type cookieNames struct {
	session, login string
	secure         bool
}

// csrfCookie is readable by the UI script, which echoes it in X-Gate-CSRF.
const (
	csrfCookie = "gate_csrf"
	csrfHeader = "X-Gate-CSRF"
)

func newCookieNames(secure bool) cookieNames {
	if secure {
		return cookieNames{session: "__Host-eurodns-gate-session", login: "__Host-eurodns-gate-login", secure: true}
	}
	return cookieNames{session: "eurodns-gate-session", login: "eurodns-gate-login"}
}

func (c cookieNames) cookie(name, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (c cookieNames) clear(name string) *http.Cookie {
	return &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteLaxMode}
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
