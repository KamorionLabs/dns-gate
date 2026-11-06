package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/apikey"
	"github.com/KamorionLabs/dns-gate/internal/audit"
	"github.com/KamorionLabs/dns-gate/internal/config"
	"github.com/KamorionLabs/dns-gate/internal/identity"
	"github.com/KamorionLabs/dns-gate/internal/store"
)

type auditLog struct {
	mu     sync.Mutex
	events []audit.Event
}

func (l *auditLog) Log(_ context.Context, e audit.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func TestAPIKeys(t *testing.T) {
	a, _ := setup(t)
	now := time.Now()
	a.SetClock(func() time.Time { return now })
	st := store.NewMemory().(store.APIKeyStore)
	log := &auditLog{}
	a.SetAPIKeys(st, log)
	ctx := context.Background()

	mk := func(team, role string, mod func(*store.APIKey)) (string, string) {
		id := apikey.NewID()
		key := apikey.NewSecret(id)
		k := store.APIKey{ID: id, Name: "lego", Team: team, Role: role, RoleGrant: grantOf(a, role), SecretHash: apikey.Hash(key), CreatedAt: now}
		if mod != nil {
			mod(&k)
		}
		if err := st.CreateAPIKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		return id, key
	}
	id, key := mk("edge", "acme-solver", nil)
	req := func(remote string, hdr map[string]string) error {
		r := httptest.NewRequest("POST", "/acme/httpreq/present", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		s, err := a.Authenticate(r)
		if err == nil && (s.Kind != identity.KindAPIKey || s.String() != "api-key:"+id || s.Teams[0] != "edge" || s.Roles[0] != "acme-solver" || s.Category != identity.CategoryKey) {
			t.Fatalf("subject %+v", s)
		}
		return err
	}
	basicAuth := func(u, p string) map[string]string {
		return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))}
	}
	for name, hdr := range map[string]map[string]string{
		"bearer":         {"Authorization": "Bearer " + key},
		"basic":          basicAuth(id, key),
		"basic no user":  basicAuth("", key),
		"x-api-key":      {"X-Api-Key": key},
		"x-app-id":       {"X-App-Id": id, "X-Api-Key": key},
		"acme-dns style": {"X-Api-User": id, "X-Api-Key": key},
	} {
		if err := req("192.0.2.1:1", hdr); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, _ := st.GetAPIKey(ctx, id)
	if got.LastUsedAt == nil || got.LastUsedIP != "192.0.2.1" {
		t.Fatalf("last use not recorded: %+v", got)
	}
	for name, hdr := range map[string]map[string]string{
		"wrong user":       basicAuth("0123456789abcdef", key),
		"wrong app id":     {"X-App-Id": "0123456789abcdef", "X-Api-Key": key},
		"basic not a key":  basicAuth(id, "password"),
		"tampered":         {"Authorization": "Bearer " + tampered(key)},
		"malformed":        {"Authorization": "Bearer dgk_nope"},
		"unknown":          {"Authorization": "Bearer " + apikey.NewSecret("0123456789abcdef")},
		"both credentials": {"Authorization": "Bearer " + key, "X-Api-Key": key},
	} {
		if err := req("192.0.2.1:1", hdr); status(err) != 401 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(log.events) < 2 || log.events[0].Action != "apikey.authenticate" || log.events[0].Decision != "deny" {
		t.Fatalf("failures not audited: %+v", log.events)
	}
	for _, e := range log.events {
		if e.Extra["message"] == nil || e.Subject == key {
			t.Fatalf("audit event %+v", e)
		}
	}

	past := now.Add(-time.Minute)
	later := now.Add(time.Hour)
	expID, expKey := mk("edge", "acme-solver", func(k *store.APIKey) { k.ExpiresAt = &past })
	revID, revKey := mk("edge", "acme-solver", func(k *store.APIKey) { k.RevokedAt = &past })
	_, cidrKey := mk("edge", "acme-solver", func(k *store.APIKey) { k.AllowedCIDRs = []string{"198.51.100.0/24"} })
	_, roleKey := mk("edge", "gone", nil)
	for name, tc := range map[string]struct {
		key  string
		want int
	}{
		"expired": {expKey, 401}, "revoked": {revKey, 401}, "cidr": {cidrKey, 403}, "role removed": {roleKey, 403},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.1:1"
		r.Header.Set("Authorization", "Bearer "+tc.key)
		if _, err := a.Authenticate(r); status(err) != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, _ = expID, revID

	rotID, oldKey := mk("edge", "acme-solver", nil)
	k, _ := st.GetAPIKey(ctx, rotID)
	newKey := apikey.NewSecret(rotID)
	k.PreviousHash, k.PreviousExpiresAt, k.SecretHash = k.SecretHash, &later, apikey.Hash(newKey)
	if err := st.UpdateAPIKey(ctx, *k); err != nil {
		t.Fatal(err)
	}
	try := func(key string) error {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.1:1"
		r.Header.Set("Authorization", "Bearer "+key)
		_, err := a.Authenticate(r)
		return err
	}
	if try(oldKey) != nil || try(newKey) != nil {
		t.Fatal("overlap not honoured")
	}
	now = later.Add(time.Second)
	if status(try(oldKey)) != 401 || try(newKey) != nil {
		t.Fatal("previous key accepted after the overlap")
	}

	b, _ := setup(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	if _, err := b.Authenticate(r); status(err) != 401 {
		t.Fatal("API key accepted without a key store")
	}
}

func tampered(key string) string {
	i := len(key) - 10
	c := byte('A')
	if key[i] == 'A' {
		c = 'B'
	}
	return key[:i] + string(c) + key[i+1:]
}

// Refusals of unknown or malformed keys are aggregated per source address
// and minute; refusals of existing keys are audited one by one.
func TestAPIKeyFailureAuditAggregated(t *testing.T) {
	a, _ := setup(t)
	now := time.Now()
	a.SetClock(func() time.Time { return now })
	st := store.NewMemory().(store.APIKeyStore)
	log := &auditLog{}
	a.SetAPIKeys(st, log)
	id := apikey.NewID()
	key := apikey.NewSecret(id)
	if err := st.CreateAPIKey(context.Background(), store.APIKey{ID: id, Team: "edge", Role: "acme-solver", RoleGrant: grantOf(a, "acme-solver"), SecretHash: apikey.Hash(key), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	try := func(remote, tok string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer "+tok)
		if _, err := a.Authenticate(r); err == nil {
			t.Fatal("accepted")
		}
	}
	for i := 0; i < 5; i++ {
		try("192.0.2.1:1", apikey.NewSecret(apikey.NewID()))
		try("192.0.2.1:1", "dgk_garbage")
	}
	try("192.0.2.2:1", "dgk_garbage")
	if len(log.events) != 2 {
		t.Fatalf("noise not aggregated: %d events", len(log.events))
	}
	now = now.Add(time.Minute)
	try("192.0.2.1:1", "dgk_garbage")
	if len(log.events) != 3 || log.events[2].Extra["count"] != 10 {
		t.Fatalf("aggregate: %+v", log.events)
	}
	for i := 0; i < 3; i++ {
		try("192.0.2.1:1", tampered(key))
	}
	if len(log.events) != 4 || log.events[3].Subject != "api-key:"+id {
		t.Fatalf("refusals of an existing key not aggregated per key and address: %+v", log.events)
	}
	try("192.0.2.9:1", tampered(key))
	if len(log.events) != 5 {
		t.Fatalf("refusal of an existing key from another address: %+v", log.events)
	}
}

// IPv6 sources are aggregated per /64, and the aggregation state is
// bounded: an evicted source reports its pending count.
func TestAPIKeyFailureAggregationBounded(t *testing.T) {
	a, _ := setup(t)
	now := time.Now()
	a.SetClock(func() time.Time { return now })
	log := &auditLog{}
	a.SetAPIKeys(store.NewMemory().(store.APIKeyStore), log)
	a.noise.max = 4
	try := func(remote string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer dgk_garbage")
		_, _ = a.Authenticate(r)
	}
	try("[2001:db8:1:1::1]:1")
	try("[2001:db8:1:1::2]:1")
	try("[2001:db8:1:2::1]:1")
	if len(log.events) != 2 {
		t.Fatalf("IPv6 not aggregated per /64: %+v", log.events)
	}
	for i := 1; i <= 2; i++ {
		try(fmt.Sprintf("192.0.2.%d:1", i))
	}
	if len(log.events) != 4 || a.noise.len() != 4 {
		t.Fatalf("events %d, entries %d", len(log.events), a.noise.len())
	}
	try("192.0.2.3:1")
	ev := log.events[len(log.events)-2]
	if a.noise.len() != 4 || ev.Extra["count"] != 1 || ev.Extra["remote_addr"] != "2001:db8:1:1::/64" {
		t.Fatalf("eviction: entries %d, events %+v", a.noise.len(), log.events)
	}
}

// A key is refused once its role grants more than at issuance (the grant
// snapshot); a role that shrank is fine.
func TestAPIKeyRoleWidened(t *testing.T) {
	scope := &config.RecordScope{Hosts: []string{"_acme-challenge", "_acme-challenge.**"}, Types: []string{"TXT"}}
	write := []string{"dns.read", "dns.record.write"}
	c := &config.Config{
		Zones:  []string{"example.com"},
		Limits: config.Limits{MaxChangesPerRequest: 20},
		Roles: map[string]config.Role{
			"narrow": {EphemeralTTL: config.Duration(time.Hour), Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: write, Records: scope}}},
			"wide":   {EphemeralTTL: config.Duration(time.Hour), Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: write}}},
		},
	}
	a, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory().(store.APIKeyStore)
	log := &auditLog{}
	a.SetAPIKeys(st, log)
	snap := a.policy.Current()
	grant := func(role string) string {
		g, _ := snap.RoleGrant(role)
		b, _ := json.Marshal(g)
		return string(b)
	}
	try := func(role, issued string) error {
		id := apikey.NewID()
		key := apikey.NewSecret(id)
		if err := st.CreateAPIKey(context.Background(), store.APIKey{ID: id, Team: "web", Role: role, RoleGrant: issued, SecretHash: apikey.Hash(key), CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		_, err := a.Authenticate(r)
		return err
	}
	if err := try("wide", grant("narrow")); status(err) != 403 || log.events[len(log.events)-1].Reason != "role_widened" {
		t.Fatalf("widened role: %v %+v", err, log.events)
	}
	if err := try("narrow", grant("wide")); err != nil {
		t.Fatalf("narrowed role: %v", err)
	}
	if err := try("narrow", grant("narrow")); err != nil {
		t.Fatalf("same role: %v", err)
	}
	if err := try("narrow", ""); status(err) != 403 {
		t.Fatalf("key without a recorded grant: %v", err)
	}
}

// grantOf is the grant a key of role records at issuance.
func grantOf(a *Authenticator, role string) string {
	g, _ := a.policy.Current().RoleGrant(role)
	b, _ := json.Marshal(g)
	return string(b)
}

// Once a teams block exists, a key bound to an undeclared team is refused,
// like a virtual key in the file.
func TestAPIKeyTeamMustBeDeclared(t *testing.T) {
	scope := &config.RecordScope{Hosts: []string{"_acme-challenge"}, Types: []string{"TXT"}}
	c := &config.Config{
		Zones:  []string{"example.com"},
		Limits: config.Limits{MaxChangesPerRequest: 20},
		Roles: map[string]config.Role{
			"acme": {EphemeralTTL: config.Duration(time.Hour), Rules: []config.Rule{{Zones: []string{"example.com"}, Actions: []string{"dns.record.write"}, Records: scope}}},
		},
		Teams: map[string]config.Team{"web": {}},
	}
	a, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory().(store.APIKeyStore)
	a.SetAPIKeys(st, &auditLog{})
	try := func(team string) (*identity.Subject, error) {
		id := apikey.NewID()
		key := apikey.NewSecret(id)
		if err := st.CreateAPIKey(context.Background(), store.APIKey{ID: id, Team: team, Role: "acme", RoleGrant: grantOf(a, "acme"), SecretHash: apikey.Hash(key), CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		return a.Authenticate(r)
	}
	s, err := try("web")
	if err != nil || s.TeamRoles["web"][0] != "acme" {
		t.Fatalf("declared team: %+v %v", s, err)
	}
	if _, err := try("legacy"); status(err) != 403 {
		t.Fatalf("a key of an undeclared team must be refused once teams are declared: %v", err)
	}
}
