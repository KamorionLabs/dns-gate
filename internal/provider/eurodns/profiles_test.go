package eurodns_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	eurodnsprov "github.com/KamorionLabs/dns-gate/internal/provider/eurodns"
	"github.com/KamorionLabs/dns-gate/internal/provider/eurodns/profiletest"
	api "github.com/KamorionLabs/eurodns-go"
)

func profileProvider(t *testing.T) (*eurodnsprov.Provider, *profiletest.Fake) {
	t.Helper()
	fake := profiletest.New()
	fake.APIKey = "k"
	srv := httptest.NewServer(fake.Wrap(nil))
	t.Cleanup(srv.Close)
	c, err := api.New(api.WithBaseURL(srv.URL), api.WithAuth(api.APIKeyAuth{AppID: "a", APIKey: "k"}), api.WithRateLimit(time.Microsecond, 1000))
	if err != nil {
		t.Fatal(err)
	}
	return eurodnsprov.NewWithClient("eurodns", srv.URL, c), fake
}

func TestZoneProfileLifecycle(t *testing.T) {
	ctx := context.Background()
	p, fake := profileProvider(t)
	in := &eurodnsprov.ZoneProfile{Name: "transfer", Records: []api.Record{{Type: "A", Host: "@", TTL: 3600, RData: "192.0.2.1"}}}
	got, err := p.CreateZoneProfile(ctx, in)
	if err != nil || got.ID == nil || len(got.Records) != 1 || got.Records[0].ID == nil {
		t.Fatalf("create: %+v %v", got, err)
	}
	if b := fake.Bodies()[0]; !strings.Contains(b, `"urlForwards":[]`) || !strings.Contains(b, `"mailForwards":[]`) || strings.Contains(b, `"id"`) {
		t.Fatalf("create body: %s", b)
	}
	id := *got.ID
	read, err := p.GetZoneProfile(ctx, id)
	if err != nil || read.Name != "transfer" {
		t.Fatalf("get: %+v %v", read, err)
	}
	read.Records[0].RData = "192.0.2.2"
	read.Report = &api.ValidationReport{}
	if _, err := p.UpdateZoneProfile(ctx, id, read); err != nil || fake.Profile(id).Records[0].RData != "192.0.2.2" {
		t.Fatalf("update: %v", err)
	}
	if b := fake.Bodies()[1]; strings.Contains(b, `"report"`) || !strings.Contains(b, fmt.Sprintf(`"id":%d`, id)) {
		t.Fatalf("update body: %s", b)
	}
	chk, err := p.CheckZoneProfile(ctx, &eurodnsprov.ZoneProfile{Name: "x", Records: []api.Record{{Type: "A", Host: "@", TTL: 1, RData: "192.0.2.1"}}})
	if err != nil || chk.Report == nil || chk.Report.Valid() {
		t.Fatalf("check: %+v %v", chk, err)
	}
	_, err = p.CreateZoneProfile(ctx, &eurodnsprov.ZoneProfile{Name: "bad", Records: []api.Record{{Type: "A", Host: "@", TTL: 1, RData: "x"}}})
	var ae *api.APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusBadRequest || ae.Code != "INVALID_ZONE_PROFILE" {
		t.Fatalf("invalid create: %v", err)
	}
	if err := p.DeleteZoneProfile(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetZoneProfile(ctx, id); !api.IsNotFound(err) {
		t.Fatalf("get deleted: %v", err)
	}
}

func TestListZoneProfilesPages(t *testing.T) {
	ctx := context.Background()
	p, _ := profileProvider(t)
	for i := range 230 {
		if _, err := p.CreateZoneProfile(ctx, &eurodnsprov.ZoneProfile{Name: fmt.Sprintf("p%03d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := p.ListZoneProfiles(ctx)
	if err != nil || len(all) != 230 || all[0].Name != "p000" || all[229].Name != "p229" {
		t.Fatalf("list: %d %v", len(all), err)
	}
	page, h, err := p.ListZoneProfilesPage(ctx, eurodnsprov.ProfilePage{Page: 2, Size: 10, SortField: "name", SortOrder: "desc"})
	if err != nil || len(page) != 10 || page[0].Name != "p219" || h.Get("pagination-count") != "230" || h.Get("pagination-page") != "2" {
		t.Fatalf("page: %+v %v %v", page, h, err)
	}
}
