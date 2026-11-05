package identitystore

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/identitystore/types"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

type fakeStore struct {
	mu       sync.Mutex
	users    map[string]string
	members  map[string][]string
	names    map[string]string
	calls    map[string]int
	lastPath string
	failList bool
}

func (f *fakeStore) count(op string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[op]++
}

func (f *fakeStore) GetUserId(_ context.Context, in *identitystore.GetUserIdInput, _ ...func(*identitystore.Options)) (*identitystore.GetUserIdOutput, error) {
	f.count("GetUserId")
	if aws.ToString(in.IdentityStoreId) != "d-1234567890" {
		return nil, errors.New("wrong store")
	}
	ua := in.AlternateIdentifier.(*types.AlternateIdentifierMemberUniqueAttribute).Value
	f.mu.Lock()
	f.lastPath = aws.ToString(ua.AttributePath)
	f.mu.Unlock()
	b, err := ua.AttributeValue.MarshalSmithyDocument()
	if err != nil {
		return nil, err
	}
	id, ok := f.users[strings.Trim(string(b), `"`)]
	if !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("no user")}
	}
	return &identitystore.GetUserIdOutput{UserId: aws.String(id)}, nil
}

func (f *fakeStore) ListGroupMembershipsForMember(_ context.Context, in *identitystore.ListGroupMembershipsForMemberInput, _ ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsForMemberOutput, error) {
	f.count("List")
	if f.failList {
		return nil, errors.New("throttled")
	}
	ids := f.members[in.MemberId.(*types.MemberIdMemberUserId).Value]
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	out := &identitystore.ListGroupMembershipsForMemberOutput{}
	end := start + 1
	if end > len(ids) {
		end = len(ids)
	}
	for _, id := range ids[start:end] {
		out.GroupMemberships = append(out.GroupMemberships, types.GroupMembership{GroupId: aws.String(id)})
	}
	if end < len(ids) {
		out.NextToken = aws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeStore) DescribeGroup(_ context.Context, in *identitystore.DescribeGroupInput, _ ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	f.count("DescribeGroup")
	name, ok := f.names[aws.ToString(in.GroupId)]
	if !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("gone")}
	}
	return &identitystore.DescribeGroupOutput{GroupId: in.GroupId, DisplayName: aws.String(name)}, nil
}

func TestGroups(t *testing.T) {
	f := &fakeStore{
		users:   map[string]string{"alice@example.com": "u-1"},
		members: map[string][]string{"u-1": {"g-2", "g-1", "g-gone"}},
		names:   map[string]string{"g-1": "DNS-Admins", "g-2": "Ops"},
		calls:   map[string]int{},
	}
	l := New(f, config.IdentityStoreGroups{IdentityStoreID: "d-1234567890", UserAttribute: "email", CacheTTL: config.Duration(time.Minute)})
	now := time.Now()
	l.SetClock(func() time.Time { return now })

	got, err := l.Groups(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"DNS-Admins", "Ops"}) || f.lastPath != "emails.value" {
		t.Fatalf("groups %v path %q", got, f.lastPath)
	}
	if f.calls["List"] != 3 {
		t.Fatalf("pagination: %d list calls", f.calls["List"])
	}
	if _, err := l.Groups(context.Background(), "alice@example.com"); err != nil || f.calls["GetUserId"] != 1 {
		t.Fatalf("cache: %v %v", err, f.calls)
	}
	now = now.Add(2 * time.Minute)
	if _, err := l.Groups(context.Background(), "alice@example.com"); err != nil || f.calls["GetUserId"] != 2 {
		t.Fatalf("cache expiry: %v %v", err, f.calls)
	}
	if _, err := l.Groups(context.Background(), "bob@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	f.failList = true
	now = now.Add(2 * time.Minute)
	if _, err := l.Groups(context.Background(), "alice@example.com"); err == nil {
		t.Fatal("error swallowed")
	}

	l2 := New(f, config.IdentityStoreGroups{IdentityStoreID: "d-1234567890"})
	_, _ = l2.Groups(context.Background(), "alice@example.com")
	if f.lastPath != "userName" {
		t.Fatalf("default attribute path %q", f.lastPath)
	}
}
