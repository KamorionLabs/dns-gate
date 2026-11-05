// Package identitystore resolves the groups of an AWS IAM Identity Center
// user: GetUserId (by userName or email), ListGroupMembershipsForMember and
// DescribeGroup. Results are cached per instance for a short time.
package identitystore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/identitystore/document"
	"github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/KamorionLabs/dns-gate/internal/config"
)

// maxGroups bounds the groups kept for one user (session cookie size).
const maxGroups = 100

// maxCached bounds each per-instance cache.
const maxCached = 10000

// API is the subset of the identity store client used.
type API interface {
	GetUserId(ctx context.Context, in *identitystore.GetUserIdInput, opts ...func(*identitystore.Options)) (*identitystore.GetUserIdOutput, error)
	ListGroupMembershipsForMember(ctx context.Context, in *identitystore.ListGroupMembershipsForMemberInput, opts ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsForMemberOutput, error)
	DescribeGroup(ctx context.Context, in *identitystore.DescribeGroupInput, opts ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error)
}

// ErrUserNotFound reports a user absent from the identity store.
var ErrUserNotFound = errors.New("identity store: user not found")

// Lookup resolves group display names.
type Lookup struct {
	api      API
	storeID  string
	attrPath string
	ttl      time.Duration
	now      func() time.Time

	mu     sync.Mutex
	users  map[string]cached
	groups map[string]cached
}

type cached struct {
	names   []string
	expires time.Time
}

// New builds a lookup on api for the configuration c.
func New(api API, c config.IdentityStoreGroups) *Lookup {
	path := "userName"
	if c.UserAttribute == "email" {
		path = "emails.value"
	}
	ttl := c.CacheTTL.D()
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Lookup{
		api: api, storeID: c.IdentityStoreID, attrPath: path, ttl: ttl, now: time.Now,
		users: map[string]cached{}, groups: map[string]cached{},
	}
}

// NewAWS builds a lookup with the default AWS credential chain, assuming
// c.AssumeRoleARN when set. No AWS call is made before the first lookup.
func NewAWS(ctx context.Context, c config.IdentityStoreGroups) (*Lookup, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.Region))
	if err != nil {
		return nil, fmt.Errorf("identity store: %w", err)
	}
	if c.AssumeRoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), c.AssumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "dns-gate-groups"
		}))
	}
	return New(identitystore.NewFromConfig(cfg), c), nil
}

// SetClock overrides the clock (tests).
func (l *Lookup) SetClock(now func() time.Time) { l.now = now }

// Groups returns the sorted display names of the groups of the user whose
// configured attribute equals user.
func (l *Lookup) Groups(ctx context.Context, user string) ([]string, error) {
	if user == "" {
		return nil, ErrUserNotFound
	}
	now := l.now()
	l.mu.Lock()
	if c, ok := l.users[user]; ok && now.Before(c.expires) {
		l.mu.Unlock()
		return append([]string(nil), c.names...), nil
	}
	l.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := l.api.GetUserId(ctx, &identitystore.GetUserIdInput{
		IdentityStoreId: aws.String(l.storeID),
		AlternateIdentifier: &types.AlternateIdentifierMemberUniqueAttribute{Value: types.UniqueAttribute{
			AttributePath: aws.String(l.attrPath), AttributeValue: document.NewLazyDocument(user),
		}},
	})
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("identity store: GetUserId: %w", err)
	}
	userID := aws.ToString(out.UserId)
	var ids []string
	in := &identitystore.ListGroupMembershipsForMemberInput{
		IdentityStoreId: aws.String(l.storeID), MemberId: &types.MemberIdMemberUserId{Value: userID}, MaxResults: aws.Int32(100),
	}
	for {
		page, err := l.api.ListGroupMembershipsForMember(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("identity store: ListGroupMembershipsForMember: %w", err)
		}
		for _, m := range page.GroupMemberships {
			if id := aws.ToString(m.GroupId); id != "" {
				ids = append(ids, id)
			}
		}
		if page.NextToken == nil || *page.NextToken == "" || len(ids) >= maxGroups {
			break
		}
		in.NextToken = page.NextToken
	}
	if len(ids) > maxGroups {
		ids = ids[:maxGroups]
	}
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		name, err := l.groupName(ctx, id, now)
		if err != nil {
			return nil, err
		}
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	l.mu.Lock()
	if len(l.users) >= maxCached {
		l.users = map[string]cached{}
	}
	l.users[user] = cached{names: names, expires: now.Add(l.ttl)}
	l.mu.Unlock()
	return append([]string(nil), names...), nil
}

func (l *Lookup) groupName(ctx context.Context, id string, now time.Time) (string, error) {
	l.mu.Lock()
	if c, ok := l.groups[id]; ok && now.Before(c.expires) {
		l.mu.Unlock()
		return c.names[0], nil
	}
	l.mu.Unlock()
	out, err := l.api.DescribeGroup(ctx, &identitystore.DescribeGroupInput{IdentityStoreId: aws.String(l.storeID), GroupId: aws.String(id)})
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			return "", nil
		}
		return "", fmt.Errorf("identity store: DescribeGroup: %w", err)
	}
	name := aws.ToString(out.DisplayName)
	l.mu.Lock()
	if len(l.groups) >= maxCached {
		l.groups = map[string]cached{}
	}
	l.groups[id] = cached{names: []string{name}, expires: now.Add(l.ttl)}
	l.mu.Unlock()
	return name, nil
}
