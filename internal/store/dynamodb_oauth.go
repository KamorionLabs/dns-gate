package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// OAuth items: grants under pk=OAUTH, sk=GRANT#<id> (ListOAuthGrants reads
// the partition and filters in memory); codes under pk=OAUTHCODE#<hash>,
// assertion ids under pk=OAUTHJTI#<jti>, both with sk=OAUTH and a TTL.
const (
	oauthGrantPK = "OAUTH"
	oauthSK      = "OAUTH"
)

func oauthGrantSK(id string) string  { return "GRANT#" + id }
func oauthCodePK(hash string) string { return "OAUTHCODE#" + hash }
func oauthJTIPK(key string) string   { return "OAUTHJTI#" + key }

type oauthGrantItem struct {
	PK             string   `dynamodbav:"pk"`
	SK             string   `dynamodbav:"sk"`
	ID             string   `dynamodbav:"id"`
	ClientID       string   `dynamodbav:"client_id"`
	Subject        string   `dynamodbav:"subject"`
	SubjectName    string   `dynamodbav:"subject_name,omitempty"`
	Issuer         string   `dynamodbav:"issuer"`
	Session        []byte   `dynamodbav:"session_data,omitempty"`
	AuthTime       int64    `dynamodbav:"auth_time"`
	Scopes         []string `dynamodbav:"scopes"`
	CreatedAt      string   `dynamodbav:"created_at"`
	ConsentedAt    string   `dynamodbav:"consented_at"`
	LastUsedAt     string   `dynamodbav:"last_used_at"`
	ExpiresAt      string   `dynamodbav:"expires_at"`
	ClaimsAt       string   `dynamodbav:"claims_at"`
	Generation     int64    `dynamodbav:"generation"`
	BaseGeneration int64    `dynamodbav:"base_generation"`
	RefreshHash    string   `dynamodbav:"refresh_hash,omitempty"`
	PreviousHash   string   `dynamodbav:"previous_hash,omitempty"`
	RotatedAt      string   `dynamodbav:"rotated_at,omitempty"`
	Pending        string   `dynamodbav:"pending,omitempty"`
	RevokedAt      string   `dynamodbav:"revoked_at,omitempty"`
	RevokedBy      string   `dynamodbav:"revoked_by,omitempty"`
	RevokeReason   string   `dynamodbav:"revoke_reason,omitempty"`
	Version        int64    `dynamodbav:"version"`
	TTL            int64    `dynamodbav:"ttl"`
}

func oauthGrantTTL(g OAuthGrant) int64 {
	end := g.ExpiresAt
	if g.RevokedAt != nil && g.RevokedAt.Before(end) {
		end = *g.RevokedAt
	}
	return end.Add(OAuthGrantRetention).Unix()
}

func toOAuthGrantItem(g OAuthGrant) oauthGrantItem {
	return oauthGrantItem{
		PK: oauthGrantPK, SK: oauthGrantSK(g.ID), ID: g.ID, ClientID: g.ClientID, Subject: g.Subject, SubjectName: g.SubjectName,
		Issuer: g.Issuer, Session: g.Session, AuthTime: g.AuthTime, Scopes: append([]string{}, g.Scopes...),
		CreatedAt: fmtTime(&g.CreatedAt), ConsentedAt: fmtTime(&g.ConsentedAt), LastUsedAt: fmtTime(&g.LastUsedAt),
		ExpiresAt: fmtTime(&g.ExpiresAt), ClaimsAt: fmtTime(&g.ClaimsAt), Generation: g.Generation, BaseGeneration: g.BaseGeneration,
		RefreshHash: g.RefreshHash, PreviousHash: g.PreviousHash, RotatedAt: fmtTime(g.RotatedAt), Pending: g.Pending,
		RevokedAt: fmtTime(g.RevokedAt), RevokedBy: g.RevokedBy, RevokeReason: g.RevokeReason, Version: g.Version, TTL: oauthGrantTTL(g),
	}
}

func fromOAuthGrantItem(it oauthGrantItem) OAuthGrant {
	at := func(s string) time.Time {
		if t := parseTime(s); t != nil {
			return *t
		}
		return time.Time{}
	}
	return OAuthGrant{
		ID: it.ID, ClientID: it.ClientID, Subject: it.Subject, SubjectName: it.SubjectName, Issuer: it.Issuer,
		Session: append([]byte(nil), it.Session...), AuthTime: it.AuthTime, Scopes: append([]string{}, it.Scopes...),
		CreatedAt: at(it.CreatedAt), ConsentedAt: at(it.ConsentedAt), LastUsedAt: at(it.LastUsedAt), ExpiresAt: at(it.ExpiresAt), ClaimsAt: at(it.ClaimsAt),
		Generation: it.Generation, BaseGeneration: it.BaseGeneration, RefreshHash: it.RefreshHash, PreviousHash: it.PreviousHash,
		RotatedAt: parseTime(it.RotatedAt), Pending: it.Pending, RevokedAt: parseTime(it.RevokedAt), RevokedBy: it.RevokedBy,
		RevokeReason: it.RevokeReason, Version: it.Version,
	}
}

func (d *dynamo) putOAuthGrant(ctx context.Context, g OAuthGrant, cond string, values map[string]types.AttributeValue) error {
	item, err := attributevalue.MarshalMap(toOAuthGrantItem(g))
	if err != nil {
		return fmt.Errorf("store: encode oauth grant: %w", err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(d.table),
		Item:                      item,
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeValues: values,
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: put oauth grant: %w", err)
	}
	return nil
}

func (d *dynamo) CreateOAuthGrant(ctx context.Context, g OAuthGrant) error {
	if err := validateOAuthGrant(g); err != nil {
		return err
	}
	g.Version = 1
	return d.putOAuthGrant(ctx, g, "attribute_not_exists(pk)", nil)
}

func (d *dynamo) GetOAuthGrant(ctx context.Context, id string) (*OAuthGrant, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            keyAttrs(oauthGrantPK, oauthGrantSK(id)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get oauth grant: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var it oauthGrantItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, fmt.Errorf("store: decode oauth grant: %w", err)
	}
	g := fromOAuthGrantItem(it)
	return &g, nil
}

func (d *dynamo) ListOAuthGrants(ctx context.Context, q OAuthGrantQuery) ([]OAuthGrant, error) {
	out := []OAuthGrant{}
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(d.table),
			KeyConditionExpression:    aws.String("pk = :pk"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": strAttr(oauthGrantPK)},
			ConsistentRead:            aws.Bool(true),
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, fmt.Errorf("store: list oauth grants: %w", err)
		}
		for _, raw := range res.Items {
			var it oauthGrantItem
			if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
				return nil, fmt.Errorf("store: decode oauth grant: %w", err)
			}
			if g := fromOAuthGrantItem(it); q.match(g) {
				out = append(out, g)
			}
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		start = res.LastEvaluatedKey
	}
	sortOAuthGrants(out)
	return out, nil
}

func (d *dynamo) UpdateOAuthGrant(ctx context.Context, g OAuthGrant) error {
	cur, err := d.GetOAuthGrant(ctx, g.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrConflict
		}
		return err
	}
	if cur.Version != g.Version {
		return ErrConflict
	}
	n := g
	n.ClientID, n.Subject, n.CreatedAt = cur.ClientID, cur.Subject, cur.CreatedAt
	n.Version = g.Version + 1
	return d.putOAuthGrant(ctx, n, "version = :v", map[string]types.AttributeValue{":v": numAttr(g.Version)})
}

func (d *dynamo) PutOAuthCode(ctx context.Context, c OAuthCode) error {
	if c.Hash == "" || c.ClientID == "" {
		return fmt.Errorf("store: oauth code hash and client are required")
	}
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			"pk":         strAttr(oauthCodePK(c.Hash)),
			"sk":         strAttr(oauthSK),
			"client_id":  strAttr(c.ClientID),
			"data":       &types.AttributeValueMemberB{Value: c.Data},
			"expires_at": numAttr(c.ExpiresAt.UnixMilli()),
			"ttl":        numAttr(c.ExpiresAt.Add(time.Hour).Unix()),
		},
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: put oauth code: %w", err)
	}
	return nil
}

func (d *dynamo) TakeOAuthCode(ctx context.Context, hash string) (*OAuthCode, error) {
	out, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(d.table),
		Key:          keyAttrs(oauthCodePK(hash), oauthSK),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, fmt.Errorf("store: take oauth code: %w", err)
	}
	if len(out.Attributes) == 0 {
		return nil, ErrNotFound
	}
	c := &OAuthCode{Hash: hash}
	if v, ok := out.Attributes["client_id"].(*types.AttributeValueMemberS); ok {
		c.ClientID = v.Value
	}
	if v, ok := out.Attributes["data"].(*types.AttributeValueMemberB); ok {
		c.Data = v.Value
	}
	if v, ok := out.Attributes["expires_at"].(*types.AttributeValueMemberN); ok {
		var ms int64
		if _, err := fmt.Sscan(v.Value, &ms); err == nil {
			c.ExpiresAt = time.UnixMilli(ms).UTC()
		}
	}
	return c, nil
}

func (d *dynamo) UseOAuthJTI(ctx context.Context, key string, exp, now time.Time) error {
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			"pk":         strAttr(oauthJTIPK(key)),
			"sk":         strAttr(oauthSK),
			"expires_at": numAttr(exp.UnixMilli()),
			"ttl":        numAttr(exp.Add(time.Hour).Unix()),
		},
		ConditionExpression:       aws.String("attribute_not_exists(pk) OR expires_at < :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": numAttr(now.UnixMilli())},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: use oauth jti: %w", err)
	}
	return nil
}

func (d *dynamo) PurgeOAuth(context.Context, time.Time) (int, error) { return 0, nil }
