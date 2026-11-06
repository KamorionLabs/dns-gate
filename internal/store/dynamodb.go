package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type dynamoAPI interface {
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Scan(ctx context.Context, in *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

type dynamo struct {
	api       dynamoAPI
	table     string
	now       func() time.Time
	retention time.Duration
}

type ownershipItem struct {
	PK                string `dynamodbav:"pk"`
	SK                string `dynamodbav:"sk"`
	Zone              string `dynamodbav:"zone"`
	Host              string `dynamodbav:"host"`
	Type              string `dynamodbav:"type"`
	Owner             string `dynamodbav:"owner"`
	CreatedBy         string `dynamodbav:"created_by"`
	CreatedByName     string `dynamodbav:"created_by_name,omitempty"`
	CreatedByCategory string `dynamodbav:"created_by_category,omitempty"`
	UpdatedBy         string `dynamodbav:"updated_by,omitempty"`
	UpdatedByName     string `dynamodbav:"updated_by_name,omitempty"`
	UpdatedByCategory string `dynamodbav:"updated_by_category,omitempty"`
	CreatedAt         string `dynamodbav:"created_at"`
	UpdatedAt         string `dynamodbav:"updated_at"`
	RequestID         string `dynamodbav:"request_id,omitempty"`
	ContentHash       string `dynamodbav:"content_hash,omitempty"`
	PendingHash       string `dynamodbav:"pending_hash,omitempty"`
	State             string `dynamodbav:"state"`
	Adopted           bool   `dynamodbav:"adopted"`
	ExpiresAt         string `dynamodbav:"expires_at,omitempty"`
	TransferID        string `dynamodbav:"transfer_id,omitempty"`
	Version           int64  `dynamodbav:"version"`
}

func newDynamoDB(ctx context.Context, cfg DynamoDBConfig) (Store, error) {
	if cfg.Table == "" {
		return nil, errors.New("store: dynamodb table is required")
	}
	var loadOpts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("store: load aws config: %w", err)
	}
	client := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return &dynamo{api: client, table: cfg.Table, now: time.Now, retention: auditRetention(cfg.AuditRetention)}, nil
}

func zonePK(zone string) string             { return "ZONE#" + zone }
func rrsetSK(host, typ string) string       { return "RRSET#" + host + "#" + typ }
func strAttr(s string) types.AttributeValue { return &types.AttributeValueMemberS{Value: s} }
func numAttr(n int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}
func keyAttrs(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"pk": strAttr(pk), "sk": strAttr(sk)}
}

func isConditionFailed(err error) bool {
	var ccf *types.ConditionalCheckFailedException
	return errors.As(err, &ccf)
}

func toItem(o Ownership) ownershipItem {
	it := ownershipItem{
		PK: zonePK(o.Zone), SK: rrsetSK(o.Host, o.Type),
		Zone: o.Zone, Host: o.Host, Type: o.Type, Owner: o.Owner,
		CreatedBy: o.CreatedBy, CreatedByName: o.CreatedByName, CreatedByCategory: o.CreatedByCategory,
		UpdatedBy: o.UpdatedBy, UpdatedByName: o.UpdatedByName, UpdatedByCategory: o.UpdatedByCategory,
		CreatedAt: o.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: o.UpdatedAt.UTC().Format(time.RFC3339Nano), RequestID: o.RequestID,
		ContentHash: o.ContentHash, PendingHash: o.PendingHash, State: string(o.State),
		Adopted: o.Adopted, TransferID: o.TransferID, Version: o.Version,
	}
	if o.ExpiresAt != nil {
		it.ExpiresAt = o.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return it
}

func fromItem(it ownershipItem) Ownership {
	o := Ownership{
		Zone: it.Zone, Host: it.Host, Type: it.Type, Owner: it.Owner, CreatedBy: it.CreatedBy,
		CreatedByName: it.CreatedByName, CreatedByCategory: it.CreatedByCategory,
		UpdatedBy: it.UpdatedBy, UpdatedByName: it.UpdatedByName, UpdatedByCategory: it.UpdatedByCategory,
		RequestID: it.RequestID, ContentHash: it.ContentHash, PendingHash: it.PendingHash,
		State: State(it.State), Adopted: it.Adopted, TransferID: it.TransferID, Version: it.Version,
	}
	o.CreatedAt, _ = time.Parse(time.RFC3339Nano, it.CreatedAt)
	o.UpdatedAt, _ = time.Parse(time.RFC3339Nano, it.UpdatedAt)
	if it.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, it.ExpiresAt); err == nil {
			o.ExpiresAt = &t
		}
	}
	return o
}

func (d *dynamo) Get(ctx context.Context, zone, host, typ string) (*Ownership, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            keyAttrs(zonePK(zone), rrsetSK(host, typ)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var it ownershipItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, fmt.Errorf("store: decode: %w", err)
	}
	o := fromItem(it)
	return &o, nil
}

func (d *dynamo) List(ctx context.Context, zone string) ([]Ownership, error) {
	var out []Ownership
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(d.table),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": strAttr(zonePK(zone)), ":prefix": strAttr("RRSET#"),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("store: list: %w", err)
		}
		for _, raw := range res.Items {
			var it ownershipItem
			if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
				return nil, fmt.Errorf("store: decode: %w", err)
			}
			out = append(out, fromItem(it))
		}
		if len(res.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = res.LastEvaluatedKey
	}
}

func (d *dynamo) Put(ctx context.Context, o Ownership) error {
	expected := o.Version
	o.Version = expected + 1
	item, err := attributevalue.MarshalMap(toItem(o))
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}
	in := &dynamodb.PutItemInput{TableName: aws.String(d.table), Item: item}
	if expected == 0 {
		in.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		in.ConditionExpression = aws.String("version = :v")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":v": numAttr(expected)}
	}
	if _, err := d.api.PutItem(ctx, in); err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: put: %w", err)
	}
	return nil
}

func (d *dynamo) Delete(ctx context.Context, zone, host, typ string, version int64) error {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(d.table),
		Key:                       keyAttrs(zonePK(zone), rrsetSK(host, typ)),
		ConditionExpression:       aws.String("attribute_exists(pk) AND version = :v"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": numAttr(version)},
	})
	if err == nil {
		return nil
	}
	if !isConditionFailed(err) {
		return fmt.Errorf("store: delete: %w", err)
	}
	if _, gerr := d.Get(ctx, zone, host, typ); errors.Is(gerr, ErrNotFound) {
		return ErrNotFound
	}
	return ErrConflict
}

func (d *dynamo) ZoneVersion(ctx context.Context, zone string) (int64, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            keyAttrs(zonePK(zone), "META"),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("store: zone version: %w", err)
	}
	v, ok := out.Item["zone_version"].(*types.AttributeValueMemberN)
	if !ok {
		return 0, nil
	}
	return strconv.ParseInt(v.Value, 10, 64)
}

func (d *dynamo) BumpZoneVersion(ctx context.Context, zone string, expected int64) (int64, error) {
	cond := "zone_version = :exp"
	if expected == 0 {
		cond = "attribute_not_exists(zone_version) OR zone_version = :exp"
	}
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(d.table),
		Key:                 keyAttrs(zonePK(zone), "META"),
		UpdateExpression:    aws.String("SET zone_version = :new"),
		ConditionExpression: aws.String(cond),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":exp": numAttr(expected), ":new": numAttr(expected + 1),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return 0, ErrConflict
		}
		return 0, fmt.Errorf("store: bump zone version: %w", err)
	}
	return expected + 1, nil
}

func (d *dynamo) Lock(ctx context.Context, zone, holder string, ttl time.Duration) error {
	now := d.now()
	expires := now.Add(ttl)
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			"pk":            strAttr(zonePK(zone)),
			"sk":            strAttr("LOCK"),
			"holder":        strAttr(holder),
			"lease_expires": numAttr(expires.UnixMilli()),
			"ttl":           numAttr(expires.Add(24 * time.Hour).Unix()),
		},
		ConditionExpression: aws.String("attribute_not_exists(pk) OR holder = :h OR lease_expires < :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":h": strAttr(holder), ":now": numAttr(now.UnixMilli()),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrLockHeld
		}
		return fmt.Errorf("store: lock: %w", err)
	}
	return nil
}

func (d *dynamo) Unlock(ctx context.Context, zone, holder string) error {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(d.table),
		Key:                       keyAttrs(zonePK(zone), "LOCK"),
		ConditionExpression:       aws.String("holder = :h"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":h": strAttr(holder)},
	})
	if err != nil && !isConditionFailed(err) {
		return fmt.Errorf("store: unlock: %w", err)
	}
	return nil
}
