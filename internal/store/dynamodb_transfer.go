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

// Tombstone items: pk=ZONE#<zone>, sk=TOMB#<host>#<type>, removed by the
// DynamoDB TTL after their expiry. Transfer items: pk=TRANSFERS,
// sk=TR#<id>, the request as JSON in document; ListTransfers reads the
// whole partition and sorts in memory, like the policy revisions.
const transfersPK = "TRANSFERS"

// TransferRetention is how long a transfer request is kept after its expiry.
const TransferRetention = 90 * 24 * time.Hour

func tombSK(host, typ string) string { return "TOMB#" + host + "#" + typ }
func transferSK(id string) string    { return "TR#" + id }

type tombstoneItem struct {
	PK                string `dynamodbav:"pk"`
	SK                string `dynamodbav:"sk"`
	Zone              string `dynamodbav:"zone"`
	Host              string `dynamodbav:"host"`
	Type              string `dynamodbav:"type"`
	Team              string `dynamodbav:"team"`
	ContentHash       string `dynamodbav:"content_hash,omitempty"`
	DeletedBy         string `dynamodbav:"deleted_by,omitempty"`
	DeletedByName     string `dynamodbav:"deleted_by_name,omitempty"`
	DeletedByCategory string `dynamodbav:"deleted_by_category,omitempty"`
	DeletedAt         string `dynamodbav:"deleted_at"`
	ExpiresAt         string `dynamodbav:"expires_at"`
	RequestID         string `dynamodbav:"request_id,omitempty"`
	TTL               int64  `dynamodbav:"ttl"`
}

func toTombstoneItem(t Tombstone) tombstoneItem {
	return tombstoneItem{
		PK: zonePK(t.Zone), SK: tombSK(t.Host, t.Type), Zone: t.Zone, Host: t.Host, Type: t.Type, Team: t.Team,
		ContentHash: t.ContentHash, DeletedBy: t.DeletedBy, DeletedByName: t.DeletedByName, DeletedByCategory: t.DeletedByCategory,
		DeletedAt: t.DeletedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339Nano),
		RequestID: t.RequestID, TTL: t.ExpiresAt.Add(time.Hour).Unix(),
	}
}

func fromTombstoneItem(it tombstoneItem) Tombstone {
	t := Tombstone{
		Zone: it.Zone, Host: it.Host, Type: it.Type, Team: it.Team, ContentHash: it.ContentHash,
		DeletedBy: it.DeletedBy, DeletedByName: it.DeletedByName, DeletedByCategory: it.DeletedByCategory, RequestID: it.RequestID,
	}
	t.DeletedAt, _ = time.Parse(time.RFC3339Nano, it.DeletedAt)
	t.ExpiresAt, _ = time.Parse(time.RFC3339Nano, it.ExpiresAt)
	return t
}

func (d *dynamo) PutTombstone(ctx context.Context, t Tombstone) error {
	item, err := attributevalue.MarshalMap(toTombstoneItem(t))
	if err != nil {
		return fmt.Errorf("store: encode tombstone: %w", err)
	}
	if _, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table), Item: item}); err != nil {
		return fmt.Errorf("store: put tombstone: %w", err)
	}
	return nil
}

func (d *dynamo) GetTombstone(ctx context.Context, zone, host, typ string) (*Tombstone, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.table), Key: keyAttrs(zonePK(zone), tombSK(host, typ)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get tombstone: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var it tombstoneItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, fmt.Errorf("store: decode tombstone: %w", err)
	}
	t := fromTombstoneItem(it)
	return &t, nil
}

func (d *dynamo) ListTombstones(ctx context.Context, zone string) ([]Tombstone, error) {
	var out []Tombstone
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(d.table),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": strAttr(zonePK(zone)), ":prefix": strAttr("TOMB#"),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("store: list tombstones: %w", err)
		}
		for _, raw := range res.Items {
			var it tombstoneItem
			if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
				return nil, fmt.Errorf("store: decode tombstone: %w", err)
			}
			out = append(out, fromTombstoneItem(it))
		}
		if len(res.LastEvaluatedKey) == 0 {
			sortTombstones(out)
			return out, nil
		}
		start = res.LastEvaluatedKey
	}
}

func (d *dynamo) DeleteWithTombstone(ctx context.Context, zone, host, typ string, version int64, t Tombstone) error {
	item, err := attributevalue.MarshalMap(toTombstoneItem(t))
	if err != nil {
		return fmt.Errorf("store: encode tombstone: %w", err)
	}
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{
			TableName: aws.String(d.table), Key: keyAttrs(zonePK(zone), rrsetSK(host, typ)),
			ConditionExpression:       aws.String("attribute_exists(pk) AND version = :v"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":v": numAttr(version)},
		}},
		{Put: &types.Put{TableName: aws.String(d.table), Item: item}},
	}})
	if err == nil {
		return nil
	}
	var tce *types.TransactionCanceledException
	if errors.As(err, &tce) {
		if _, gerr := d.Get(ctx, zone, host, typ); errors.Is(gerr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrConflict
	}
	return fmt.Errorf("store: delete with tombstone: %w", err)
}

func (d *dynamo) DeleteTombstone(ctx context.Context, zone, host, typ string) error {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(d.table), Key: keyAttrs(zonePK(zone), tombSK(host, typ))})
	if err != nil {
		return fmt.Errorf("store: delete tombstone: %w", err)
	}
	return nil
}

func (d *dynamo) GCTombstones(context.Context, time.Time) (int, error) { return 0, nil }

func (d *dynamo) transferItem(t Transfer, version int64) (map[string]types.AttributeValue, error) {
	doc, err := encodeTransfer(t)
	if err != nil {
		return nil, err
	}
	return map[string]types.AttributeValue{
		"pk":       strAttr(transfersPK),
		"sk":       strAttr(transferSK(t.ID)),
		"zone":     strAttr(t.Zone),
		"status":   strAttr(t.Status),
		"document": strAttr(doc),
		"version":  numAttr(version),
		"ttl":      numAttr(t.ExpiresAt.Add(TransferRetention).Unix()),
	}, nil
}

func transferFromItem(it map[string]types.AttributeValue) (Transfer, error) {
	doc, _ := it["document"].(*types.AttributeValueMemberS)
	ver, _ := it["version"].(*types.AttributeValueMemberN)
	if doc == nil || ver == nil {
		return Transfer{}, errors.New("store: transfer item without document or version")
	}
	var version int64
	if _, err := fmt.Sscan(ver.Value, &version); err != nil {
		return Transfer{}, fmt.Errorf("store: transfer version: %w", err)
	}
	return decodeTransfer(doc.Value, version)
}

func (d *dynamo) CreateTransfer(ctx context.Context, t Transfer) error {
	if err := validateTransfer(t); err != nil {
		return err
	}
	item, err := d.transferItem(t, 1)
	if err != nil {
		return err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if isConditionFailed(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: create transfer: %w", err)
	}
	return nil
}

func (d *dynamo) GetTransfer(ctx context.Context, id string) (*Transfer, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.table), Key: keyAttrs(transfersPK, transferSK(id)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get transfer: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	t, err := transferFromItem(out.Item)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (d *dynamo) ListTransfers(ctx context.Context, q TransferQuery) ([]Transfer, string, error) {
	var all []Transfer
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(d.table),
			KeyConditionExpression:    aws.String("pk = :pk"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": strAttr(transfersPK)},
			ConsistentRead:            aws.Bool(true),
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, "", fmt.Errorf("store: list transfers: %w", err)
		}
		for _, raw := range res.Items {
			t, err := transferFromItem(raw)
			if err != nil {
				return nil, "", err
			}
			all = append(all, t)
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		start = res.LastEvaluatedKey
	}
	return pageTransfers(all, q)
}

func (d *dynamo) UpdateTransfer(ctx context.Context, t Transfer) error {
	if err := validateTransfer(t); err != nil {
		return err
	}
	item, err := d.transferItem(t, t.Version+1)
	if err != nil {
		return err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table), Item: item,
		ConditionExpression:       aws.String("attribute_exists(pk) AND version = :v"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": numAttr(t.Version)},
	})
	if isConditionFailed(err) {
		if _, gerr := d.GetTransfer(ctx, t.ID); errors.Is(gerr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: update transfer: %w", err)
	}
	return nil
}

func (d *dynamo) GCTransfers(context.Context, time.Time) (int, error) { return 0, nil }

func (d *dynamo) Reassign(ctx context.Context, from string, owns []Ownership, tombs []Tombstone) error {
	if len(owns)+len(tombs) > MaxReassign {
		return errReassignSize
	}
	if len(owns)+len(tombs) == 0 {
		return nil
	}
	items := make([]types.TransactWriteItem, 0, len(owns)+len(tombs))
	for _, o := range owns {
		next := o
		next.Version = o.Version + 1
		item, err := attributevalue.MarshalMap(toItem(next))
		if err != nil {
			return fmt.Errorf("store: encode: %w", err)
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{
			TableName: aws.String(d.table), Item: item,
			ConditionExpression:       aws.String("version = :v"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":v": numAttr(o.Version)},
		}})
	}
	for _, t := range tombs {
		item, err := attributevalue.MarshalMap(toTombstoneItem(t))
		if err != nil {
			return fmt.Errorf("store: encode tombstone: %w", err)
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{
			TableName: aws.String(d.table), Item: item,
			ConditionExpression:       aws.String("team = :from"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":from": strAttr(from)},
		}})
	}
	_, err := d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err == nil {
		return nil
	}
	var tce *types.TransactionCanceledException
	if errors.As(err, &tce) {
		for _, r := range tce.CancellationReasons {
			if aws.ToString(r.Code) == "ConditionalCheckFailed" {
				return ErrConflict
			}
		}
	}
	return fmt.Errorf("store: reassign: %w", err)
}
