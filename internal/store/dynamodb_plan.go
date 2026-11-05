package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func planPK(id string) string { return "PLAN#" + id }

const planSK = "PLAN"

func (d *dynamo) PutPlan(ctx context.Context, p Plan) error {
	if err := validatePlan(p); err != nil {
		return err
	}
	changes, err := encodeChanges(p.Changes)
	if err != nil {
		return err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			"pk":           strAttr(planPK(p.ID)),
			"sk":           strAttr(planSK),
			"subject":      strAttr(p.Subject),
			"zone":         strAttr(p.Zone),
			"changes":      strAttr(changes),
			"zone_version": numAttr(p.ZoneVersion),
			"created_at":   numAttr(p.CreatedAt.UnixMilli()),
			"expires_at":   numAttr(p.ExpiresAt.UnixMilli()),
			"ttl":          numAttr(p.ExpiresAt.Add(time.Hour).Unix()),
		},
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: put plan: %w", err)
	}
	return nil
}

func (d *dynamo) TakePlan(ctx context.Context, id, subject string, now time.Time) (*Plan, error) {
	out, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(d.table),
		Key:                       keyAttrs(planPK(id), planSK),
		ConditionExpression:       aws.String("subject = :s"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":s": strAttr(subject)},
		ReturnValues:              types.ReturnValueAllOld,
	})
	if err != nil {
		if !isConditionFailed(err) {
			return nil, fmt.Errorf("store: take plan: %w", err)
		}
		got, gerr := d.api.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(d.table),
			Key:            keyAttrs(planPK(id), planSK),
			ConsistentRead: aws.Bool(true),
		})
		if gerr != nil {
			return nil, fmt.Errorf("store: take plan: %w", gerr)
		}
		if len(got.Item) == 0 {
			return nil, ErrNotFound
		}
		return nil, ErrPlanOwner
	}
	if len(out.Attributes) == 0 {
		return nil, ErrNotFound
	}
	return planFromItem(id, out.Attributes, now)
}

func planFromItem(id string, it map[string]types.AttributeValue, now time.Time) (*Plan, error) {
	str := func(k string) string {
		if v, ok := it[k].(*types.AttributeValueMemberS); ok {
			return v.Value
		}
		return ""
	}
	num := func(k string) (int64, error) {
		v, ok := it[k].(*types.AttributeValueMemberN)
		if !ok {
			return 0, errors.New("store: plan item without " + k)
		}
		return strconv.ParseInt(v.Value, 10, 64)
	}
	p := &Plan{ID: id, Subject: str("subject"), Zone: str("zone")}
	var err error
	if p.ZoneVersion, err = num("zone_version"); err != nil {
		return nil, err
	}
	created, err := num("created_at")
	if err != nil {
		return nil, err
	}
	expires, err := num("expires_at")
	if err != nil {
		return nil, err
	}
	p.CreatedAt, p.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	if now.After(p.ExpiresAt) {
		return nil, ErrPlanExpired
	}
	if p.Changes, err = decodeChanges(str("changes")); err != nil {
		return nil, err
	}
	return p, nil
}

func (d *dynamo) GCPlans(context.Context, time.Time) (int, error) { return 0, nil }
