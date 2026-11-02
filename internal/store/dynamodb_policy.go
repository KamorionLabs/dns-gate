package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Policy items: pk=POLICY, sk=REV#<id> (one revision, document as binary)
// and pk=POLICY, sk=ACTIVE (revision_id of the active revision).
// ListRevisions reads the whole POLICY partition and sorts in memory, which
// is fine for thousands of revisions.
const policyPK = "POLICY"

type revisionItem struct {
	PK          string `dynamodbav:"pk"`
	SK          string `dynamodbav:"sk"`
	ID          string `dynamodbav:"id"`
	ParentID    string `dynamodbav:"parent_id,omitempty"`
	Document    []byte `dynamodbav:"document"`
	Author      string `dynamodbav:"author,omitempty"`
	AuthorName  string `dynamodbav:"author_name,omitempty"`
	AuthorCat   string `dynamodbav:"author_cat,omitempty"`
	CreatedAt   string `dynamodbav:"created_at"`
	Comment     string `dynamodbav:"comment,omitempty"`
	Status      string `dynamodbav:"status"`
	Approvals   string `dynamodbav:"approvals"`
	ActivatedAt string `dynamodbav:"activated_at,omitempty"`
	ActivatedBy string `dynamodbav:"activated_by,omitempty"`
	Version     int64  `dynamodbav:"version"`
}

func revisionSK(id string) string { return "REV#" + id }

func toRevisionItem(r PolicyRevision) (revisionItem, error) {
	approvals, err := encodeApprovals(r.Approvals)
	if err != nil {
		return revisionItem{}, err
	}
	it := revisionItem{
		PK: policyPK, SK: revisionSK(r.ID), ID: r.ID, ParentID: r.ParentID, Document: r.Document,
		Author: r.Author, AuthorName: r.AuthorName, AuthorCat: r.AuthorCat,
		CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339Nano), Comment: r.Comment, Status: r.Status,
		Approvals: approvals, ActivatedBy: r.ActivatedBy, Version: r.Version,
	}
	if r.ActivatedAt != nil {
		it.ActivatedAt = r.ActivatedAt.UTC().Format(time.RFC3339Nano)
	}
	return it, nil
}

func fromRevisionItem(it revisionItem) (PolicyRevision, error) {
	r := PolicyRevision{
		ID: it.ID, ParentID: it.ParentID, Document: it.Document, Author: it.Author, AuthorName: it.AuthorName,
		AuthorCat: it.AuthorCat, Comment: it.Comment, Status: it.Status, ActivatedBy: it.ActivatedBy, Version: it.Version,
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339Nano, it.CreatedAt)
	if it.ActivatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, it.ActivatedAt); err == nil {
			r.ActivatedAt = &t
		}
	}
	if err := json.Unmarshal([]byte(it.Approvals), &r.Approvals); err != nil {
		return r, fmt.Errorf("store: decode approvals: %w", err)
	}
	return r, nil
}

func (d *dynamo) CreateRevision(ctx context.Context, r PolicyRevision) error {
	if err := validateNewRevision(r); err != nil {
		return err
	}
	r.Version = 1
	it, err := toRevisionItem(r)
	if err != nil {
		return err
	}
	item, err := attributevalue.MarshalMap(it)
	if err != nil {
		return fmt.Errorf("store: encode revision: %w", err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if isConditionFailed(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: create revision: %w", err)
	}
	return nil
}

func (d *dynamo) GetRevision(ctx context.Context, id string) (*PolicyRevision, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.table), Key: keyAttrs(policyPK, revisionSK(id)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get revision: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var it revisionItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, fmt.Errorf("store: decode revision: %w", err)
	}
	r, err := fromRevisionItem(it)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *dynamo) ListRevisions(ctx context.Context, status string, limit int, cursor string) ([]PolicyRevision, string, error) {
	var all []PolicyRevision
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(d.table),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": strAttr(policyPK), ":prefix": strAttr("REV#"),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, "", fmt.Errorf("store: list revisions: %w", err)
		}
		for _, raw := range res.Items {
			var it revisionItem
			if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
				return nil, "", fmt.Errorf("store: decode revision: %w", err)
			}
			r, err := fromRevisionItem(it)
			if err != nil {
				return nil, "", err
			}
			all = append(all, r)
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		start = res.LastEvaluatedKey
	}
	return pageRevisions(all, status, limit, cursor)
}

func (d *dynamo) UpdateRevision(ctx context.Context, r PolicyRevision) error {
	cur, err := d.GetRevision(ctx, r.ID)
	if err != nil {
		return err
	}
	if cur.Version != r.Version {
		return ErrConflict
	}
	if err := checkUpdateTransition(cur.Status, r.Status); err != nil {
		return err
	}
	approvals, err := encodeApprovals(r.Approvals)
	if err != nil {
		return err
	}
	activatedAt := ""
	if r.ActivatedAt != nil {
		activatedAt = r.ActivatedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err = d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(d.table),
		Key:                      keyAttrs(policyPK, revisionSK(r.ID)),
		UpdateExpression:         aws.String("SET #s = :s, approvals = :a, activated_at = :at, activated_by = :by, version = :nv"),
		ConditionExpression:      aws.String("version = :v AND #s = :cs"),
		ExpressionAttributeNames: map[string]string{"#s": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":s": strAttr(r.Status), ":a": strAttr(approvals), ":at": strAttr(activatedAt), ":by": strAttr(r.ActivatedBy),
			":nv": numAttr(r.Version + 1), ":v": numAttr(r.Version), ":cs": strAttr(cur.Status),
		},
	})
	if isConditionFailed(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("store: update revision: %w", err)
	}
	return nil
}

func (d *dynamo) ActiveRevision(ctx context.Context) (*PolicyRevision, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.table), Key: keyAttrs(policyPK, "ACTIVE"), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: active revision: %w", err)
	}
	v, ok := out.Item["revision_id"].(*types.AttributeValueMemberS)
	if !ok {
		return nil, ErrNotFound
	}
	return d.GetRevision(ctx, v.Value)
}

func (d *dynamo) Activate(ctx context.Context, id, expectedActiveID, by string, at time.Time) error {
	pointer := &types.Put{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			"pk": strAttr(policyPK), "sk": strAttr("ACTIVE"), "revision_id": strAttr(id),
		},
	}
	if expectedActiveID == "" {
		pointer.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		pointer.ConditionExpression = aws.String("revision_id = :exp")
		pointer.ExpressionAttributeValues = map[string]types.AttributeValue{":exp": strAttr(expectedActiveID)}
	}
	items := []types.TransactWriteItem{
		{Put: pointer},
		{Update: &types.Update{
			TableName:                aws.String(d.table),
			Key:                      keyAttrs(policyPK, revisionSK(id)),
			UpdateExpression:         aws.String("SET #s = :active, activated_at = :at, activated_by = :by, version = version + :one"),
			ConditionExpression:      aws.String("#s IN (:p, :a)"),
			ExpressionAttributeNames: map[string]string{"#s": "status"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":active": strAttr(revisionActive), ":at": strAttr(at.UTC().Format(time.RFC3339Nano)), ":by": strAttr(by),
				":one": numAttr(1), ":p": strAttr(revisionProposed), ":a": strAttr(revisionApproved),
			},
		}},
	}
	if expectedActiveID != "" {
		items = append(items, types.TransactWriteItem{Update: &types.Update{
			TableName:                aws.String(d.table),
			Key:                      keyAttrs(policyPK, revisionSK(expectedActiveID)),
			UpdateExpression:         aws.String("SET #s = :sup, version = version + :one"),
			ConditionExpression:      aws.String("attribute_exists(pk)"),
			ExpressionAttributeNames: map[string]string{"#s": "status"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":sup": strAttr(revisionSuperseded), ":one": numAttr(1),
			},
		}})
	}
	_, err := d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err == nil {
		return nil
	}
	var canceled *types.TransactionCanceledException
	if !errors.As(err, &canceled) {
		return fmt.Errorf("store: activate: %w", err)
	}
	target, gerr := d.GetRevision(ctx, id)
	switch {
	case errors.Is(gerr, ErrNotFound):
		return ErrNotFound
	case gerr != nil:
		return fmt.Errorf("store: activate: %w", gerr)
	}
	reasons := canceled.CancellationReasons
	pointerFailed := len(reasons) > 0 && aws.ToString(reasons[0].Code) == "ConditionalCheckFailed"
	if !pointerFailed && !activatable(target.Status) {
		return ErrInvalidTransition
	}
	return ErrConflict
}
