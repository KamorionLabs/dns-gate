package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/KamorionLabs/dns-gate/internal/audit"
)

// Audit items: pk=AUDIT#<zone> (AUDIT#_global for zone-less events) plus a
// copy under AUDIT#_all for cross-zone queries; sk=<time>#<event id>
// (<time>#<request id> for events recorded before event ids); attribute
// "event" holds the JSON event, "event_id" its id, "ttl" the retention.
const (
	auditGlobal = "_global"
	auditAll    = "_all"
)

func auditPK(partition string) string { return "AUDIT#" + partition }

func (d *dynamo) AppendAudit(ctx context.Context, e audit.Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("store: encode audit: %w", err)
	}
	partition := e.Zone
	if partition == "" {
		partition = auditGlobal
	}
	sk := auditSortKey(e)
	ttl := e.Time.Add(d.retention).Unix()
	for _, p := range []string{partition, auditAll} {
		item := map[string]types.AttributeValue{
			"pk":    strAttr(auditPK(p)),
			"sk":    strAttr(sk),
			"event": strAttr(string(body)),
			"ttl":   numAttr(ttl),
		}
		if e.EventID != "" {
			item["event_id"] = strAttr(e.EventID)
		}
		_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table), Item: item})
		if err != nil {
			return fmt.Errorf("store: append audit: %w", err)
		}
	}
	return nil
}

func (d *dynamo) ListAudit(ctx context.Context, q AuditQuery) ([]audit.Event, string, error) {
	after, err := decodeCursor(q.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := auditLimit(q)
	partition := auditAll
	if q.Zone != "" {
		partition = q.Zone
	}
	cond := "pk = :pk"
	values := map[string]types.AttributeValue{":pk": strAttr(auditPK(partition))}
	if after != "" {
		cond += " AND sk < :after"
		values[":after"] = strAttr(after)
	}
	var out []audit.Event
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(d.table),
			KeyConditionExpression:    aws.String(cond),
			ExpressionAttributeValues: values,
			ScanIndexForward:          aws.Bool(false),
			ExclusiveStartKey:         start,
			Limit:                     aws.Int32(int32(limit + 1)),
		})
		if err != nil {
			return nil, "", fmt.Errorf("store: list audit: %w", err)
		}
		for _, item := range res.Items {
			raw, ok := item["event"].(*types.AttributeValueMemberS)
			if !ok {
				continue
			}
			var e audit.Event
			if err := json.Unmarshal([]byte(raw.Value), &e); err != nil {
				return nil, "", fmt.Errorf("store: decode audit: %w", err)
			}
			if !q.Since.IsZero() && e.Time.Before(q.Since) {
				return out, "", nil
			}
			if !matchAudit(e, q) {
				continue
			}
			if len(out) == limit {
				return out, encodeCursor(auditSortKey(out[len(out)-1])), nil
			}
			out = append(out, e)
		}
		if len(res.LastEvaluatedKey) == 0 {
			return out, "", nil
		}
		start = res.LastEvaluatedKey
	}
}
