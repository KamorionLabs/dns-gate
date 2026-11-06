package store

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// API key items: pk=APIKEY, sk=KEY#<id>. ListAPIKeys reads the whole
// partition and sorts in memory.
const apiKeyPK = "APIKEY"

func apiKeySK(id string) string { return "KEY#" + id }

type apiKeyItem struct {
	PK                string   `dynamodbav:"pk"`
	SK                string   `dynamodbav:"sk"`
	ID                string   `dynamodbav:"id"`
	Name              string   `dynamodbav:"name,omitempty"`
	Description       string   `dynamodbav:"description,omitempty"`
	Team              string   `dynamodbav:"team"`
	Role              string   `dynamodbav:"role"`
	SecretHash        string   `dynamodbav:"secret_hash"`
	PreviousHash      string   `dynamodbav:"previous_hash,omitempty"`
	PreviousExpiresAt string   `dynamodbav:"previous_expires_at,omitempty"`
	ExpiresAt         string   `dynamodbav:"expires_at,omitempty"`
	AllowedCIDRs      []string `dynamodbav:"allowed_cidrs,omitempty"`
	CreatedAt         string   `dynamodbav:"created_at"`
	CreatedBy         string   `dynamodbav:"created_by,omitempty"`
	CreatedByName     string   `dynamodbav:"created_by_name,omitempty"`
	RotatedAt         string   `dynamodbav:"rotated_at,omitempty"`
	RevokedAt         string   `dynamodbav:"revoked_at,omitempty"`
	RevokedBy         string   `dynamodbav:"revoked_by,omitempty"`
	LastUsedAt        string   `dynamodbav:"last_used_at,omitempty"`
	LastUsedIP        string   `dynamodbav:"last_used_ip,omitempty"`
	Version           int64    `dynamodbav:"version"`
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return &t
}

func toAPIKeyItem(k APIKey) apiKeyItem {
	return apiKeyItem{
		PK: apiKeyPK, SK: apiKeySK(k.ID), ID: k.ID, Name: k.Name, Description: k.Description, Team: k.Team, Role: k.Role,
		SecretHash: k.SecretHash, PreviousHash: k.PreviousHash, PreviousExpiresAt: fmtTime(k.PreviousExpiresAt),
		ExpiresAt: fmtTime(k.ExpiresAt), AllowedCIDRs: k.AllowedCIDRs, CreatedAt: fmtTime(&k.CreatedAt),
		CreatedBy: k.CreatedBy, CreatedByName: k.CreatedByName, RotatedAt: fmtTime(k.RotatedAt),
		RevokedAt: fmtTime(k.RevokedAt), RevokedBy: k.RevokedBy, LastUsedAt: fmtTime(k.LastUsedAt),
		LastUsedIP: k.LastUsedIP, Version: k.Version,
	}
}

func fromAPIKeyItem(it apiKeyItem) APIKey {
	k := APIKey{
		ID: it.ID, Name: it.Name, Description: it.Description, Team: it.Team, Role: it.Role,
		SecretHash: it.SecretHash, PreviousHash: it.PreviousHash, PreviousExpiresAt: parseTime(it.PreviousExpiresAt),
		ExpiresAt: parseTime(it.ExpiresAt), AllowedCIDRs: append([]string{}, it.AllowedCIDRs...),
		CreatedBy: it.CreatedBy, CreatedByName: it.CreatedByName, RotatedAt: parseTime(it.RotatedAt),
		RevokedAt: parseTime(it.RevokedAt), RevokedBy: it.RevokedBy, LastUsedAt: parseTime(it.LastUsedAt),
		LastUsedIP: it.LastUsedIP, Version: it.Version,
	}
	if t := parseTime(it.CreatedAt); t != nil {
		k.CreatedAt = *t
	}
	return k
}

func (d *dynamo) CreateAPIKey(ctx context.Context, k APIKey) error {
	if err := validateAPIKey(k); err != nil {
		return err
	}
	k.Version = 1
	item, err := attributevalue.MarshalMap(toAPIKeyItem(k))
	if err != nil {
		return fmt.Errorf("store: encode api key: %w", err)
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(d.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: create api key: %w", err)
	}
	return nil
}

func (d *dynamo) GetAPIKey(ctx context.Context, id string) (*APIKey, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            keyAttrs(apiKeyPK, apiKeySK(id)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get api key: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var it apiKeyItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, fmt.Errorf("store: decode api key: %w", err)
	}
	k := fromAPIKeyItem(it)
	return &k, nil
}

func (d *dynamo) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	out := []APIKey{}
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(d.table),
			KeyConditionExpression:    aws.String("pk = :pk"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": strAttr(apiKeyPK)},
			ConsistentRead:            aws.Bool(true),
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, fmt.Errorf("store: list api keys: %w", err)
		}
		for _, raw := range res.Items {
			var it apiKeyItem
			if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
				return nil, fmt.Errorf("store: decode api key: %w", err)
			}
			out = append(out, fromAPIKeyItem(it))
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		start = res.LastEvaluatedKey
	}
	sortAPIKeys(out)
	return out, nil
}

func (d *dynamo) UpdateAPIKey(ctx context.Context, k APIKey) error {
	optional := func(s string) types.AttributeValue {
		if s == "" {
			return &types.AttributeValueMemberNULL{Value: true}
		}
		return strAttr(s)
	}
	cidrs := &types.AttributeValueMemberL{Value: []types.AttributeValue{}}
	for _, c := range k.AllowedCIDRs {
		cidrs.Value = append(cidrs.Value, strAttr(c))
	}
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(d.table),
		Key:       keyAttrs(apiKeyPK, apiKeySK(k.ID)),
		UpdateExpression: aws.String("SET #n = :name, description = :desc, secret_hash = :sh, previous_hash = :ph, previous_expires_at = :pe, " +
			"expires_at = :exp, allowed_cidrs = :cidrs, rotated_at = :rot, revoked_at = :rev, revoked_by = :revby, version = :nv"),
		ConditionExpression:      aws.String("version = :v"),
		ExpressionAttributeNames: map[string]string{"#n": "name"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":name": strAttr(k.Name), ":desc": strAttr(k.Description), ":sh": strAttr(k.SecretHash), ":ph": strAttr(k.PreviousHash),
			":pe": optional(fmtTime(k.PreviousExpiresAt)), ":exp": optional(fmtTime(k.ExpiresAt)), ":cidrs": cidrs,
			":rot": optional(fmtTime(k.RotatedAt)), ":rev": optional(fmtTime(k.RevokedAt)), ":revby": strAttr(k.RevokedBy),
			":v": numAttr(k.Version), ":nv": numAttr(k.Version + 1),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: update api key: %w", err)
	}
	return nil
}

func (d *dynamo) TouchAPIKey(ctx context.Context, id string, at time.Time, ip string) error {
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(d.table),
		Key:                 keyAttrs(apiKeyPK, apiKeySK(id)),
		UpdateExpression:    aws.String("SET last_used_at = :at, last_used_ip = :ip"),
		ConditionExpression: aws.String("attribute_exists(pk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":at": strAttr(fmtTime(&at)), ":ip": strAttr(ip),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrNotFound
		}
		return fmt.Errorf("store: touch api key: %w", err)
	}
	return nil
}

// ACME registration items: pk=APIKEY#<key id>, sk=ACMEDNS#<subdomain>.
func acmeRegPK(keyID string) string     { return "APIKEY#" + keyID }
func acmeRegSK(subdomain string) string { return "ACMEDNS#" + subdomain }

type acmeRegItem struct {
	PK        string   `dynamodbav:"pk"`
	SK        string   `dynamodbav:"sk"`
	KeyID     string   `dynamodbav:"key_id"`
	Subdomain string   `dynamodbav:"subdomain"`
	Domain    string   `dynamodbav:"domain"`
	Origin    string   `dynamodbav:"origin,omitempty"`
	AllowFrom []string `dynamodbav:"allow_from,omitempty"`
	Values    []string `dynamodbav:"txt_values,omitempty"`
	CreatedAt string   `dynamodbav:"created_at"`
	UpdatedAt string   `dynamodbav:"updated_at"`
	ExpiresAt string   `dynamodbav:"expires_at,omitempty"`
	TTL       int64    `dynamodbav:"ttl,omitempty"`
	Version   int64    `dynamodbav:"version"`
}

func fromACMERegItem(it acmeRegItem) ACMERegistration {
	r := ACMERegistration{
		KeyID: it.KeyID, Subdomain: it.Subdomain, Domain: it.Domain, Origin: it.Origin, Version: it.Version,
		AllowFrom: append([]string{}, it.AllowFrom...), Values: append([]string{}, it.Values...),
		ExpiresAt: parseTime(it.ExpiresAt),
	}
	if r.Origin == "" {
		r.Origin = ACMEOriginClient
	}
	if t := parseTime(it.CreatedAt); t != nil {
		r.CreatedAt = *t
	}
	if t := parseTime(it.UpdatedAt); t != nil {
		r.UpdatedAt = *t
	}
	return r
}

func (d *dynamo) PutACMERegistration(ctx context.Context, r ACMERegistration) error {
	if err := validateACMERegistration(r); err != nil {
		return err
	}
	it := acmeRegItem{
		PK: acmeRegPK(r.KeyID), SK: acmeRegSK(r.Subdomain), KeyID: r.KeyID, Subdomain: r.Subdomain, Domain: r.Domain,
		Origin: r.Origin, AllowFrom: r.AllowFrom, Values: r.Values, CreatedAt: fmtTime(&r.CreatedAt), UpdatedAt: fmtTime(&r.UpdatedAt),
		ExpiresAt: fmtTime(r.ExpiresAt), Version: r.Version + 1,
	}
	if r.ExpiresAt != nil {
		it.TTL = r.ExpiresAt.Unix()
	}
	item, err := attributevalue.MarshalMap(it)
	if err != nil {
		return fmt.Errorf("store: encode acme registration: %w", err)
	}
	in := &dynamodb.PutItemInput{TableName: aws.String(d.table), Item: item}
	if r.Version == 0 {
		in.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		in.ConditionExpression = aws.String("version = :v")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":v": numAttr(r.Version)}
	}
	if _, err := d.api.PutItem(ctx, in); err != nil {
		if isConditionFailed(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: put acme registration: %w", err)
	}
	return nil
}

func (d *dynamo) GetACMERegistration(ctx context.Context, keyID, subdomain string) (*ACMERegistration, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            keyAttrs(acmeRegPK(keyID), acmeRegSK(subdomain)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("store: get acme registration: %w", err)
	}
	if len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var it acmeRegItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, fmt.Errorf("store: decode acme registration: %w", err)
	}
	r := fromACMERegItem(it)
	return &r, nil
}

func (d *dynamo) ListACMERegistrations(ctx context.Context, keyID string) ([]ACMERegistration, error) {
	out := []ACMERegistration{}
	var start map[string]types.AttributeValue
	for {
		res, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(d.table),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": strAttr(acmeRegPK(keyID)), ":prefix": strAttr("ACMEDNS#"),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("store: list acme registrations: %w", err)
		}
		for _, raw := range res.Items {
			var it acmeRegItem
			if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
				return nil, fmt.Errorf("store: decode acme registration: %w", err)
			}
			out = append(out, fromACMERegItem(it))
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		start = res.LastEvaluatedKey
	}
	sortACMERegistrations(out)
	return out, nil
}

func (d *dynamo) DeleteACMERegistration(ctx context.Context, keyID, subdomain string) error {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(d.table),
		Key:       keyAttrs(acmeRegPK(keyID), acmeRegSK(subdomain)),
	})
	if err != nil {
		return fmt.Errorf("store: delete acme registration: %w", err)
	}
	return nil
}

func (d *dynamo) PurgeACMERegistrations(context.Context, time.Time) (int, error) { return 0, nil }
