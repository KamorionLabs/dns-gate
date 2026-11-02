package store

import (
	"context"
	"time"
)

// DynamoDBConfig configures the DynamoDB backend (single table).
type DynamoDBConfig struct {
	Table    string
	Region   string
	Endpoint string // optional, for local testing
	// AuditRetention sets the DynamoDB TTL of audit items (default 400 days).
	AuditRetention time.Duration
}

// NewMemory returns an in-process store (single replica, tests).
func NewMemory() Store { return newMemory(time.Now) }

// NewMemoryWithClock is NewMemory with an injectable clock (tests).
func NewMemoryWithClock(now func() time.Time) Store { return newMemory(now) }

// NewDynamoDB returns a DynamoDB-backed store using the default AWS
// credential chain (EKS Pod Identity, IRSA, env...).
func NewDynamoDB(ctx context.Context, cfg DynamoDBConfig) (Store, error) {
	return newDynamoDB(ctx, cfg)
}
