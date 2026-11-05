// Package store persists RRset ownership, zone versions, zone locks and the
// audit log.
//
// Backends:
//
//	memory    tests and demos only; state is lost on restart
//	sqlite    one gate replica without any cloud dependency (pure Go driver,
//	          WAL, single writer connection); needs a persistent volume and
//	          replicas=1, never a shared or network file system
//	postgres  several replicas, portable (any managed or self-hosted PostgreSQL)
//	dynamodb  several replicas on AWS, no database to operate
//
// The SQL backends share one database/sql implementation: embedded,
// versioned migrations (migrations/<dialect>, table schema_migrations) are
// applied at startup in a single transaction (serialized across replicas on
// PostgreSQL by a transaction-scoped advisory lock). Optimistic versions use
// UPDATE ... WHERE version = ?, zone leases a conditional upsert on
// expires_at (no session advisory locks, which do not survive a connection
// pool). Timestamps are unix microseconds, UTC. Audit events older than the
// retention are purged by AppendAudit at most once per hour per process
// (PurgeAudit can also be called directly).
//
// Policy revisions are immutable documents: UpdateRevision only changes the
// status, approvals and activation fields, and only Activate moves a
// revision to active (the previous one to superseded), atomically with the
// active pointer (SQL transaction, DynamoDB TransactWriteItems).
//
// DynamoDB single-table layout (on-demand billing recommended):
//
//	pk (S, partition key)   sk (S, sort key)         item
//	ZONE#<zone>             RRSET#<host>#<type>      one ownership entry
//	ZONE#<zone>             META                     zone_version (N)
//	ZONE#<zone>             LOCK                     holder (S), lease_expires (N, unix ms)
//	AUDIT#<zone>            <time>#<request id>      event (S, JSON)
//	AUDIT#_global           <time>#<request id>      zone-less events
//	AUDIT#_all              <time>#<request id>      copy of every event (cross-zone queries)
//	POLICY                  REV#<id>                 one policy revision (document as binary)
//	POLICY                  ACTIVE                   revision_id of the active revision
//	PLAN#<id>               PLAN                     one RRset plan (subject, zone, changes as JSON, zone_version, expires_at)
//
// Ownership attributes: owner, created_by, created_at, updated_at,
// request_id, content_hash, pending_hash, state, adopted, expires_at
// (RFC 3339, ephemeral RRsets), version (N, optimistic concurrency).
//
// Enable DynamoDB TTL on the attribute "ttl" (N, unix seconds). LOCK items
// carry it as a cleanup of abandoned leases, audit items for retention
// (DynamoDBConfig.AuditRetention, default 400 days), plan items for expiry
// (TakePlan also checks expires_at, the TTL deletion being lazy). Ephemeral ownership
// entries never carry it: the gate must delete the upstream records before
// the entry disappears.
//
// RRset plans are taken once: a conditional delete on the subject (SQL
// DELETE ... RETURNING, DynamoDB DeleteItem with ReturnValues ALL_OLD), so
// that one plan is never applied twice, even by two gate instances. GCPlans
// purges expired plans on the SQL backends; call it from a periodic task.
//
// Put semantics: Version 0 creates (fails with ErrConflict if the entry
// exists); any other Version must match the stored one. On success the
// stored Version is the given Version + 1.
package store
