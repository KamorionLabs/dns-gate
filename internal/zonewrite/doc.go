// Package zonewrite performs every DNS zone write on behalf of a subject,
// enforcing RBAC per RRset and ownership (only RRsets created or adopted by
// the gate, owned by one of the subject's teams, and unchanged since the last
// gate write, may be modified or deleted).
//
// The engine works on the provider-neutral model (package dns) and resolves
// the provider of each zone (package provider). Behaviours common to every
// provider:
//   - Read-only RRsets (dns.RRset.ReadOnly: SOA and locked records at
//     EuroDNS, routing policies at Route53...) and any SOA are never written
//     nor adopted.
//   - Desired RRsets go through provider.Normalize, so that the content hash
//     stored at write time matches the RRset read back.
//   - Writes are serialized per zone by an in-process semaphore and a store
//     lease; providers without atomic batches are fine under that lock, an
//     interrupted batch leaves pending claims settled against the next read.
//   - With CheckOnWrite, a provider with a server-side dry run
//     (provider.Checker) refuses the write on any blocking problem.
//   - The audit event of a write carries the old and new values of every
//     changed RRset, which is what a rollback relies on; the provider
//     snapshot id (provider.Snapshotter) is a convenience.
package zonewrite
