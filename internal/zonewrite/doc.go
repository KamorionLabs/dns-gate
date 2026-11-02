// Package zonewrite performs every DNS zone write on behalf of a subject,
// enforcing RBAC per RRset and ownership (only RRsets created or adopted by
// the gate, owned by one of the subject's teams, and unchanged since the last
// gate write, may be modified or deleted).
//
// EuroDNS behaviours handled here (observed against the live API):
//   - SOA and locked records (apex SOA and NS) are managed by EuroDNS; the SOA
//     serial changes on every write. They never take part in deltas, content
//     hashes or drift detection, cannot be written, and a client sending a
//     stale SOA is not refused for it.
//   - CNAME, MX, NS, SRV, PTR and APEX targets without an ending dot are
//     stored relative to the zone (EuroDNS only warns at check time): new
//     values without the dot are refused. An RRset that already holds such
//     a value raises a check warning, so with CheckOnWrite it cannot be
//     changed until the value is fixed.
//   - With CheckOnWrite, every validation error refuses the write, and so do
//     warnings on an RRset the request changes.
//   - EuroDNS keeps only the last 5 zone snapshots. The snapshot id recorded
//     in the audit is a convenience that soon disappears; the audit event
//     itself carries the old and new values of every changed RRset, which is
//     what a rollback relies on.
package zonewrite
