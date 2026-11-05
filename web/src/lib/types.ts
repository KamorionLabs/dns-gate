// Mirrors internal/uiapi/types.go (the JSON contract of /api/v1).

export type Category = 'human' | 'pipeline' | 'key' | 'system';
export type Status = 'managed' | 'tainted' | 'pending' | 'foreign' | 'missing';
export type Decision = 'allow' | 'deny' | 'error';
export type ChangeOp = 'create' | 'update' | 'delete' | 'adopt' | 'taint' | 'expire';

export interface Me {
  subject: string;
  name: string;
  category: Category;
  roles: string[];
  teams: string[];
  groups?: string[];
  permissions?: Permission[];
}

/** One effective rule of one of the subject's roles. */
export interface Permission {
  role: string;
  zones: string[];
  actions: string[];
  hosts: string[]; // empty: the whole zone
  types: string[]; // empty: any type
}

/** GET /.well-known/dns-gate: version and features, unauthenticated. */
export interface GateInfo {
  version: string;
  features: string[];
}

/** GET /api/v1/connect: what a client needs to reach the gate. */
export interface Connect {
  base_url: string;
  mcp: { enabled: boolean; url: string; allow_writes: boolean };
  /** UI login issuer; for SAML, url is the gate issuer, if any. */
  issuer?: { url: string; kind: 'entra' | 'oidc' | 'saml'; tenant_id?: string };
  client_id?: string;
  cli_scope?: string;
  /** Download of the Claude Desktop extension; empty without MCP or UI login. */
  claude_desktop_extension_url: string;
  /** POST here (session, CSRF) for a gate token; absent without a gate issuer. */
  tokens_url?: string;
}

/** POST /api/v1/tokens: a gate-issued token of the UI session, for curl and Terraform. */
export interface IssuedToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at: string;
  issuer: string;
}

/** DNS provider of a zone, as the gate names it ("eurodns", "route53"). */
export type Provider = string;

export interface ZoneSummary {
  zone: string;
  provider?: Provider;
  rrsets: number;
  managed: number;
  tainted: number;
  pending: number;
  foreign: number;
  last_synced_at?: string;
  last_write_at?: string;
  /** Zone found at the DNS provider but not managed by the gate: read-only, counts are 0 until it was read once. */
  unmanaged?: boolean;
}

export interface Actor {
  subject: string;
  name: string;
  category: Category;
}

/** Provider alias target (Route53 alias records): an RRset with an alias has no values. */
export interface Alias {
  target: string;
  hosted_zone_id: string;
  evaluate_target_health: boolean;
}

/** Why the gate never writes an RRset: server_managed, routing_policy, locked, or another provider reason. */
export type ReadOnlyReason = 'server_managed' | 'routing_policy' | 'locked' | (string & {});

export interface RRset {
  host: string;
  type: string;
  ttl: number;
  values: string[];
  alias?: Alias;
  read_only?: ReadOnlyReason;
  /** Content hash (TTL and values), the precondition of a change. */
  hash?: string;
  status: Status;
  protected: boolean;
  owner?: string;
  created_by?: Actor;
  created_at?: string;
  updated_by?: Actor;
  updated_at?: string;
  adopted: boolean;
  expires_at?: string;
  last_request_id?: string;
}

export interface ZoneInventory {
  zone: string;
  provider?: Provider;
  last_synced_at?: string;
  rrsets: RRset[];
  /** Discovered but not managed: every RRset is foreign, no write nor adoption. */
  unmanaged?: boolean;
}

export interface Change {
  op: ChangeOp;
  host: string;
  type: string;
  old_ttl?: number;
  old_values?: string[];
  new_ttl?: number;
  new_values?: string[];
}

export interface AuditEntry {
  time: string;
  request_id: string;
  actor: Actor;
  teams?: string[];
  action: string;
  zone?: string;
  decision: Decision;
  reason?: string;
  changes?: Change[];
  snapshot_id?: number;
}

export interface AuditPage {
  entries: AuditEntry[];
  next_cursor?: string;
}

export interface AuditQuery {
  zone?: string;
  host?: string;
  type?: string;
  subject?: string;
  category?: string;
  decision?: string;
  since?: string;
  until?: string;
  limit?: number;
  cursor?: string;
}

// DNS writes (POST /api/v1/zones/{zone}/plan and /apply)

/** Desired state of one RRset: values (or alias), or delete. */
export interface RRsetChange {
  host: string;
  type: string;
  ttl?: number;
  values?: string[];
  alias?: Alias;
  delete?: boolean;
  /** The RRset must still have this content hash upstream. */
  expected_hash?: string;
  /** The RRset must not exist yet. */
  must_not_exist?: boolean;
}

/** One side of a planned change, when the gate sends it as an object. */
export interface PlanSide {
  ttl?: number;
  values?: string[];
  alias?: Alias;
}

/** A change of a plan: the journal shape, or old/new objects; reason when this change alone is refused. */
export interface PlanChange {
  op: ChangeOp;
  host: string;
  type: string;
  old_ttl?: number;
  old_values?: string[];
  new_ttl?: number;
  new_values?: string[];
  old?: PlanSide | null;
  new?: PlanSide | null;
  reason?: string;
  message?: string;
}

export interface PlanResult {
  zone: string;
  allowed: boolean;
  reason?: string;
  message?: string;
  changes: PlanChange[];
  zone_version?: number;
  plan_id?: string;
  request_id?: string;
}

// Policy (internal/uiapi/policy.go)

export type RevisionStatus = 'proposed' | 'approved' | 'rejected' | 'active' | 'superseded';

export interface SubjectMatcher {
  issuer: string;
  claims?: Record<string, string[]>;
}

export interface Group {
  description?: string;
  members: SubjectMatcher[];
}

export interface RecordScope {
  hosts?: string[];
  types?: string[];
}

export interface Rule {
  zones: string[];
  actions: string[];
  records?: RecordScope;
}

export interface Role {
  description?: string;
  rules: Rule[];
  rebase_on_save?: boolean;
  ephemeral_ttl?: string;
  max_changes_per_request?: number;
}

/** Owner team derived from a claim: prefix + lowercased capture of the regex (one group, anchored). */
export interface TeamFrom {
  claim: string;
  regex: string;
  prefix?: string;
}

export interface Binding {
  role: string;
  /** "" when team_from is set. */
  team: string;
  team_from?: TeamFrom;
  groups?: string[];
  subjects?: SubjectMatcher[];
}

export interface VirtualKey {
  id: string;
  app_id: string;
  key_sha256: string;
  description?: string;
  roles: string[];
  teams: string[];
  expires_at?: string;
  allowed_cidrs?: string[];
}

export interface PolicyDocument {
  /** Zones the managed layer brings under management, merged with the base zones. */
  zones?: string[];
  groups: Record<string, Group>;
  roles: Record<string, Role>;
  bindings: Binding[];
  virtual_keys: VirtualKey[];
  /** Roles and bindings owned by policy delegations (managed layer only, never edited here). */
  delegated?: DelegatedObjects;
}

/** Who manages a delegated object. */
export interface DelegatedOwner {
  /** policy.delegations[].name */
  delegation: string;
  /** Client label, for example "terraform". */
  managed_by?: string;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

export interface DelegatedRole extends Role {
  owner: DelegatedOwner;
}

export interface DelegatedBinding extends Binding {
  owner: DelegatedOwner;
}

export interface DelegatedObjects {
  roles?: Record<string, DelegatedRole>;
  bindings?: Record<string, DelegatedBinding>;
}

/** A policy.delegations entry of the base file. */
export interface Delegation {
  name: string;
  description?: string;
  subjects: SubjectMatcher[];
  allow: {
    zones: string[];
    actions: string[];
    records?: RecordScope;
    binding_subjects: SubjectMatcher[];
    teams: { from_subject?: TeamFrom; names?: string[] };
    roles?: string[];
    groups?: string[];
    max_objects: number;
  };
}

export interface Issuer {
  name: string;
  issuer: string;
  audiences: string[];
  bound_claims?: Record<string, string[]>;
  subject_claim?: string;
  category?: string;
  category_claim?: string;
}

export interface Protected {
  zones: string[];
  hosts: string[];
  types: string[];
}

export interface Bounds {
  zones: string[];
  actions: string[];
}

/** zones_discovery settings and state of the replica that answered. */
export interface ZonesDiscovery {
  enabled: boolean;
  include: string[];
  exclude: string[];
  refresh: string;
  loaded: boolean;
  count: number;
  last_refresh_at?: string;
  error?: string;
}

export interface BaseLayer {
  config_hash: string;
  loaded_at: string;
  zones: string[];
  zones_discovery?: ZonesDiscovery;
  issuers: Issuer[];
  protected: Protected[];
  bounds: Bounds;
  document: PolicyDocument;
  /** policy.delegations of the file. */
  delegations?: Delegation[];
}

export interface PolicySettings {
  editable: boolean;
  require_approval: boolean;
  edit_max_age: string;
  require_amr?: string[];
}

export interface MyPolicyRights {
  can_propose: boolean;
  can_approve: boolean;
}

export interface EffectivePolicy {
  settings: PolicySettings;
  base: BaseLayer;
  active?: RevisionSummary;
  managed?: PolicyDocument;
  me: MyPolicyRights;
}

export interface Approval {
  by: Actor;
  at: string;
  decision: 'approve' | 'reject';
  comment?: string;
}

export interface RevisionSummary {
  id: string;
  parent_id?: string;
  status: RevisionStatus;
  author: Actor;
  created_at: string;
  comment?: string;
  approvals?: Approval[];
  activated_at?: string;
  activated_by?: Actor;
}

export interface RevisionPage {
  revisions: RevisionSummary[];
  next_cursor?: string;
}

export interface ImpactItem {
  kind: 'gain' | 'loss' | 'warning';
  who: string;
  role?: string;
  zones?: string[];
  actions?: string[];
  message: string;
}

export interface RevisionDetail extends RevisionSummary {
  document: PolicyDocument;
  diff_yaml: string;
  impact: ImpactItem[];
  stale: boolean;
}

export interface ProposeRequest {
  parent_id: string;
  document: PolicyDocument;
  comment: string;
}

export interface ValidationError {
  path: string;
  message: string;
}

export interface ExplainRequest {
  subject: SubjectMatcher;
  action: string;
  zone: string;
  host?: string;
  type?: string;
  revision_id?: string;
}

export interface ExplainResponse {
  allowed: boolean;
  groups: string[];
  bindings: string[];
  matched?: string;
  denied?: string;
  layer?: string;
}

export interface WhoCanEntry {
  role: string;
  team: string;
  team_from?: TeamFrom;
  layer: string;
  groups?: string[];
  subjects?: SubjectMatcher[];
  virtual_keys?: string[];
}

export interface WhoCanResponse {
  protected: boolean;
  entries: WhoCanEntry[];
}

export interface GeneratedKey {
  app_id: string;
  key: string;
  key_sha256: string;
}

// Adoption (internal/uiapi/adopt.go)

export interface RRsetRef {
  host: string;
  type: string;
}

export interface AdoptSelection {
  rrsets?: RRsetRef[];
  hosts?: string[];
  types?: string[];
  owner?: string;
}

export type AdoptReason =
  | 'protected'
  | 'server_managed'
  | 'owned_by_other_team'
  | 'already_owned'
  | 'forbidden'
  | 'relative_target';

export interface AdoptCandidate {
  host: string;
  type: string;
  ttl: number;
  values: string[];
  status: Status;
  adoptable: boolean;
  reason?: AdoptReason | string;
}

export interface AdoptPreview {
  zone: string;
  owner: string;
  candidates: AdoptCandidate[];
  preview_token: string;
}

export interface AdoptApply {
  rrsets: RRsetRef[];
  owner?: string;
  comment: string;
  preview_token: string;
}

export interface AdoptResult {
  zone: string;
  owner: string;
  adopted: RRsetRef[];
  request_id: string;
}

export interface TerraformQuery {
  team?: string;
  hosts?: string[];
  types?: string[];
}
