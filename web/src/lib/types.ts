// Mirrors internal/uiapi/types.go (the JSON contract of /api/v1).

export type Category = 'human' | 'pipeline' | 'key' | 'system';
export type Status = 'managed' | 'tainted' | 'pending' | 'foreign' | 'missing';
export type Decision = 'allow' | 'deny' | 'error';
export type ChangeOp = 'create' | 'update' | 'delete' | 'adopt' | 'taint' | 'expire' | 'transfer';

export interface Me {
  subject: string;
  name: string;
  category: Category;
  /** Address the issuer vouches for; absent when none. */
  email?: string;
  roles: string[];
  teams: string[];
  groups?: string[];
  permissions?: Permission[];
  /** Team the caller writes for unless it selects another of its teams. */
  default_team?: string;
}

/** One effective rule of one of the subject's roles. */
export interface Permission {
  role: string;
  zones: string[];
  /** Folder globs (EuroDNS folders): the rule also applies to the zones in these folders. */
  folders?: string[];
  /** Zones a zone selected through folders must also match (bounds of a managed or delegated rule). */
  folder_zones?: string[];
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

/** Consent of a user to an application declared at the gate (GET /api/v1/oauth/grants). */
export interface OAuthGrant {
  id: string;
  client_id: string;
  client_name: string;
  subject: string;
  subject_name?: string;
  scopes: string[];
  status: 'active' | 'expired' | 'revoked';
  created_at: string;
  consented_at: string;
  last_used_at: string;
  /** The earlier of the absolute and the idle expiry. */
  expires_at: string;
  revoked_at?: string;
  revoked_by?: string;
}

export interface OAuthGrantList {
  grants: OAuthGrant[];
  /** The caller holds gate.oauth.manage: it may list and revoke the grants of a client or a user. */
  manage: boolean;
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
  /** Folder of the zone at the provider (EuroDNS), "/" for a zone in no folder; absent without folders. */
  folder?: string;
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

/** 301 or 302 redirect, or a frame showing the URL; another value for a forward the gate cannot read. */
export type ForwardMode = '301' | '302' | 'frame' | (string & {});

/** URL forward of a host (an RRset of type URLFWD, TTL 0, no values). Title, keywords and description: frame only. */
export interface Forward {
  type: ForwardMode;
  url: string;
  title?: string;
  keywords?: string;
  description?: string;
}

/** Why the gate never writes an RRset: server_managed, routing_policy, locked, unsupported_forward, duplicate_forward, forward_record, or another provider reason. */
export type ReadOnlyReason = 'server_managed' | 'routing_policy' | 'locked' | 'unsupported_forward' | 'duplicate_forward' | 'forward_record' | (string & {});

export interface RRset {
  host: string;
  type: string;
  ttl: number;
  values: string[];
  alias?: Alias;
  /** The URL forward of the host (type URLFWD), with no values. */
  forward?: Forward;
  read_only?: ReadOnlyReason;
  /** Content hash (TTL and values, alias or forward), the precondition of a change. */
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
  /** Record sets deleted recently through the gate, still reserved for their team. */
  tombstones?: Tombstone[];
  /** Folder of the zone at the provider (EuroDNS), "/" for a zone in no folder. */
  folder?: string;
}

/** active, pending and no_forward answer HTTPS; inactive answers plain HTTP only; unsupported: the provider has no forwards. */
export type HTTPSStatus = 'active' | 'pending' | 'no_forward' | 'inactive' | 'unsupported' | 'unknown';

/** Whether the forwards of a zone answer HTTPS (an HTTPS redirect subscription at the provider). */
export interface HTTPSRedirect {
  status: HTTPSStatus;
  subscription?: string;
  expires_at?: string;
  message?: string;
}

/** GET /api/v1/zones/{zone}/forwards: the URL forwards of a zone with their ownership. */
export interface ForwardList {
  zone: string;
  /** Absent when it could not be read or the zone is not managed. */
  https?: HTTPSRedirect;
  forwards: RRset[];
}

/** Until expires_at, only this team may create or adopt the record set again; others ask for a transfer. */
export interface Tombstone {
  host: string;
  type: string;
  team: string;
  deleted_by?: Actor;
  deleted_at: string;
  expires_at: string;
}

export interface Change {
  op: ChangeOp;
  host: string;
  type: string;
  old_ttl?: number;
  old_values?: string[];
  old_alias?: Alias;
  old_forward?: Forward;
  new_ttl?: number;
  new_values?: string[];
  new_alias?: Alias;
  new_forward?: Forward;
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
  /** Provider instance id of the zone. */
  provider?: Provider;
  /** Provider snapshot taken before the write (EuroDNS). */
  snapshot_id?: string;
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
  /** A URL forward (type URLFWD): no TTL nor values. */
  forward?: Forward;
  /** Forwards only: refused (https_unavailable) unless the forwards of the zone answer HTTPS; not stored. */
  require_https?: boolean;
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
  forward?: Forward;
}

/** A change of a plan: the journal shape, or old/new objects; reason when this change alone is refused. */
export interface PlanChange {
  op: ChangeOp;
  host: string;
  type: string;
  old_ttl?: number;
  old_values?: string[];
  old_alias?: Alias;
  old_forward?: Forward;
  new_ttl?: number;
  new_values?: string[];
  new_alias?: Alias;
  new_forward?: Forward;
  old?: PlanSide | null;
  new?: PlanSide | null;
  reason?: string;
  message?: string;
  /** Content hash after an applied create or update: the expect of a propagation check. */
  new_hash?: string;
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
  /** Team the plan was made for, when one was selected. */
  team?: string;
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

/** A team declared in the teams block (members of the bindings naming it without groups or subjects). */
export interface Team {
  description?: string;
  members: { groups?: string[]; subjects?: SubjectMatcher[] };
}

export interface RecordScope {
  hosts?: string[];
  types?: string[];
}

export interface Rule {
  zones: string[];
  /** Folder globs: "/ES" the folder ES, "/ES/**" every folder below it. */
  folders?: string[];
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
  /** Teams declared besides the base ones; omitted in a proposal, the active ones are kept. */
  teams?: Record<string, Team>;
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
    folders?: string[];
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
  folders?: string[];
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
  /** Why this replica does not serve the active managed revision (its last policy refresh failed). */
  load_error?: string;
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
  /** Folder of the zone, when the matched rule applied through its folders. */
  folder?: string;
}

export interface WhoCanEntry {
  role: string;
  team: string;
  team_from?: TeamFrom;
  layer: string;
  groups?: string[];
  subjects?: SubjectMatcher[];
  virtual_keys?: string[];
  /** Granted through a folder selector of the role. */
  by_folder?: boolean;
}

export interface WhoCanResponse {
  /** Folder of the zone (EuroDNS). */
  folder?: string;
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
  | 'relative_target'
  | 'unsupported_forward'
  | 'duplicate_forward'
  | 'forward_record'
  | 'invalid_forward';

export interface AdoptCandidate {
  host: string;
  type: string;
  ttl: number;
  values: string[];
  alias?: Alias;
  forward?: Forward;
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

// Teams and ownership transfers (internal/uiapi/teams.go)

/** declared: teams block; auto: referenced, not declared; family: team_from; claim: issuer team_claim; store: owns RRsets, named nowhere. */
export type TeamKind = 'declared' | 'auto' | 'family' | 'claim' | 'store';

export interface TeamInfo {
  name: string;
  kind: TeamKind;
  layer?: 'base' | 'managed';
  description?: string;
  /** With policy.read only. */
  members?: { groups?: string[]; subjects?: SubjectMatcher[] };
  roles: string[];
  virtual_keys?: string[];
  family?: TeamFrom;
  issuer?: string;
  warning?: string;
  /** Record sets owned in the zones the caller can read. */
  rrsets: number;
}

export interface TeamList {
  strict: boolean;
  teams: TeamInfo[];
  /** Transfers and renames need another person's approval; otherwise their requester may approve them. */
  require_second_approver?: boolean;
}

export interface TeamZone {
  zone: string;
  rrsets: number;
  tombstones: number;
}

export interface TeamDetail extends TeamInfo {
  owned: TeamZone[];
  transfers: Transfer[];
  /** Rules of the team's roles: for policy.read holders and the team's members. */
  permissions?: Permission[];
}

/** applying: approved, being applied or retried by the gate (error holds the last transient error). */
export type TransferStatus = 'proposed' | 'applying' | 'applied' | 'rejected' | 'expired' | 'failed';

export interface TransferRRset {
  host: string;
  type: string;
  hash?: string;
  tombstone?: boolean;
}

export interface Transfer {
  id: string;
  kind: 'rrsets' | 'rename';
  /** Empty for a rename. */
  zone?: string;
  from_team: string;
  to_team: string;
  rrsets: TransferRRset[];
  status: TransferStatus;
  comment: string;
  requester: Actor;
  created_at: string;
  expires_at: string;
  decided_by?: Actor;
  decided_at?: string;
  decision_comment?: string;
  moved?: number;
  /** Why a failed transfer was not applied, or the last transient error of an applying one. */
  error?: string;
  can_decide: boolean;
  /** Approved by its requester (no second approver required). */
  self_approved?: boolean;
}

export interface TransferProposal {
  rrsets: RRsetRef[];
  to_team: string;
  comment: string;
  /** Approve it at once, by its requester (no second approver required). */
  apply?: boolean;
}

export interface TransferPage {
  transfers: Transfer[];
  next_cursor?: string;
}

export interface TransferQuery {
  zone?: string;
  status?: TransferStatus;
  limit?: number;
  cursor?: string;
}

// DNS propagation (GET /api/v1/zones/{zone}/rrsets/{host}/{type}/propagation, internal/propagation)

export type PropagationStatus = 'match' | 'stale' | 'missing' | 'error' | 'indeterminate';

export interface PropagationAnswer {
  kind: 'authoritative' | 'resolver';
  name: string;
  address: string;
  location?: string;
  country?: string;
  region?: string;
  status: PropagationStatus;
  values: string[];
  cnames?: string[];
  ttl_left?: number;
  rcode?: string;
  latency_ms: number;
  tcp?: boolean;
  error?: string;
  /** The resolver blocks some names by policy: its negative answers may be a filter decision. */
  filtering?: boolean;
  /** Values left out or cut. */
  truncated?: boolean;
}

export interface PropagationSummary {
  total: number;
  match: number;
  stale: number;
  missing: number;
  error: number;
  /** Alias answers that could not be tied to the target (never up to date). */
  indeterminate: number;
  /** Every server that answered has the expected content, an authoritative one at least. */
  converged: boolean;
  /** Longest TTL left among the stale and missing answers, in seconds. */
  max_ttl_left: number;
}

export interface Propagation {
  zone: string;
  host: string;
  type: string;
  name: string;
  query_type: string;
  expected: { exists: boolean; hash?: string; ttl?: number; values: string[]; alias_target?: string };
  checked_at: string;
  cached: boolean;
  summary: PropagationSummary;
  answers: PropagationAnswer[];
}
