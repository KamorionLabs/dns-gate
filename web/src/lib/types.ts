// Mirrors internal/uiapi/types.go (the read-only JSON contract of /api/v1).

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

/** GET /api/v1/connect: what a client needs to reach the gate. */
export interface Connect {
  base_url: string;
  mcp: { enabled: boolean; url: string; allow_writes: boolean };
  issuer?: { url: string; kind: 'entra' | 'oidc'; tenant_id?: string };
  client_id?: string;
  cli_scope?: string;
  /** Download of the Claude Desktop extension; empty without MCP or UI login. */
  claude_desktop_extension_url: string;
}

export interface ZoneSummary {
  zone: string;
  rrsets: number;
  managed: number;
  tainted: number;
  pending: number;
  foreign: number;
  last_synced_at?: string;
  last_write_at?: string;
}

export interface Actor {
  subject: string;
  name: string;
  category: Category;
}

export interface RRset {
  host: string;
  type: string;
  ttl: number;
  values: string[];
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
  last_synced_at?: string;
  rrsets: RRset[];
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

export interface Binding {
  role: string;
  team: string;
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
  groups: Record<string, Group>;
  roles: Record<string, Role>;
  bindings: Binding[];
  virtual_keys: VirtualKey[];
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

export interface BaseLayer {
  config_hash: string;
  loaded_at: string;
  zones: string[];
  issuers: Issuer[];
  protected: Protected[];
  bounds: Bounds;
  document: PolicyDocument;
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
