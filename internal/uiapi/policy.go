package uiapi

import "time"

// Policy is layered:
//   - base: the YAML config file (GitOps). Issuers, UI, store, protected
//     records, policy bounds and every policy.* grant live only there.
//   - managed: an editable document stored as immutable revisions in the
//     store, merged with base at evaluation. A managed role or group cannot
//     reuse a base name, cannot grant policy.* actions, and cannot exceed the
//     bounds set in base. Activation requires approval by another policy
//     approver when policy.require_approval is true (default).
//
// Routes (all JSON, cookie session or bearer):
//
//	GET  /api/v1/policy                          -> EffectivePolicy        (policy.read)
//	GET  /api/v1/policy/revisions?status=&limit=&cursor= -> RevisionPage   (policy.read)
//	GET  /api/v1/policy/revisions/{id}           -> RevisionDetail         (policy.read)
//	POST /api/v1/policy/revisions                 ProposeRequest -> RevisionDetail (policy.propose)
//	POST /api/v1/policy/revisions/{id}/approve    DecisionRequest -> RevisionDetail (policy.approve)
//	POST /api/v1/policy/revisions/{id}/reject     DecisionRequest -> RevisionDetail (policy.approve)
//	POST /api/v1/policy/revisions/{id}/activate   -> RevisionDetail (policy.approve, or policy.propose when approval is not required)
//	POST /api/v1/policy/revisions/{id}/rollback   -> RevisionDetail: new proposal copying revision {id} (policy.propose)
//	GET  /api/v1/policy/revisions/{id}/export     -> YAML of the managed document (policy.read)
//	POST /api/v1/policy/explain                   ExplainRequest -> ExplainResponse (policy.read)
//	GET  /api/v1/policy/who-can?zone=&host=&type=&action= -> WhoCanResponse (policy.read)
//	POST /api/v1/policy/virtual-keys/generate     -> GeneratedKey (policy.propose); the key is shown once, only its hash goes in a proposal
//
// Every POST requires the X-Gate-CSRF header equal to the gate_csrf cookie
// and a same-origin Origin header. Mutations by humans require a recent login
// (policy.edit_max_age) and, if configured, an MFA claim (policy.require_amr);
// otherwise 403 {"reason":"reauth_required"} and the UI redirects to
// /auth/login?reauth=1&return_to=...

// Revision statuses.
const (
	RevisionProposed   = "proposed"
	RevisionApproved   = "approved"
	RevisionRejected   = "rejected"
	RevisionActive     = "active"
	RevisionSuperseded = "superseded"
)

// Meta actions (granted only by base bindings).
const (
	ActionPolicyRead    = "policy.read"
	ActionPolicyPropose = "policy.propose"
	ActionPolicyApprove = "policy.approve"
)

// SubjectMatcher matches tokens of an issuer whose claims all match (array
// claims match when one element matches the glob).
type SubjectMatcher struct {
	Issuer string              `json:"issuer"`
	Claims map[string][]string `json:"claims,omitempty"`
}

// Group is a named set of subject matchers (e.g. an Entra app role or group
// object id, a GitHub repository, explicit users).
type Group struct {
	Description string           `json:"description,omitempty"`
	Members     []SubjectMatcher `json:"members"`
}

// RecordScope restricts a rule to hosts and types.
type RecordScope struct {
	Hosts []string `json:"hosts,omitempty"`
	Types []string `json:"types,omitempty"`
}

// Rule grants actions on zones.
type Rule struct {
	Zones   []string     `json:"zones"`
	Actions []string     `json:"actions"`
	Records *RecordScope `json:"records,omitempty"`
}

// Role is a named set of rules.
type Role struct {
	Description          string `json:"description,omitempty"`
	Rules                []Rule `json:"rules"`
	RebaseOnSave         bool   `json:"rebase_on_save,omitempty"`
	EphemeralTTL         string `json:"ephemeral_ttl,omitempty"` // Go duration
	MaxChangesPerRequest int    `json:"max_changes_per_request,omitempty"`
}

// Binding grants a role, acting for a team, to groups and/or subjects.
type Binding struct {
	Role     string           `json:"role"`
	Team     string           `json:"team"`
	Groups   []string         `json:"groups,omitempty"`
	Subjects []SubjectMatcher `json:"subjects,omitempty"`
}

// VirtualKey as stored in a policy (never the key itself).
type VirtualKey struct {
	ID           string     `json:"id"`
	AppID        string     `json:"app_id"`
	KeySHA256    string     `json:"key_sha256"`
	Description  string     `json:"description,omitempty"`
	Roles        []string   `json:"roles"`
	Teams        []string   `json:"teams"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	AllowedCIDRs []string   `json:"allowed_cidrs,omitempty"`
}

// PolicyDocument is the managed (editable) layer.
type PolicyDocument struct {
	Groups      map[string]Group `json:"groups"`
	Roles       map[string]Role  `json:"roles"`
	Bindings    []Binding        `json:"bindings"`
	VirtualKeys []VirtualKey     `json:"virtual_keys"`
}

// Issuer as shown in the UI (no secrets).
type Issuer struct {
	Name          string              `json:"name"`
	Issuer        string              `json:"issuer"`
	Audiences     []string            `json:"audiences"`
	BoundClaims   map[string][]string `json:"bound_claims,omitempty"`
	SubjectClaim  string              `json:"subject_claim,omitempty"`
	Category      string              `json:"category,omitempty"`
	CategoryClaim string              `json:"category_claim,omitempty"`
}

// Protected record selector.
type Protected struct {
	Zones []string `json:"zones"`
	Hosts []string `json:"hosts"`
	Types []string `json:"types"`
}

// Bounds limit what the managed layer may grant.
type Bounds struct {
	Zones   []string `json:"zones"`   // globs a managed rule may target
	Actions []string `json:"actions"` // actions a managed rule may grant
}

// BaseLayer is the read-only file layer.
type BaseLayer struct {
	ConfigHash string         `json:"config_hash"` // sha256 of the loaded file
	LoadedAt   time.Time      `json:"loaded_at"`
	Zones      []string       `json:"zones"`
	Issuers    []Issuer       `json:"issuers"`
	Protected  []Protected    `json:"protected"`
	Bounds     Bounds         `json:"bounds"`
	Document   PolicyDocument `json:"document"` // base groups, roles, bindings, keys
}

// PolicySettings mirrors the policy section of the config.
type PolicySettings struct {
	Editable        bool     `json:"editable"`
	RequireApproval bool     `json:"require_approval"`
	EditMaxAge      string   `json:"edit_max_age"`
	RequireAMR      []string `json:"require_amr,omitempty"`
}

// MyPolicyRights tells the UI which controls to show.
type MyPolicyRights struct {
	CanPropose bool `json:"can_propose"`
	CanApprove bool `json:"can_approve"`
}

// EffectivePolicy is GET /api/v1/policy.
type EffectivePolicy struct {
	Settings PolicySettings   `json:"settings"`
	Base     BaseLayer        `json:"base"`
	Active   *RevisionSummary `json:"active,omitempty"`  // nil when no managed revision is active
	Managed  *PolicyDocument  `json:"managed,omitempty"` // document of the active revision
	Me       MyPolicyRights   `json:"me"`
}

// Approval is one decision on a revision.
type Approval struct {
	By       Actor     `json:"by"`
	At       time.Time `json:"at"`
	Decision string    `json:"decision"` // approve | reject
	Comment  string    `json:"comment,omitempty"`
}

// RevisionSummary is a revision without its document.
type RevisionSummary struct {
	ID          string     `json:"id"`
	ParentID    string     `json:"parent_id,omitempty"`
	Status      string     `json:"status"`
	Author      Actor      `json:"author"`
	CreatedAt   time.Time  `json:"created_at"`
	Comment     string     `json:"comment,omitempty"`
	Approvals   []Approval `json:"approvals,omitempty"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ActivatedBy *Actor     `json:"activated_by,omitempty"`
}

// RevisionPage lists revisions, newest first.
type RevisionPage struct {
	Revisions  []RevisionSummary `json:"revisions"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// ImpactItem is one permission gained or lost by a subject selector.
type ImpactItem struct {
	Kind    string   `json:"kind"` // gain | loss | warning
	Who     string   `json:"who"`  // group name, binding team, matcher text or virtual key id
	Role    string   `json:"role,omitempty"`
	Zones   []string `json:"zones,omitempty"`
	Actions []string `json:"actions,omitempty"`
	Message string   `json:"message"` // human-readable, e.g. "team web loses write on owned RRsets (12)"
}

// RevisionDetail is a revision with its document, diff and impact.
type RevisionDetail struct {
	RevisionSummary
	Document PolicyDocument `json:"document"`
	// DiffYAML is a unified diff of the managed document against the
	// revision's parent (or the active one), in YAML.
	DiffYAML string       `json:"diff_yaml"`
	Impact   []ImpactItem `json:"impact"`
	Stale    bool         `json:"stale"` // parent is no longer the active revision
}

// ProposeRequest creates a proposed revision.
type ProposeRequest struct {
	ParentID string         `json:"parent_id"` // active revision id the edit is based on ("" if none)
	Document PolicyDocument `json:"document"`
	Comment  string         `json:"comment"`
}

// ValidationError is returned with 400 {"reason":"invalid_policy","errors":[...]}.
type ValidationError struct {
	Path    string `json:"path"` // e.g. "roles.web-writer.rules[0].actions[1]"
	Message string `json:"message"`
}

// DecisionRequest approves or rejects.
type DecisionRequest struct {
	Comment string `json:"comment"`
}

// ExplainRequest simulates a decision.
type ExplainRequest struct {
	Subject SubjectMatcher `json:"subject"` // issuer + concrete claim values
	Action  string         `json:"action"`
	Zone    string         `json:"zone"`
	Host    string         `json:"host,omitempty"`
	Type    string         `json:"type,omitempty"`
	// RevisionID evaluates a proposed revision instead of the active policy.
	RevisionID string `json:"revision_id,omitempty"`
}

// ExplainResponse is the decision with its reasons.
type ExplainResponse struct {
	Allowed  bool     `json:"allowed"`
	Groups   []string `json:"groups"`            // groups the subject belongs to
	Bindings []string `json:"bindings"`          // "role@team" that apply
	Matched  string   `json:"matched,omitempty"` // rule that granted, e.g. "roles.web-writer.rules[0]"
	Denied   string   `json:"denied,omitempty"`  // e.g. "protected: zones=* hosts=@ types=NS"
	Layer    string   `json:"layer,omitempty"`   // base | managed
}

// WhoCanEntry is one grant on a record.
type WhoCanEntry struct {
	Role     string           `json:"role"`
	Team     string           `json:"team"`
	Layer    string           `json:"layer"`
	Groups   []string         `json:"groups,omitempty"`
	Subjects []SubjectMatcher `json:"subjects,omitempty"`
	Keys     []string         `json:"virtual_keys,omitempty"`
}

// WhoCanResponse lists who may perform an action on an RRset.
type WhoCanResponse struct {
	Protected bool          `json:"protected"`
	Entries   []WhoCanEntry `json:"entries"`
}

// GeneratedKey is returned once by virtual-keys/generate.
type GeneratedKey struct {
	AppID     string `json:"app_id"`
	Key       string `json:"key"`
	KeySHA256 string `json:"key_sha256"`
}
