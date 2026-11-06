package audit

import (
	"net/netip"
	"strings"
	"time"

	"github.com/KamorionLabs/dns-gate/internal/version"
)

// Versions of the standard schemas the ecs and ocsf formats follow.
const (
	ECSVersion  = "8.11.0"
	OCSFVersion = "1.3.0"
)

// Activity is the nature of an audited action, shared by the ECS and OCSF
// mappings.
type Activity string

// Activities.
const (
	ActivityRead   Activity = "read"
	ActivityCreate Activity = "create"
	ActivityUpdate Activity = "update"
	ActivityDelete Activity = "delete"
	ActivityOther  Activity = "other"
)

// Class groups actions for the standard mappings.
type Class string

// Classes.
const (
	ClassAuthentication Class = "authentication" // credentials checked or tokens issued
	ClassAccountChange  Class = "account_change" // gate API key lifecycle
	ClassPolicy         Class = "policy"         // managed policy and delegations
	ClassDiscovery      Class = "discovery"      // zone folders found by provider discovery
	ClassAPI            Class = "api"            // DNS, ownership and every other operation
)

// Classify returns the class and activity of an event. Events without a
// subject are refused authentications.
func Classify(e Event) (Class, Activity) {
	a := strings.ToLower(e.Action)
	switch {
	case a == "apikey.authenticate", a == "token.issue", a == "gate.token.exchange":
		return ClassAuthentication, ActivityOther
	case e.Subject == "" && e.Decision == "deny":
		return ClassAuthentication, ActivityOther
	case strings.HasPrefix(a, "apikey."):
		return ClassAccountChange, activity(e)
	case strings.HasPrefix(a, "policy."):
		return ClassPolicy, activity(e)
	case strings.HasPrefix(a, "gate.zone.folder"):
		return ClassDiscovery, discoveryActivity[a]
	}
	return ClassAPI, activity(e)
}

var discoveryActivity = map[string]Activity{
	"gate.zone.folder_changed": ActivityUpdate, "gate.zone.folder_seen": ActivityCreate,
	"gate.zone.folder_gone": ActivityDelete, "gate.zone.folders_listed": ActivityRead,
}

var (
	readWords   = []string{"get", "list", "read", "search", "export", "plan", "preview", "check", "explain", "manage"}
	createWords = []string{"create", "issue", "propose", "generate", "register", "add"}
	deleteWords = []string{"delete", "revoke", "remove", "expire", "cleanup"}
)

func activity(e Event) Activity {
	words := actionWords(e.Action)
	if len(e.Changes) > 0 {
		creates, deletes := 0, 0
		for _, c := range e.Changes {
			switch c.Op {
			case "create":
				creates++
			case "delete", "expire":
				deletes++
			}
		}
		switch {
		case creates == len(e.Changes):
			return ActivityCreate
		case deletes == len(e.Changes):
			return ActivityDelete
		}
		return ActivityUpdate
	}
	switch {
	case anyWord(words, readWords):
		return ActivityRead
	case anyWord(words, deleteWords):
		return ActivityDelete
	case anyWord(words, createWords):
		return ActivityCreate
	}
	return ActivityUpdate
}

// actionWords splits an action on '.', '_', '-' and camelCase boundaries
// (operation ids of the EuroDNS API), lowercased.
func actionWords(action string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	for _, r := range action {
		switch {
		case r == '.' || r == '_' || r == '-' || r == '/':
			flush()
		case r >= 'A' && r <= 'Z':
			flush()
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func anyWord(words, set []string) bool {
	for _, w := range words {
		for _, s := range set {
			if w == s {
				return true
			}
		}
	}
	return false
}

// fqdns returns the zone and the names of the changed RRsets.
func fqdns(e Event) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSuffix(strings.ToLower(s), ".")
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(e.Zone)
	for _, c := range e.Changes {
		h := strings.TrimSuffix(strings.ToLower(c.Host), ".")
		switch {
		case h == "" || h == "@":
			add(e.Zone)
		case e.Zone == "" || h == e.Zone || strings.HasSuffix(h, "."+e.Zone):
			add(h)
		default:
			add(h + "." + e.Zone)
		}
	}
	return out
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func outcome(decision string) string {
	switch decision {
	case "allow":
		return "success"
	case "deny", "error":
		return "failure"
	}
	return "unknown"
}

// native is the part of the event kept under a product namespace by the
// standard formats.
func native(e Event) map[string]any {
	m := map[string]any{"schema_version": e.SchemaVersion, "decision": e.Decision}
	set := func(k string, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("subject_category", e.SubjectCategory)
	set("auth_method", e.AuthMethod)
	set("provider", e.Provider)
	set("snapshot_id", string(e.SnapshotID))
	set("request_id", e.RequestID)
	if len(e.Teams) > 0 {
		m["teams"] = e.Teams
	}
	if len(e.Changes) > 0 {
		m["changes"] = e.Changes
	}
	if len(e.Extra) > 0 {
		m["extra"] = e.Extra
	}
	return m
}

func message(e Event) string {
	var b strings.Builder
	b.WriteString(e.Decision)
	b.WriteString(" ")
	b.WriteString(e.Action)
	if e.Zone != "" {
		b.WriteString(" on ")
		b.WriteString(e.Zone)
	}
	who := e.SubjectName
	if who == "" {
		who = e.Subject
	}
	if who != "" {
		b.WriteString(" by ")
		b.WriteString(who)
	}
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Reason)
	}
	return b.String()
}

// ToECS maps an event to Elastic Common Schema 8.x fields. Fields without
// an ECS equivalent are kept under dns_gate.
func ToECS(e Event) map[string]any {
	class, act := Classify(e)
	ev := map[string]any{
		"id": e.EventID, "kind": "event", "action": e.Action, "outcome": outcome(e.Decision),
		"dataset": "dns_gate.audit", "provider": "dns-gate", "module": "dns_gate",
	}
	if e.Reason != "" {
		ev["reason"] = e.Reason
	}
	var cats, types []string
	switch class {
	case ClassAuthentication:
		cats, types = []string{"authentication"}, []string{"start"}
	case ClassAccountChange:
		cats, types = []string{"iam"}, []string{"user", ecsInfo(act)}
	case ClassPolicy:
		cats, types = []string{"iam", "configuration"}, []string{ecsInfo(act)}
	case ClassDiscovery:
		cats, types = []string{"configuration"}, []string{ecsInfo(act)}
	default:
		cats = []string{"api"}
		if act == ActivityRead {
			types = []string{"access"}
		} else {
			cats = append(cats, "configuration")
			types = []string{ecsChange(act)}
		}
		switch e.Decision {
		case "allow":
			types = append(types, "allowed")
		case "deny":
			types = append(types, "denied")
		}
	}
	ev["category"], ev["type"] = cats, types

	m := map[string]any{
		"type":       "audit",
		"@timestamp": e.Time.UTC().Format(time.RFC3339Nano),
		"message":    message(e),
		"ecs":        map[string]any{"version": ECSVersion},
		"event":      ev,
		"service":    map[string]any{"name": "dns-gate", "type": "dns-gate", "version": version.Version},
		"dns_gate":   native(e),
	}
	related := map[string]any{}
	if e.Subject != "" {
		u := map[string]any{"id": e.Subject}
		if e.SubjectName != "" {
			u["name"] = e.SubjectName
		}
		if len(e.Teams) == 1 {
			u["group"] = map[string]any{"name": e.Teams[0]}
		}
		m["user"] = u
		users := []string{e.Subject}
		if e.SubjectName != "" && e.SubjectName != e.Subject {
			users = append(users, e.SubjectName)
		}
		related["user"] = users
	}
	if e.SourceIP != "" && validIP(e.SourceIP) {
		m["source"] = map[string]any{"ip": e.SourceIP}
		related["ip"] = []string{e.SourceIP}
	}
	if e.UserAgent != "" {
		m["user_agent"] = map[string]any{"original": e.UserAgent}
	}
	if e.RequestID != "" {
		m["http"] = map[string]any{"request": map[string]any{"id": e.RequestID}}
	}
	if e.Zone != "" {
		m["dns"] = map[string]any{"question": map[string]any{"name": e.Zone}}
	}
	if hosts := fqdns(e); len(hosts) > 0 {
		related["hosts"] = hosts
	}
	if len(related) > 0 {
		m["related"] = related
	}
	return m
}

// ecsInfo is ecsChange for categories without "access" (iam): a read is
// "info".
func ecsInfo(a Activity) string {
	if a == ActivityRead {
		return "info"
	}
	return ecsChange(a)
}

func ecsChange(a Activity) string {
	switch a {
	case ActivityCreate:
		return "creation"
	case ActivityDelete:
		return "deletion"
	case ActivityRead:
		return "access"
	}
	return "change"
}

// OCSF classes used by the ocsf format.
const (
	OCSFAccountChange  = 3001 // Identity & Access Management: Account Change
	OCSFAuthentication = 3002 // Identity & Access Management: Authentication
	OCSFAPIActivity    = 6003 // Application Activity: API Activity
)

// ToOCSF maps an event to an OCSF 1.3 event: Authentication (3002) for
// credential checks and token issuance, Account Change (3001) for the gate
// API key lifecycle, API Activity (6003) for every other action. Fields
// without an OCSF equivalent are kept under unmapped.dns_gate.
func ToOCSF(e Event) map[string]any {
	class, act := Classify(e)
	status, statusID := "Failure", 2
	switch e.Decision {
	case "allow":
		status, statusID = "Success", 1
	case "":
		status, statusID = "Unknown", 0
	}
	sevID, sev := 1, "Informational"
	switch e.Decision {
	case "deny":
		sevID, sev = 2, "Low"
	case "error":
		sevID, sev = 3, "Medium"
	}
	m := map[string]any{
		"type":        "audit",
		"time":        e.Time.UnixMilli(),
		"message":     message(e),
		"severity_id": sevID,
		"severity":    sev,
		"status_id":   statusID,
		"status":      status,
		"metadata": map[string]any{
			"version":         OCSFVersion,
			"uid":             e.EventID,
			"correlation_uid": e.RequestID,
			"log_name":        "audit",
			"product":         map[string]any{"name": "dns-gate", "vendor_name": "KamorionLabs", "version": version.Version},
		},
		"unmapped": map[string]any{"dns_gate": native(e)},
	}
	if e.Reason != "" {
		m["status_detail"] = e.Reason
	}
	actor := map[string]any{"authorizations": []map[string]any{{"decision": e.Decision}}}
	if u := ocsfUser(e); u != nil {
		actor["user"] = u
	}
	m["actor"] = actor
	if e.SourceIP != "" && validIP(e.SourceIP) {
		m["src_endpoint"] = map[string]any{"ip": e.SourceIP}
	}
	if e.UserAgent != "" || e.RequestID != "" {
		hr := map[string]any{}
		if e.UserAgent != "" {
			hr["user_agent"] = e.UserAgent
		}
		if e.RequestID != "" {
			hr["uid"] = e.RequestID
		}
		m["http_request"] = hr
	}
	var classUID, activityID int
	var className, categoryName, activityName string
	categoryUID := 3
	switch class {
	case ClassAuthentication:
		classUID, className, categoryName = OCSFAuthentication, "Authentication", "Identity & Access Management"
		activityID, activityName = 1, "Logon"
		if e.Action == "token.issue" || e.Action == "gate.token.exchange" {
			activityID, activityName = 3, "Authentication Ticket"
		}
		user := ocsfUser(e)
		if user == nil {
			user = map[string]any{"name": "unknown", "type_id": 0, "type": "Unknown"}
		}
		m["user"] = user
		m["auth_protocol_id"], m["auth_protocol"] = 99, authProtocol(e.AuthMethod)
		m["service"] = map[string]any{"name": "dns-gate"}
	case ClassAccountChange:
		classUID, className, categoryName = OCSFAccountChange, "Account Change", "Identity & Access Management"
		switch act {
		case ActivityCreate:
			activityID, activityName = 1, "Create"
		case ActivityDelete:
			activityID, activityName = 6, "Delete"
		default:
			activityID, activityName = 99, "Other"
		}
		m["user"] = keyAccount(e)
	default:
		classUID, className, categoryUID, categoryName = OCSFAPIActivity, "API Activity", 6, "Application Activity"
		switch act {
		case ActivityCreate:
			activityID, activityName = 1, "Create"
		case ActivityRead:
			activityID, activityName = 2, "Read"
		case ActivityUpdate:
			activityID, activityName = 3, "Update"
		case ActivityDelete:
			activityID, activityName = 4, "Delete"
		default:
			activityID, activityName = 99, "Other"
		}
		api := map[string]any{"operation": e.Action, "service": map[string]any{"name": "dns-gate"}}
		if e.RequestID != "" {
			api["request"] = map[string]any{"uid": e.RequestID}
		}
		m["api"] = api
		provider := e.Provider
		if provider == "" {
			provider = "dns-gate"
		}
		m["cloud"] = map[string]any{"provider": provider}
		if res := ocsfResources(e); len(res) > 0 {
			m["resources"] = res
		}
	}
	m["class_uid"], m["class_name"] = classUID, className
	m["category_uid"], m["category_name"] = categoryUID, categoryName
	m["activity_id"], m["activity_name"] = activityID, activityName
	m["type_uid"], m["type_name"] = classUID*100+activityID, className+": "+activityName
	return m
}

func authProtocol(method string) string {
	if method == "" {
		return "Unknown"
	}
	return method
}

func ocsfUser(e Event) map[string]any {
	if e.Subject == "" {
		return nil
	}
	u := map[string]any{"uid": e.Subject}
	if e.SubjectName != "" {
		u["name"] = e.SubjectName
	}
	switch e.SubjectCategory {
	case "human":
		u["type_id"], u["type"] = 1, "User"
	case "system":
		u["type_id"], u["type"] = 3, "System"
	case "":
		u["type_id"], u["type"] = 0, "Unknown"
	default:
		u["type_id"], u["type"] = 99, e.SubjectCategory
	}
	if len(e.Teams) > 0 {
		groups := make([]map[string]any, 0, len(e.Teams))
		for _, t := range e.Teams {
			groups = append(groups, map[string]any{"name": t})
		}
		u["groups"] = groups
	}
	return u
}

// keyAccount is the gate API key an Account Change event is about.
func keyAccount(e Event) map[string]any {
	u := map[string]any{"type_id": 99, "type": "api-key"}
	for _, k := range []string{"key_id", "id", "api_key_id"} {
		if v, ok := e.Extra[k].(string); ok && v != "" {
			u["uid"] = v
			break
		}
	}
	for _, k := range []string{"key_name", "name"} {
		if v, ok := e.Extra[k].(string); ok && v != "" {
			u["name"] = v
			break
		}
	}
	if _, ok := u["uid"]; !ok {
		u["name"] = "unknown"
	}
	return u
}

func ocsfResources(e Event) []map[string]any {
	var out []map[string]any
	if e.Zone != "" {
		out = append(out, map[string]any{"type": "dns_zone", "name": e.Zone})
	}
	for _, h := range fqdns(e) {
		if h != e.Zone {
			out = append(out, map[string]any{"type": "dns_record", "name": h})
		}
	}
	return out
}
