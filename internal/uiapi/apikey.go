package uiapi

import "time"

// API key states.
const (
	APIKeyActive  = "active"
	APIKeyExpired = "expired"
	APIKeyRevoked = "revoked"
)

// APIKey is a gate-issued API key as listed: never the key itself.
type APIKey struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description,omitempty"`
	Team         string     `json:"team"`
	Role         string     `json:"role"`
	Status       string     `json:"status"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	// ACMEDomains are the domains of the acme-dns registrations of the key.
	ACMEDomains []string `json:"acme_domains"`
	// ACMEDNS are the acme-dns registrations of the key.
	ACMEDNS       []ACMEDNSRegistration `json:"acme_dns"`
	CreatedAt     time.Time             `json:"created_at"`
	CreatedBy     string                `json:"created_by"`
	CreatedByName string                `json:"created_by_name,omitempty"`
	RotatedAt     *time.Time            `json:"rotated_at,omitempty"`
	// PreviousKeyExpiresAt is the end of the overlap of the last rotation:
	// the previous key is accepted until then.
	PreviousKeyExpiresAt *time.Time `json:"previous_key_expires_at,omitempty"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
	RevokedBy            string     `json:"revoked_by,omitempty"`
	LastUsedAt           *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP           string     `json:"last_used_ip,omitempty"`
}

// ACMEDNSRegistration maps an acme-dns subdomain of a key to the domain
// whose _acme-challenge TXT RRset /update writes.
type ACMEDNSRegistration struct {
	Subdomain string   `json:"subdomain"`
	Domain    string   `json:"domain"`
	AllowFrom []string `json:"allowfrom"`
}

// IssuedAPIKey answers a creation or a rotation: the only time the key is
// returned.
type IssuedAPIKey struct {
	APIKey
	Key string `json:"key"`
	// ACMEDNSAccounts are the acme-dns accounts of the key by domain: the
	// storage file of the certbot acme-dns hook, the registration file of
	// certbot-dns-acmedns and the cert-manager acmeDNS secret.
	ACMEDNSAccounts map[string]ACMEDNSAccount `json:"acme_dns_accounts"`
}

// ACMEDNSAccount is an acme-dns account (/register answer).
type ACMEDNSAccount struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	FullDomain string   `json:"fulldomain"`
	SubDomain  string   `json:"subdomain"`
	AllowFrom  []string `json:"allowfrom"`
}

// APIKeyRequest creates (POST) or replaces the mutable fields (PUT) of a
// key. Team and role cannot change: on PUT they must be empty or equal.
type APIKeyRequest struct {
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Team         string     `json:"team"`
	Role         string     `json:"role"`
	ExpiresAt    *time.Time `json:"expires_at"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	ACMEDomains  []string   `json:"acme_domains"`
}

// APIKeyRotate rotates a key; the previous key stays valid during Overlap
// (a Go duration, default 24h, at most 720h, "0s" to stop it at once).
type APIKeyRotate struct {
	Overlap string `json:"overlap"`
}
