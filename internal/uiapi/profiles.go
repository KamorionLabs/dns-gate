package uiapi

// ZoneProfileList is the listing of the zone profiles of a EuroDNS
// provider: account-wide templates applied to domains on arrival, served
// under /api/v1/providers/{provider}/zone-profiles:
//
//	GET    .../zone-profiles          ZoneProfileList
//	POST   .../zone-profiles          profile -> profile with its id (201)
//	POST   .../zone-profiles/check    profile -> profile with its report
//	GET    .../zone-profiles/{id}     profile
//	PUT    .../zone-profiles/{id}     profile -> profile
//	DELETE .../zone-profiles/{id}     204
//
// Profiles have the EuroDNS ZoneProfilePage shape (name, records,
// urlForwards, mailForwards, report). Every operation requires
// dns.zone.profile on every zone ("*").
type ZoneProfileList struct {
	Provider string               `json:"provider"`
	Profiles []ZoneProfileSummary `json:"profiles"`
}

// ZoneProfileSummary identifies a zone profile.
type ZoneProfileSummary struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ZoneProfileRecord is a record of a zone profile; the host is relative to
// the domain the profile is applied to ("@" is the apex).
type ZoneProfileRecord struct {
	Type  string `json:"type" jsonschema:"record type, e.g. A, CNAME, MX, TXT"`
	Host  string `json:"host" jsonschema:"host relative to the domain, @ for the apex"`
	TTL   int    `json:"ttl" jsonschema:"EuroDNS TTL: 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400, 172800, 432000 or 604800"`
	RData string `json:"rdata" jsonschema:"record data; targets fully qualified with a trailing dot"`
}
