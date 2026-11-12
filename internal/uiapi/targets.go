package uiapi

// TargetResolution is how one target of an RRset resolves (resolve=true on
// list_rrsets, get_rrset and GET /api/v1/zones/{zone}/rrsets).
type TargetResolution struct {
	// Name is the target, absolute with a trailing dot.
	Name string `json:"name"`
	// Status is live, nxdomain, nodata, servfail, timeout or skipped.
	Status string `json:"status"`
	// Chain is the CNAME chain followed from the target.
	Chain []string `json:"chain,omitempty"`
	// Addresses are the A and AAAA records at the end of the chain.
	Addresses []string `json:"addresses,omitempty"`
	Resolver  string   `json:"resolver,omitempty"`
	// TakeoverRisk names the third-party service of a target that does not
	// resolve (a released CloudFront distribution, S3 bucket, Azure app…):
	// whoever claims that name there would serve the host.
	TakeoverRisk string `json:"takeover_risk,omitempty"`
	Error        string `json:"error,omitempty"`
	Cached       bool   `json:"cached,omitempty"`
}
