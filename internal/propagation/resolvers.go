package propagation

// Regions of the default resolvers. Region is free text in the
// configuration; these are the ones the default list uses.
const (
	RegionAnycast      = "anycast"
	RegionEurope       = "europe"
	RegionNorthAmerica = "north-america"
	RegionAsia         = "asia"
)

// Resolver is a public recursive resolver queried by a check.
type Resolver struct {
	// Name is the service and its operator, e.g. "Cloudflare".
	Name string `json:"name"`
	// Address is an IP address, with an optional port (53 by default).
	Address string `json:"address"`
	// Location is where the answer comes from: a city, a country, or
	// "Anycast" for a resolver answering from its site nearest to the gate.
	Location string `json:"location,omitempty"`
	// Country is the ISO 3166 code of the location, or of the operator for
	// an anycast resolver.
	Country string `json:"country,omitempty"`
	// Region groups resolvers in the UI.
	Region string `json:"region,omitempty"`
}

// DefaultResolvers are documented open resolvers without a configuration
// of their own: unfiltered services where the operator offers one, IPv4
// addresses (AWS Lambda functions outside a VPC have no IPv6 egress).
// Anycast resolvers answer from their site nearest to the gate, so they show
// the caches the gate sees, not the ones of a distant country; the
// resolvers with a fixed location give the regional view.
var DefaultResolvers = []Resolver{
	{Name: "Cloudflare", Address: "1.1.1.1", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "Google Public DNS", Address: "8.8.8.8", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "Quad9", Address: "9.9.9.9", Location: "Anycast", Country: "CH", Region: RegionAnycast},
	{Name: "OpenDNS (Cisco)", Address: "208.67.222.222", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "AdGuard DNS (unfiltered)", Address: "94.140.14.140", Location: "Anycast", Country: "CY", Region: RegionAnycast},
	{Name: "Control D (unfiltered)", Address: "76.76.2.0", Location: "Anycast", Country: "CA", Region: RegionAnycast},
	{Name: "CleanBrowsing (security)", Address: "185.228.168.9", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "UltraDNS Public", Address: "64.6.64.6", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "NextDNS", Address: "45.90.28.0", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "DNS.SB", Address: "185.222.222.222", Location: "Anycast", Country: "DE", Region: RegionAnycast},
	{Name: "Hurricane Electric", Address: "74.82.42.42", Location: "Anycast", Country: "US", Region: RegionAnycast},
	{Name: "DNS4EU (unfiltered)", Address: "86.54.11.100", Location: "European Union", Country: "EU", Region: RegionEurope},
	{Name: "FDN", Address: "80.67.169.12", Location: "Paris", Country: "FR", Region: RegionEurope},
	{Name: "Yandex DNS", Address: "77.88.8.8", Location: "Moscow", Country: "RU", Region: RegionEurope},
	{Name: "CIRA Canadian Shield (private)", Address: "149.112.121.10", Location: "Canada", Country: "CA", Region: RegionNorthAmerica},
	{Name: "AliDNS (Alibaba)", Address: "223.5.5.5", Location: "Hangzhou", Country: "CN", Region: RegionAsia},
	{Name: "DNSPod (Tencent)", Address: "119.29.29.29", Location: "Shenzhen", Country: "CN", Region: RegionAsia},
	{Name: "114DNS", Address: "114.114.114.114", Location: "Nanjing", Country: "CN", Region: RegionAsia},
	{Name: "Quad101 (TWNIC)", Address: "101.101.101.101", Location: "Taipei", Country: "TW", Region: RegionAsia},
}
