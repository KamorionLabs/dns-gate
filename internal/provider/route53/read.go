package route53

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

type zoneNative struct {
	hostedZoneID string
}

// ReadZone lists the record sets of the hosted zone and returns them as
// RRsets sorted by key. Each RRset keeps in Native the Route53 record sets
// it was built from ([]types.ResourceRecordSet), used for exact deletes.
// The apex NS and SOA are read-only "server_managed". Record sets with a
// routing policy (SetIdentifier), a health check or a traffic policy are
// exposed as one read-only "routing_policy" RRset per host and type, whose
// values are the union of the values and alias targets of its members and
// whose TTL is the one of its first member.
func (p *Provider) ReadZone(ctx context.Context, zone string) (*dns.Zone, error) {
	name := dns.NormalizeZone(zone)
	id, err := p.zoneID(ctx, name)
	if err != nil {
		return nil, err
	}
	sets, err := p.listRecordSets(ctx, id)
	if err != nil {
		var nsz *types.NoSuchHostedZone
		if errors.As(err, &nsz) {
			p.forget(name)
			return nil, fmt.Errorf("%w: %s (%s) in route53 %s", provider.ErrZoneNotFound, name, id, p.id)
		}
		return nil, fmt.Errorf("route53 %s: list record sets of %s: %w", p.id, name, err)
	}
	groups := map[dns.Key][]types.ResourceRecordSet{}
	var keys []dns.Key
	for _, rs := range sets {
		k := dns.Key{Host: dns.NormalizeHost(readName(aws.ToString(rs.Name)), name), Type: string(rs.Type)}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], rs)
	}
	slices.SortFunc(keys, func(a, b dns.Key) int {
		switch {
		case a.Less(b):
			return -1
		case b.Less(a):
			return 1
		}
		return 0
	})
	z := &dns.Zone{Name: name, Provider: p.id, RRsets: make([]dns.RRset, 0, len(keys)), Native: zoneNative{hostedZoneID: id}}
	for _, k := range keys {
		z.RRsets = append(z.RRsets, rrsetOf(k, groups[k]))
	}
	return z, nil
}

func (p *Provider) listRecordSets(ctx context.Context, id string) ([]types.ResourceRecordSet, error) {
	var sets []types.ResourceRecordSet
	in := &awsr53.ListResourceRecordSetsInput{HostedZoneId: aws.String(id)}
	for {
		out, err := p.api.ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, err
		}
		sets = append(sets, out.ResourceRecordSets...)
		if !out.IsTruncated || out.NextRecordName == nil {
			return sets, nil
		}
		in = &awsr53.ListResourceRecordSetsInput{
			HostedZoneId:          aws.String(id),
			StartRecordName:       out.NextRecordName,
			StartRecordType:       out.NextRecordType,
			StartRecordIdentifier: out.NextRecordIdentifier,
		}
	}
}

func routed(rs types.ResourceRecordSet) bool {
	return rs.SetIdentifier != nil || rs.HealthCheckId != nil || rs.TrafficPolicyInstanceId != nil
}

func aliasOf(at *types.AliasTarget) *dns.Alias {
	return &dns.Alias{
		Target:               readName(aws.ToString(at.DNSName)),
		HostedZoneID:         zoneIDOf(aws.ToString(at.HostedZoneId)),
		EvaluateTargetHealth: at.EvaluateTargetHealth,
	}
}

func valuesOf(typ string, rrs []types.ResourceRecord) []string {
	vals := make([]string, 0, len(rrs))
	for _, r := range rrs {
		vals = append(vals, readValue(typ, aws.ToString(r.Value)))
	}
	return vals
}

func rrsetOf(k dns.Key, g []types.ResourceRecordSet) dns.RRset {
	s := dns.RRset{Key: k, Native: g}
	if len(g) > 1 || routed(g[0]) {
		s.ReadOnly = readOnlyRoutingPolicy
		s.TTL = int(aws.ToInt64(g[0].TTL))
		var vals []string
		for _, rs := range g {
			if rs.AliasTarget != nil {
				vals = append(vals, aliasOf(rs.AliasTarget).Target)
			}
			vals = append(vals, valuesOf(k.Type, rs.ResourceRecords)...)
		}
		slices.Sort(vals)
		s.Values = slices.Compact(vals)
		return s
	}
	rs := g[0]
	if rs.AliasTarget != nil {
		s.Alias = aliasOf(rs.AliasTarget)
	} else {
		s.TTL = int(aws.ToInt64(rs.TTL))
		vals := valuesOf(k.Type, rs.ResourceRecords)
		slices.Sort(vals)
		s.Values = slices.Compact(vals)
	}
	if k.Host == dns.Apex && (k.Type == "NS" || k.Type == "SOA") {
		s.ReadOnly = readOnlyServerManaged
	}
	return s
}
