package route53

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

const (
	maxBatchRecords = 1000
	maxBatchChars   = 32000
	batchComment    = "dns-gate"
)

var conflictMessages = []string{
	"but it already exists",
	"but it was not found",
	"values provided do not match",
	"conflicts with other records",
}

var messageKey = regexp.MustCompile(`name='([^']*)', type='([^']*)'`)

// Apply writes changes in one ChangeResourceRecordSets batch, atomic on the
// Route53 side: a create is a CREATE, an update a DELETE of the record set
// exactly as read followed by a CREATE, a delete a DELETE of the record set
// exactly as read. The record set deleted is Old.Native, or the one of cur
// when Old carries none (its content must then match Old). A batch Route53
// rejects because the upstream content changed is provider.ErrConflict; a
// batch over the Route53 request limits is an *provider.InvalidError and is
// never split. Apply returns once Route53 accepted the batch, without
// waiting for INSYNC.
func (p *Provider) Apply(ctx context.Context, zone string, cur *dns.Zone, changes []dns.Change) error {
	if len(changes) == 0 {
		return nil
	}
	name := dns.NormalizeZone(zone)
	id := ""
	if cur != nil {
		if zn, ok := cur.Native.(zoneNative); ok {
			id = zn.hostedZoneID
		}
	}
	if id == "" {
		var err error
		if id, err = p.zoneID(ctx, name); err != nil {
			return err
		}
	}
	var batch []types.Change
	for _, c := range changes {
		switch c.Op {
		case dns.OpCreate, dns.OpUpdate, dns.OpDelete:
		default:
			return &provider.InvalidError{Key: c.Key, Message: fmt.Sprintf("unknown operation %q", c.Op)}
		}
		if c.Op != dns.OpCreate {
			if c.Old == nil {
				return &provider.InvalidError{Key: c.Key, Message: string(c.Op) + " without the current RRset"}
			}
			olds, err := p.oldNative(name, cur, *c.Old)
			if err != nil {
				return err
			}
			for i := range olds {
				batch = append(batch, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &olds[i]})
			}
		}
		if c.Op != dns.OpDelete {
			if c.New == nil {
				return &provider.InvalidError{Key: c.Key, Message: string(c.Op) + " without the desired RRset"}
			}
			rs, err := p.nativeOf(name, *c.New)
			if err != nil {
				return err
			}
			batch = append(batch, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &rs})
		}
	}
	if err := checkLimits(batch, changes[0].Key); err != nil {
		return err
	}
	_, err := p.api.ChangeResourceRecordSets(ctx, &awsr53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(id),
		ChangeBatch:  &types.ChangeBatch{Comment: aws.String(batchComment), Changes: batch},
	})
	if err != nil {
		return p.applyError(name, id, changes, err)
	}
	return nil
}

func (p *Provider) oldNative(zone string, cur *dns.Zone, old dns.RRset) ([]types.ResourceRecordSet, error) {
	if old.ReadOnly != "" {
		return nil, &provider.InvalidError{Key: old.Key, Message: "read-only RRset (" + old.ReadOnly + ")"}
	}
	if sets, ok := old.Native.([]types.ResourceRecordSet); ok && len(sets) > 0 {
		if len(sets) > 1 || routed(sets[0]) {
			return nil, &provider.InvalidError{Key: old.Key, Message: "read-only RRset (" + readOnlyRoutingPolicy + ")"}
		}
		return []types.ResourceRecordSet{sets[0]}, nil
	}
	if cur != nil {
		if s, ok := cur.Set(old.Key); ok {
			if s.ReadOnly != "" {
				return nil, &provider.InvalidError{Key: old.Key, Message: "read-only RRset (" + s.ReadOnly + ")"}
			}
			if dns.ContentHash(s) != dns.ContentHash(old) {
				return nil, fmt.Errorf("%w: %s differs from the zone read", provider.ErrConflict, old.Key)
			}
			if sets, ok := s.Native.([]types.ResourceRecordSet); ok && len(sets) == 1 {
				return sets, nil
			}
		}
	}
	rs, err := p.nativeOf(zone, old)
	if err != nil {
		return nil, err
	}
	return []types.ResourceRecordSet{rs}, nil
}

func (p *Provider) nativeOf(zone string, set dns.RRset) (types.ResourceRecordSet, error) {
	n, err := p.Normalize(zone, set)
	if err != nil {
		return types.ResourceRecordSet{}, err
	}
	rs := types.ResourceRecordSet{Name: aws.String(wireName(fqdn(zone, n.Key.Host))), Type: types.RRType(n.Key.Type)}
	if n.Alias != nil {
		rs.AliasTarget = &types.AliasTarget{
			DNSName:              aws.String(wireName(n.Alias.Target)),
			HostedZoneId:         aws.String(n.Alias.HostedZoneID),
			EvaluateTargetHealth: n.Alias.EvaluateTargetHealth,
		}
		return rs, nil
	}
	rs.TTL = aws.Int64(int64(n.TTL))
	for _, v := range n.Values {
		w, err := wireValue(n.Key.Type, v)
		if err != nil {
			return types.ResourceRecordSet{}, &provider.InvalidError{Key: n.Key, Message: err.Error()}
		}
		rs.ResourceRecords = append(rs.ResourceRecords, types.ResourceRecord{Value: aws.String(w)})
	}
	return rs, nil
}

func checkLimits(batch []types.Change, key dns.Key) error {
	records, chars := 0, 0
	for _, c := range batch {
		for _, r := range c.ResourceRecordSet.ResourceRecords {
			records++
			chars += len(aws.ToString(r.Value))
		}
	}
	if records > maxBatchRecords || chars > maxBatchChars {
		return &provider.InvalidError{Key: key, Message: fmt.Sprintf(
			"the change batch has %d records and %d characters of values, over the Route53 limits of %d records and %d characters per request; it is not split, to stay atomic",
			records, chars, maxBatchRecords, maxBatchChars)}
	}
	return nil
}

func (p *Provider) applyError(zone, id string, changes []dns.Change, err error) error {
	var icb *types.InvalidChangeBatch
	if errors.As(err, &icb) {
		msgs := icb.Messages
		if len(msgs) == 0 && icb.Message != nil {
			msgs = []string{*icb.Message}
		}
		detail := strings.Join(msgs, "; ")
		for _, m := range msgs {
			lm := strings.ToLower(m)
			for _, c := range conflictMessages {
				if strings.Contains(lm, c) {
					return fmt.Errorf("%w: route53 %s rejected the change batch on %s: %s", provider.ErrConflict, p.id, zone, detail)
				}
			}
		}
		return &provider.InvalidError{Key: keyOfMessages(zone, msgs, changes[0].Key), Message: "route53 rejected the change batch: " + detail}
	}
	var ii *types.InvalidInput
	if errors.As(err, &ii) {
		return &provider.InvalidError{Key: changes[0].Key, Message: "route53 rejected the change batch: " + ii.ErrorMessage()}
	}
	var nsz *types.NoSuchHostedZone
	if errors.As(err, &nsz) {
		p.forget(zone)
		return fmt.Errorf("%w: %s (%s) in route53 %s", provider.ErrZoneNotFound, zone, id, p.id)
	}
	return fmt.Errorf("route53 %s: change record sets of %s: %w", p.id, zone, err)
}

func keyOfMessages(zone string, msgs []string, fallback dns.Key) dns.Key {
	for _, m := range msgs {
		if sm := messageKey.FindStringSubmatch(m); sm != nil {
			return dns.Key{Host: dns.NormalizeHost(readName(sm[1]), zone), Type: strings.ToUpper(sm[2])}
		}
	}
	return fallback
}
