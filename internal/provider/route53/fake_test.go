package route53

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type fakeZone struct {
	id      string
	name    string
	private bool
	sets    []types.ResourceRecordSet
}

type fakeR53 struct {
	mu         sync.Mutex
	zones      []*fakeZone
	page       int
	calls      map[string]int
	batches    [][]types.Change
	changeErrs []error
}

func newFake(page int) *fakeR53 { return &fakeR53{page: page, calls: map[string]int{}} }

func (f *fakeR53) addZone(id, name string, private bool, sets ...types.ResourceRecordSet) *fakeZone {
	f.mu.Lock()
	defer f.mu.Unlock()
	z := &fakeZone{id: id, name: name + ".", private: private}
	for _, s := range sets {
		z.sets = append(z.sets, stored(s))
	}
	f.zones = append(f.zones, z)
	return z
}

func (f *fakeR53) zone(id string) *fakeZone {
	id = strings.TrimPrefix(id, "/hostedzone/")
	for _, z := range f.zones {
		if z.id == id {
			return z
		}
	}
	return nil
}

func (f *fakeR53) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func (f *fakeR53) records(id string) []types.ResourceRecordSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneSets(f.zone(id).sets)
}

func (f *fakeR53) mutate(id string, fn func(sets []types.ResourceRecordSet) []types.ResourceRecordSet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	z := f.zone(id)
	z.sets = fn(z.sets)
}

func fakeName(n string) string {
	n = strings.ToLower(n)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return strings.ReplaceAll(n, "*", `\052`)
}

func stored(s types.ResourceRecordSet) types.ResourceRecordSet {
	c := cloneSet(s)
	c.Name = aws.String(fakeName(aws.ToString(s.Name)))
	if c.AliasTarget != nil {
		c.AliasTarget.DNSName = aws.String(fakeName(aws.ToString(c.AliasTarget.DNSName)))
	}
	return c
}

func cloneSet(s types.ResourceRecordSet) types.ResourceRecordSet {
	c := s
	c.ResourceRecords = slices.Clone(s.ResourceRecords)
	if s.AliasTarget != nil {
		at := *s.AliasTarget
		c.AliasTarget = &at
	}
	return c
}

func cloneSets(sets []types.ResourceRecordSet) []types.ResourceRecordSet {
	out := make([]types.ResourceRecordSet, len(sets))
	for i, s := range sets {
		out[i] = cloneSet(s)
	}
	return out
}

type setKey struct{ name, typ, id string }

func keyOf(s types.ResourceRecordSet) setKey {
	return setKey{fakeName(aws.ToString(s.Name)), string(s.Type), aws.ToString(s.SetIdentifier)}
}

func (k setKey) less(o setKey) bool {
	if k.name != o.name {
		return k.name < o.name
	}
	if k.typ != o.typ {
		return k.typ < o.typ
	}
	return k.id < o.id
}

func valuesOfSet(s types.ResourceRecordSet) []string {
	var v []string
	for _, r := range s.ResourceRecords {
		v = append(v, aws.ToString(r.Value))
	}
	slices.Sort(v)
	return v
}

func sameSet(a, b types.ResourceRecordSet) bool {
	if (a.TTL == nil) != (b.TTL == nil) || a.TTL != nil && *a.TTL != *b.TTL {
		return false
	}
	if (a.AliasTarget == nil) != (b.AliasTarget == nil) {
		return false
	}
	if a.AliasTarget != nil {
		x, y := a.AliasTarget, b.AliasTarget
		if fakeName(aws.ToString(x.DNSName)) != fakeName(aws.ToString(y.DNSName)) ||
			aws.ToString(x.HostedZoneId) != aws.ToString(y.HostedZoneId) || x.EvaluateTargetHealth != y.EvaluateTargetHealth {
			return false
		}
	}
	return slices.Equal(valuesOfSet(a), valuesOfSet(b)) &&
		aws.ToInt64(a.Weight) == aws.ToInt64(b.Weight) &&
		aws.ToString(a.HealthCheckId) == aws.ToString(b.HealthCheckId)
}

func txtChunksTooLong(v string) bool {
	in, n := false, 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case !in && c == '"':
			in, n = true, 0
		case in && c == '"':
			in = false
		case in && c == '\\':
			if i+3 < len(v) && isOctal(v[i+1]) && isOctal(v[i+2]) && isOctal(v[i+3]) {
				i += 3
			} else {
				i++
			}
			n++
		case in:
			n++
		}
		if n > 255 {
			return true
		}
	}
	return false
}

func (f *fakeR53) ChangeResourceRecordSets(_ context.Context, in *awsr53.ChangeResourceRecordSetsInput, _ ...func(*awsr53.Options)) (*awsr53.ChangeResourceRecordSetsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["ChangeResourceRecordSets"]++
	if len(f.changeErrs) > 0 {
		err := f.changeErrs[0]
		f.changeErrs = f.changeErrs[1:]
		return nil, err
	}
	z := f.zone(aws.ToString(in.HostedZoneId))
	if z == nil {
		return nil, &types.NoSuchHostedZone{Message: aws.String("No hosted zone found with ID: " + aws.ToString(in.HostedZoneId))}
	}
	work := cloneSets(z.sets)
	var msgs []string
	for _, c := range in.ChangeBatch.Changes {
		rs := stored(*c.ResourceRecordSet)
		k := keyOf(rs)
		desc := fmt.Sprintf("[name='%s', type='%s'", k.name, k.typ)
		if k.id != "" {
			desc += fmt.Sprintf(", set-identifier='%s'", k.id)
		}
		desc += "]"
		idx := slices.IndexFunc(work, func(s types.ResourceRecordSet) bool { return keyOf(s) == k })
		switch c.Action {
		case types.ChangeActionDelete:
			switch {
			case idx < 0:
				msgs = append(msgs, "Tried to delete resource record set "+desc+" but it was not found")
			case !sameSet(work[idx], rs):
				msgs = append(msgs, "Tried to delete resource record set "+desc+" but the values provided do not match the current values")
			default:
				work = slices.Delete(work, idx, idx+1)
			}
		case types.ChangeActionCreate:
			if idx >= 0 {
				msgs = append(msgs, "Tried to create resource record set "+desc+" but it already exists")
				continue
			}
			clash := slices.ContainsFunc(work, func(s types.ResourceRecordSet) bool {
				sk := keyOf(s)
				return sk.name == k.name && (sk.typ == "CNAME") != (k.typ == "CNAME")
			})
			if clash {
				msgs = append(msgs, fmt.Sprintf("RRSet of type CNAME with DNS name %s is not permitted as it conflicts with other records with the same DNS name in zone %s", k.name, z.name))
				continue
			}
			for _, v := range rs.ResourceRecords {
				val := aws.ToString(v.Value)
				if len(val) > 4000 || (k.typ == "TXT" || k.typ == "SPF") && txtChunksTooLong(val) {
					msgs = append(msgs, "CharacterStringTooLong (Value is too long) encountered with '"+val+"'")
				}
			}
			work = append(work, rs)
		default:
			msgs = append(msgs, "unsupported action "+string(c.Action))
		}
	}
	if len(msgs) > 0 {
		return nil, &types.InvalidChangeBatch{Messages: msgs}
	}
	z.sets = work
	f.batches = append(f.batches, in.ChangeBatch.Changes)
	return &awsr53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/C1"), Status: types.ChangeStatusPending}}, nil
}

func (f *fakeR53) ListResourceRecordSets(_ context.Context, in *awsr53.ListResourceRecordSetsInput, _ ...func(*awsr53.Options)) (*awsr53.ListResourceRecordSetsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["ListResourceRecordSets"]++
	z := f.zone(aws.ToString(in.HostedZoneId))
	if z == nil {
		return nil, &types.NoSuchHostedZone{Message: aws.String("No hosted zone found with ID: " + aws.ToString(in.HostedZoneId))}
	}
	sets := cloneSets(z.sets)
	slices.SortFunc(sets, func(a, b types.ResourceRecordSet) int {
		ka, kb := keyOf(a), keyOf(b)
		switch {
		case ka.less(kb):
			return -1
		case kb.less(ka):
			return 1
		}
		return 0
	})
	start := 0
	if in.StartRecordName != nil {
		sk := setKey{fakeName(*in.StartRecordName), string(in.StartRecordType), aws.ToString(in.StartRecordIdentifier)}
		start = slices.IndexFunc(sets, func(s types.ResourceRecordSet) bool { return !keyOf(s).less(sk) })
		if start < 0 {
			start = len(sets)
		}
	}
	end := min(start+f.page, len(sets))
	out := &awsr53.ListResourceRecordSetsOutput{ResourceRecordSets: sets[start:end]}
	if end < len(sets) {
		n := sets[end]
		out.IsTruncated = true
		out.NextRecordName = n.Name
		out.NextRecordType = n.Type
		out.NextRecordIdentifier = n.SetIdentifier
	}
	return out, nil
}

func (f *fakeR53) hostedZones() []types.HostedZone {
	out := make([]types.HostedZone, len(f.zones))
	for i, z := range f.zones {
		out[i] = types.HostedZone{Id: aws.String("/hostedzone/" + z.id), Name: aws.String(z.name), Config: &types.HostedZoneConfig{PrivateZone: z.private}}
	}
	return out
}

func (f *fakeR53) ListHostedZones(_ context.Context, in *awsr53.ListHostedZonesInput, _ ...func(*awsr53.Options)) (*awsr53.ListHostedZonesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["ListHostedZones"]++
	all := f.hostedZones()
	start := 0
	if in.Marker != nil {
		start = slices.IndexFunc(all, func(h types.HostedZone) bool { return *h.Id == *in.Marker })
	}
	end := min(start+f.page, len(all))
	out := &awsr53.ListHostedZonesOutput{HostedZones: all[start:end]}
	if end < len(all) {
		out.IsTruncated = true
		out.NextMarker = all[end].Id
	}
	return out, nil
}

func (f *fakeR53) ListHostedZonesByName(_ context.Context, in *awsr53.ListHostedZonesByNameInput, _ ...func(*awsr53.Options)) (*awsr53.ListHostedZonesByNameOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["ListHostedZonesByName"]++
	all := f.hostedZones()
	slices.SortFunc(all, func(a, b types.HostedZone) int {
		if c := strings.Compare(*a.Name, *b.Name); c != 0 {
			return c
		}
		return strings.Compare(*a.Id, *b.Id)
	})
	name, id := aws.ToString(in.DNSName), aws.ToString(in.HostedZoneId)
	start := slices.IndexFunc(all, func(h types.HostedZone) bool {
		return *h.Name > name || *h.Name == name && strings.TrimPrefix(*h.Id, "/hostedzone/") >= strings.TrimPrefix(id, "/hostedzone/")
	})
	if start < 0 {
		start = len(all)
	}
	end := min(start+f.page, len(all))
	out := &awsr53.ListHostedZonesByNameOutput{HostedZones: all[start:end]}
	if end < len(all) {
		out.IsTruncated = true
		out.NextDNSName = all[end].Name
		out.NextHostedZoneId = all[end].Id
	}
	return out, nil
}
