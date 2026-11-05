// Package route53 is the Amazon Route 53 provider adapter. One Provider
// fronts the hosted zones of one AWS account: it reads them with
// ListResourceRecordSets and writes RRsets with one atomic
// ChangeResourceRecordSets batch per Apply, where every update or delete
// removes the record set exactly as it was read (compare and swap).
package route53

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/KamorionLabs/dns-gate/internal/dns"
	"github.com/KamorionLabs/dns-gate/internal/provider"
)

// Kind is the adapter kind of Route53 providers.
const Kind = "route53"

const (
	defaultRegion     = "us-east-1"
	retryMaxAttempts  = 10
	retryMaxBackoff   = 20 * time.Second
	hostedZonePrefix  = "/hostedzone/"
	sessionNamePrefix = "dns-gate-"
)

// Config is the configuration of one Route53 provider instance (one AWS
// account).
type Config struct {
	// Region of the AWS clients. Route53 is a global service; the region
	// selects the STS endpoint used to assume AssumeRoleARN. Default
	// us-east-1 when neither this nor the environment sets one.
	Region string
	// AssumeRoleARN, when set, is assumed with the credentials of the
	// default chain (Lambda or ECS task role, EKS Pod Identity, IRSA,
	// environment) to reach another account.
	AssumeRoleARN string
	// ExternalID is passed to sts:AssumeRole. It requires AssumeRoleARN.
	ExternalID string
	// HostedZones pins zone names to hosted zone ids ("Z123" or
	// "/hostedzone/Z123"). A pinned zone is always listed, and resolves the
	// ambiguity of several hosted zones with the same name.
	HostedZones map[string]string
	// IncludePrivate also exposes private hosted zones. By default only
	// public hosted zones (and pinned ones) are visible.
	IncludePrivate bool
}

// Client is the subset of the Route53 API the provider calls. The AWS SDK
// client implements it; tests inject fakes with WithClient.
type Client interface {
	ListHostedZones(ctx context.Context, in *awsr53.ListHostedZonesInput, optFns ...func(*awsr53.Options)) (*awsr53.ListHostedZonesOutput, error)
	ListHostedZonesByName(ctx context.Context, in *awsr53.ListHostedZonesByNameInput, optFns ...func(*awsr53.Options)) (*awsr53.ListHostedZonesByNameOutput, error)
	ListResourceRecordSets(ctx context.Context, in *awsr53.ListResourceRecordSetsInput, optFns ...func(*awsr53.Options)) (*awsr53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(ctx context.Context, in *awsr53.ChangeResourceRecordSetsInput, optFns ...func(*awsr53.Options)) (*awsr53.ChangeResourceRecordSetsOutput, error)
}

// Option customizes New.
type Option func(*options)

type options struct {
	client Client
}

// WithClient makes the provider call c instead of an AWS SDK client built
// from the default credential chain.
func WithClient(c Client) Option {
	return func(o *options) { o.client = c }
}

// Provider is the Route53 implementation of provider.Provider.
type Provider struct {
	id     string
	cfg    Config
	api    Client
	pinned map[string]string

	mu  sync.Mutex
	ids map[string]string
}

var _ provider.Provider = (*Provider)(nil)

// New returns the Route53 provider instance id. Without WithClient it loads
// the default AWS configuration, with an adaptive retryer (Route53 allows 5
// requests per second per account) and, when cfg.AssumeRoleARN is set,
// credentials of the assumed role. It makes no AWS call.
func New(ctx context.Context, id string, cfg Config, opts ...Option) (*Provider, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("route53: provider id is empty")
	}
	if cfg.ExternalID != "" && cfg.AssumeRoleARN == "" {
		return nil, fmt.Errorf("route53 %s: external_id requires assume_role_arn", id)
	}
	pinned, err := pinZones(cfg.HostedZones)
	if err != nil {
		return nil, fmt.Errorf("route53 %s: %w", id, err)
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	api := o.client
	if api == nil {
		awsCfg, err := loadAWSConfig(ctx, id, cfg)
		if err != nil {
			return nil, fmt.Errorf("route53 %s: %w", id, err)
		}
		api = awsr53.NewFromConfig(awsCfg)
	}
	return &Provider{id: id, cfg: cfg, api: api, pinned: pinned, ids: map[string]string{}}, nil
}

func loadAWSConfig(ctx context.Context, id string, cfg Config) (aws.Config, error) {
	lo := []func(*config.LoadOptions) error{config.WithRetryer(newRetryer)}
	if cfg.Region != "" {
		lo = append(lo, config.WithRegion(cfg.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, lo...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS configuration: %w", err)
	}
	if awsCfg.Region == "" {
		awsCfg.Region = defaultRegion
	}
	if cfg.AssumeRoleARN != "" {
		ap := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), cfg.AssumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName(id)
			if cfg.ExternalID != "" {
				o.ExternalID = aws.String(cfg.ExternalID)
			}
		})
		awsCfg.Credentials = aws.NewCredentialsCache(ap)
	}
	return awsCfg, nil
}

func newRetryer() aws.Retryer {
	return retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
		o.StandardOptions = append(o.StandardOptions, func(so *retry.StandardOptions) {
			so.MaxAttempts = retryMaxAttempts
			so.MaxBackoff = retryMaxBackoff
		})
	})
}

var sessionNameInvalid = regexp.MustCompile(`[^\w+=,.@-]`)

func sessionName(id string) string {
	n := sessionNamePrefix + sessionNameInvalid.ReplaceAllString(id, "-")
	if len(n) > 64 {
		n = n[:64]
	}
	return n
}

func pinZones(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for name, id := range in {
		n := dns.NormalizeZone(name)
		zid := zoneIDOf(id)
		if n == "" || zid == "" {
			return nil, fmt.Errorf("hosted_zones: invalid entry %q: %q", name, id)
		}
		if prev, ok := out[n]; ok && prev != zid {
			return nil, fmt.Errorf("hosted_zones: zone %s pinned twice", n)
		}
		out[n] = zid
	}
	return out, nil
}

func zoneIDOf(id string) string {
	return strings.ToUpper(strings.TrimPrefix(strings.TrimSpace(id), hostedZonePrefix))
}

// ID returns the instance id from the configuration.
func (p *Provider) ID() string { return p.id }

// Kind returns "route53".
func (p *Provider) Kind() string { return Kind }

// Capabilities: atomic conditional batches, alias records, any TTL.
func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		AtomicBatch:      true,
		ConditionalWrite: true,
		Alias:            true,
		FullZoneWrite:    false,
		Types:            writableTypes(),
		MinTTL:           minTTL,
		MaxTTL:           maxTTL,
	}
}

type hostedZone struct {
	id      string
	name    string
	private bool
}

func hostedZoneOf(hz types.HostedZone) hostedZone {
	z := hostedZone{id: zoneIDOf(aws.ToString(hz.Id)), name: dns.NormalizeZone(readName(aws.ToString(hz.Name)))}
	if hz.Config != nil {
		z.private = hz.Config.PrivateZone
	}
	return z
}

// ListZones returns the public hosted zones of the account (and the private
// ones with IncludePrivate), plus the pinned zones. Several visible hosted
// zones with the same name are an error unless the name is pinned.
func (p *Provider) ListZones(ctx context.Context) ([]string, error) {
	byName := map[string][]hostedZone{}
	in := &awsr53.ListHostedZonesInput{}
	for {
		out, err := p.api.ListHostedZones(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("route53 %s: list hosted zones: %w", p.id, err)
		}
		for _, hz := range out.HostedZones {
			z := hostedZoneOf(hz)
			if z.private && !p.cfg.IncludePrivate {
				continue
			}
			byName[z.name] = append(byName[z.name], z)
		}
		if !out.IsTruncated || out.NextMarker == nil {
			break
		}
		in = &awsr53.ListHostedZonesInput{Marker: out.NextMarker}
	}
	ids := make(map[string]string, len(byName)+len(p.pinned))
	for name, id := range p.pinned {
		ids[name] = id
	}
	for name, zs := range byName {
		if _, ok := p.pinned[name]; ok {
			continue
		}
		if len(zs) > 1 {
			return nil, p.duplicateError(name, zs)
		}
		ids[name] = zs[0].id
	}
	p.mu.Lock()
	p.ids = ids
	p.mu.Unlock()
	names := make([]string, 0, len(ids))
	for name := range ids {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (p *Provider) duplicateError(name string, zs []hostedZone) error {
	desc := make([]string, len(zs))
	for i, z := range zs {
		kind := "public"
		if z.private {
			kind = "private"
		}
		desc[i] = z.id + " (" + kind + ")"
	}
	sort.Strings(desc)
	return fmt.Errorf("route53 %s: %d hosted zones named %s: %s; pin one in hosted_zones", p.id, len(zs), name, strings.Join(desc, ", "))
}

func (p *Provider) zoneID(ctx context.Context, name string) (string, error) {
	if id, ok := p.pinned[name]; ok {
		return id, nil
	}
	p.mu.Lock()
	id, ok := p.ids[name]
	p.mu.Unlock()
	if ok {
		return id, nil
	}
	return p.lookupZone(ctx, name)
}

func (p *Provider) lookupZone(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty zone name", provider.ErrZoneNotFound)
	}
	var found []hostedZone
	in := &awsr53.ListHostedZonesByNameInput{DNSName: aws.String(name + ".")}
	for {
		out, err := p.api.ListHostedZonesByName(ctx, in)
		if err != nil {
			return "", fmt.Errorf("route53 %s: find hosted zone %s: %w", p.id, name, err)
		}
		past := false
		for _, hz := range out.HostedZones {
			z := hostedZoneOf(hz)
			if z.name != name {
				past = true
				break
			}
			if z.private && !p.cfg.IncludePrivate {
				continue
			}
			found = append(found, z)
		}
		if past || !out.IsTruncated || out.NextDNSName == nil {
			break
		}
		in = &awsr53.ListHostedZonesByNameInput{DNSName: out.NextDNSName, HostedZoneId: out.NextHostedZoneId}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%w: %s in route53 %s", provider.ErrZoneNotFound, name, p.id)
	case 1:
		p.mu.Lock()
		p.ids[name] = found[0].id
		p.mu.Unlock()
		return found[0].id, nil
	default:
		return "", p.duplicateError(name, found)
	}
}

func (p *Provider) forget(name string) {
	p.mu.Lock()
	delete(p.ids, name)
	p.mu.Unlock()
}
