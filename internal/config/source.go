package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Environment variables read by the configuration sources.
const (
	// EnvConfigURI locates the configuration: a file path, s3://bucket/key
	// or ssm:/parameter/name.
	EnvConfigURI = "DNS_GATE_CONFIG_URI"
	// EnvSecretsARN names a Secrets Manager secret holding a JSON object
	// whose keys are environment variable names.
	EnvSecretsARN = "DNS_GATE_SECRETS_ARN"
	// EnvLambdaRuntime is set by AWS Lambda in every function environment.
	EnvLambdaRuntime = "AWS_LAMBDA_RUNTIME_API"
)

// maxSourceBytes bounds a configuration document read from S3 or SSM.
const maxSourceBytes = 4 << 20

var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// S3API is the subset of the S3 client used to read a configuration object.
type S3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// SSMAPI is the subset of the SSM client used to read a parameter.
type SSMAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// SecretsAPI is the subset of the Secrets Manager client used to read a secret.
type SecretsAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Sources reads configuration documents and secrets. Nil clients are built
// on first use from the default AWS credential chain, so a plain file path
// never touches AWS.
type Sources struct {
	S3      S3API
	SSM     SSMAPI
	Secrets SecretsAPI
	// Getenv and Setenv default to os.Getenv and os.Setenv.
	Getenv func(string) string
	Setenv func(key, value string) error

	once   sync.Once
	awsCfg aws.Config
	awsErr error
}

func (s *Sources) aws(ctx context.Context) (aws.Config, error) {
	s.once.Do(func() { s.awsCfg, s.awsErr = awsconfig.LoadDefaultConfig(ctx) })
	return s.awsCfg, s.awsErr
}

func (s *Sources) getenv(k string) string {
	if s.Getenv != nil {
		return s.Getenv(k)
	}
	return os.Getenv(k)
}

func (s *Sources) setenv(k, v string) error {
	if s.Setenv != nil {
		return s.Setenv(k, v)
	}
	return os.Setenv(k, v)
}

func (s *Sources) s3Client(ctx context.Context) (S3API, error) {
	if s.S3 == nil {
		c, err := s.aws(ctx)
		if err != nil {
			return nil, err
		}
		s.S3 = s3.NewFromConfig(c)
	}
	return s.S3, nil
}

func (s *Sources) ssmClient(ctx context.Context) (SSMAPI, error) {
	if s.SSM == nil {
		c, err := s.aws(ctx)
		if err != nil {
			return nil, err
		}
		s.SSM = ssm.NewFromConfig(c)
	}
	return s.SSM, nil
}

func (s *Sources) secretsClient(ctx context.Context) (SecretsAPI, error) {
	if s.Secrets == nil {
		c, err := s.aws(ctx)
		if err != nil {
			return nil, err
		}
		s.Secrets = secretsmanager.NewFromConfig(c)
	}
	return s.Secrets, nil
}

// Read returns the document at uri: s3://bucket/key, ssm:/parameter/name
// (or a parameter ARN, decrypted when a SecureString), or a file path.
func (s *Sources) Read(ctx context.Context, uri string) ([]byte, error) {
	switch {
	case strings.HasPrefix(uri, "s3://"):
		bucket, key, ok := strings.Cut(strings.TrimPrefix(uri, "s3://"), "/")
		if !ok || bucket == "" || key == "" {
			return nil, fmt.Errorf("config: %q: s3://bucket/key expected", uri)
		}
		c, err := s.s3Client(ctx)
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", uri, err)
		}
		out, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", uri, err)
		}
		defer out.Body.Close()
		b, err := io.ReadAll(io.LimitReader(out.Body, maxSourceBytes+1))
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", uri, err)
		}
		if len(b) > maxSourceBytes {
			return nil, fmt.Errorf("config: %s: larger than %d bytes", uri, maxSourceBytes)
		}
		return b, nil
	case strings.HasPrefix(uri, "ssm:"):
		name := strings.TrimPrefix(uri, "ssm:")
		if name == "" {
			return nil, fmt.Errorf("config: %q: ssm:/parameter/name expected", uri)
		}
		c, err := s.ssmClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", uri, err)
		}
		out, err := c.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name), WithDecryption: aws.Bool(true)})
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", uri, err)
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			return nil, fmt.Errorf("config: %s: empty parameter", uri)
		}
		return []byte(*out.Parameter.Value), nil
	default:
		return os.ReadFile(strings.TrimPrefix(uri, "file://"))
	}
}

// Load reads the document at uri and parses it with the environment
// overrides of s.
func (s *Sources) Load(ctx context.Context, uri string) (*Config, error) {
	data, err := s.Read(ctx, uri)
	if err != nil {
		return nil, err
	}
	return Parse(data, s.getenv)
}

// LoadSecrets reads the Secrets Manager secret named by arn, a JSON object
// of environment variable names to string values, and sets each variable
// that is not already set: the function environment wins over the secret.
// It returns the names it set, sorted.
func (s *Sources) LoadSecrets(ctx context.Context, arn string) ([]string, error) {
	c, err := s.secretsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	out, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(arn)})
	if err != nil {
		return nil, fmt.Errorf("secrets: %s: %w", arn, err)
	}
	var raw []byte
	switch {
	case out.SecretString != nil:
		raw = []byte(*out.SecretString)
	case out.SecretBinary != nil:
		raw = out.SecretBinary
	default:
		return nil, fmt.Errorf("secrets: %s: empty secret", arn)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("secrets: %s: JSON object of environment variables expected", arn)
	}
	vals := make(map[string]string, len(fields))
	var errs []error
	for k, v := range fields {
		if !envVarNameRe.MatchString(k) {
			errs = append(errs, fmt.Errorf("secrets: %s: %q is not an environment variable name", arn, k))
			continue
		}
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			errs = append(errs, fmt.Errorf("secrets: %s: %s: string value expected", arn, k))
			continue
		}
		vals[k] = str
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	var set []string
	for k, v := range vals {
		if s.getenv(k) != "" {
			continue
		}
		if err := s.setenv(k, v); err != nil {
			return nil, fmt.Errorf("secrets: %s: %w", k, err)
		}
		set = append(set, k)
	}
	sort.Strings(set)
	return set, nil
}

// LoadSecretsFromEnv calls LoadSecrets with DNS_GATE_SECRETS_ARN; it does
// nothing when the variable is unset.
func (s *Sources) LoadSecretsFromEnv(ctx context.Context) ([]string, error) {
	arn := s.getenv(EnvSecretsARN)
	if arn == "" {
		return nil, nil
	}
	return s.LoadSecrets(ctx, arn)
}
