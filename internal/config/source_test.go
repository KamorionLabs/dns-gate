package config

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeS3 struct {
	objects map[string]string
	calls   int
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.calls++
	v, ok := f.objects[*in.Bucket+"/"+*in.Key]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(v))}, nil
}

type fakeSSM struct {
	params    map[string]string
	decrypted bool
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.decrypted = aws.ToBool(in.WithDecryption)
	v, ok := f.params[*in.Name]
	if !ok {
		return nil, errors.New("ParameterNotFound")
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(v)}}, nil
}

type fakeSecrets struct {
	secrets map[string]string
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	v, ok := f.secrets[*in.SecretId]
	if !ok {
		return nil, errors.New("ResourceNotFoundException")
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

type noAWS struct{}

func (noAWS) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	panic("unexpected S3 call")
}

func (noAWS) GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	panic("unexpected SSM call")
}

func TestSourcesRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs3 := &fakeS3{objects: map[string]string{"cfg-bucket/gate/config.yaml": "from-s3"}}
	fssm := &fakeSSM{params: map[string]string{"/dns-gate/config": "from-ssm"}}
	src := &Sources{S3: fs3, SSM: fssm}
	ctx := context.Background()
	for uri, want := range map[string]string{
		path:                               "from-file",
		"file://" + path:                   "from-file",
		"s3://cfg-bucket/gate/config.yaml": "from-s3",
		"ssm:/dns-gate/config":             "from-ssm",
	} {
		got, err := src.Read(ctx, uri)
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if string(got) != want {
			t.Errorf("%s: got %q, want %q", uri, got, want)
		}
	}
	if !fssm.decrypted {
		t.Error("SSM parameter read without decryption")
	}
	for _, uri := range []string{"s3://bucket-only", "s3:///key", "s3://cfg-bucket/missing", "ssm:", "ssm:/missing", filepath.Join(t.TempDir(), "none")} {
		if _, err := src.Read(ctx, uri); err == nil {
			t.Errorf("%s: error expected", uri)
		}
	}
}

func TestSourcesReadFileDoesNotTouchAWS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := &Sources{S3: noAWS{}, SSM: noAWS{}}
	if _, err := src.Read(context.Background(), path); err != nil {
		t.Fatal(err)
	}
}

func TestSourcesLoadParsesWithEnv(t *testing.T) {
	src := &Sources{
		S3:     &fakeS3{objects: map[string]string{"b/k": base}},
		Getenv: env(map[string]string{"EURODNS_API_KEY": "secret"}),
	}
	c, err := src.Load(context.Background(), "s3://b/k")
	if err != nil {
		t.Fatal(err)
	}
	if c.Upstream.APIKey != "secret" {
		t.Errorf("api key %q", c.Upstream.APIKey)
	}
}

func TestLambdaRequiresDynamoDB(t *testing.T) {
	lambdaEnv := map[string]string{"EURODNS_API_KEY": "secret", EnvLambdaRuntime: "127.0.0.1:9001"}
	_, err := Parse([]byte(base), env(lambdaEnv))
	if err == nil || !strings.Contains(err.Error(), "dynamodb required") {
		t.Fatalf("got %v, want a dynamodb error", err)
	}
	if _, err := Parse([]byte(base+"store: {type: dynamodb, dynamodb: {table: gate}}\n"), env(lambdaEnv)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(base), env(map[string]string{"EURODNS_API_KEY": "secret"})); err != nil {
		t.Fatalf("memory store outside Lambda: %v", err)
	}
}

func TestLoadSecrets(t *testing.T) {
	vars := map[string]string{"EURODNS_APP_ID": "from-env"}
	src := &Sources{
		Secrets: &fakeSecrets{secrets: map[string]string{
			"arn:gate": `{"DNS_GATE_SESSION_KEY":"k","EURODNS_API_KEY":"api","EURODNS_APP_ID":"from-secret"}`,
			"bad-name": `{"not a name":"x"}`,
			"bad-val":  `{"EURODNS_API_KEY":42}`,
			"not-obj":  `["x"]`,
		}},
		Getenv: func(k string) string { return vars[k] },
		Setenv: func(k, v string) error { vars[k] = v; return nil },
	}
	ctx := context.Background()
	set, err := src.LoadSecrets(ctx, "arn:gate")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"DNS_GATE_SESSION_KEY", "EURODNS_API_KEY"}; !reflect.DeepEqual(set, want) {
		t.Errorf("set %v, want %v", set, want)
	}
	if vars["EURODNS_API_KEY"] != "api" || vars["DNS_GATE_SESSION_KEY"] != "k" {
		t.Errorf("environment %v", vars)
	}
	if vars["EURODNS_APP_ID"] != "from-env" {
		t.Errorf("the function environment must win over the secret, got %q", vars["EURODNS_APP_ID"])
	}
	for _, arn := range []string{"bad-name", "bad-val", "not-obj", "missing"} {
		if _, err := src.LoadSecrets(ctx, arn); err == nil {
			t.Errorf("%s: error expected", arn)
		}
	}
}

func TestLoadSecretsFromEnv(t *testing.T) {
	vars := map[string]string{}
	src := &Sources{
		Secrets: &fakeSecrets{secrets: map[string]string{"arn:s": `{"EURODNS_API_KEY":"api"}`}},
		Getenv:  func(k string) string { return vars[k] },
		Setenv:  func(k, v string) error { vars[k] = v; return nil },
	}
	if set, err := src.LoadSecretsFromEnv(context.Background()); err != nil || set != nil {
		t.Fatalf("without %s: %v %v", EnvSecretsARN, set, err)
	}
	vars[EnvSecretsARN] = "arn:s"
	if _, err := src.LoadSecretsFromEnv(context.Background()); err != nil {
		t.Fatal(err)
	}
	if vars["EURODNS_API_KEY"] != "api" {
		t.Errorf("environment %v", vars)
	}
}
