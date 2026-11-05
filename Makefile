.PHONY: test e2e e2e-tofu spec generate lambda

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LAMBDA_ZIP := dist/dns-gate_$(patsubst v%,%,$(VERSION))_lambda_arm64.zip

# The EuroDNS OpenAPI document is not redistributed: fetch it to regenerate
# the route table.
spec:
	mkdir -p api
	curl -fsSL https://docapi.eurodns.com/openapi.json -o api/eurodns.openapi.json

generate: spec
	go generate ./internal/routes

test:
	go test -race ./...

# End-to-end: builds ../terraform-provider-eurodns and drives it with Terraform
# through a real gate in front of the EuroDNS fake.
e2e:
	go test -tags e2e -count=1 -v ./e2e/...

e2e-tofu:
	E2E_TERRAFORM=$$(command -v tofu) go test -tags e2e -count=1 -v ./e2e/...

# AWS Lambda package (provided.al2023, arm64): build web/dist first
# (cd web && npm ci && npm run build), it is embedded in the binary. The zip
# is written by a Go program so that bootstrap is 0755 whatever the disk.
lambda:
	mkdir -p dist/lambda
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags lambda.norpc \
	  -ldflags "-s -w -X github.com/KamorionLabs/dns-gate/internal/version.Version=$(VERSION)" \
	  -o dist/lambda/bootstrap ./cmd/dns-gate
	go run ./internal/tools/lambdazip -o $(LAMBDA_ZIP) dist/lambda/bootstrap
	zipinfo $(LAMBDA_ZIP) bootstrap | grep -q '^-rwxr-xr-x'
	@echo $(LAMBDA_ZIP)
