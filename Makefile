.PHONY: test e2e e2e-tofu spec generate

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
