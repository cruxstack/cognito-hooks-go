SHELL := /bin/bash
.DEFAULT_GOAL := help

# lambda build settings; provided.al2023 runs on arm64 or x86_64
GOARCH  ?= arm64
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DIST    := dist
LDFLAGS := -s -w -X main.version=$(VERSION)

# tool versions, run with "go run" so they are built with this module's go
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@v1.9.0

# the race detector on macos needs this linker flag with some xcode versions
TEST_ENV   := $(if $(filter Darwin,$(shell uname -s)),CGO_LDFLAGS=-w,)
TEST_FLAGS := -race -count=1

.PHONY: help
help: ## show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

##@ build

.PHONY: build
build: ## build the lambda binary (dist/bootstrap); GOARCH=arm64 by default
	GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -tags lambda.norpc -ldflags "$(LDFLAGS)" -o $(DIST)/bootstrap .

.PHONY: package
package: build ## zip the binary with PRESIGNUP_POLICY, POSTCONFIRMATION_POLICY, and/or PREAUTHENTICATION_POLICY into dist/lambda.zip
	@test -n "$(PRESIGNUP_POLICY)$(POSTCONFIRMATION_POLICY)$(PREAUTHENTICATION_POLICY)" || (echo "usage: make package [PRESIGNUP_POLICY=path.rego] [POSTCONFIRMATION_POLICY=path.rego] [PREAUTHENTICATION_POLICY=path.rego]"; exit 1)
	$(if $(PRESIGNUP_POLICY),cp $(PRESIGNUP_POLICY) $(DIST)/presignup.rego)
	$(if $(POSTCONFIRMATION_POLICY),cp $(POSTCONFIRMATION_POLICY) $(DIST)/postconfirmation.rego)
	$(if $(PREAUTHENTICATION_POLICY),cp $(PREAUTHENTICATION_POLICY) $(DIST)/preauthentication.rego)
	cd $(DIST) && rm -f lambda.zip && zip -q lambda.zip bootstrap $(if $(PRESIGNUP_POLICY),presignup.rego) $(if $(POSTCONFIRMATION_POLICY),postconfirmation.rego) $(if $(PREAUTHENTICATION_POLICY),preauthentication.rego)
	@echo "$(DIST)/lambda.zip"

.PHONY: clean
clean: ## remove build output
	rm -rf $(DIST) coverage.out

##@ test

.PHONY: test
test: ## run all tests with the race detector
	$(TEST_ENV) go test $(TEST_FLAGS) ./...

.PHONY: test-unit
test-unit: ## run unit tests
	$(TEST_ENV) go test $(TEST_FLAGS) ./internal/...

.PHONY: test-e2e
test-e2e: ## run end-to-end tests (offline)
	$(TEST_ENV) go test $(TEST_FLAGS) ./e2e

.PHONY: test-policies
test-policies: ## test the example policies, including their rego unit tests
	go test -count=1 ./examples

.PHONY: cover
cover: ## run tests with coverage and print a summary
	go test -count=1 -coverprofile=coverage.out -coverpkg=./internal/... ./...
	go tool cover -func=coverage.out | tail -1

##@ quality

.PHONY: lint
lint: ## run golangci-lint
	$(GOLANGCI_LINT) run ./...

.PHONY: fmt
fmt: ## format code
	$(GOLANGCI_LINT) fmt ./...

.PHONY: vuln
vuln: ## check for known vulnerabilities
	$(GOVULNCHECK) ./...

.PHONY: tidy
tidy: ## tidy go.mod and go.sum
	go mod tidy

.PHONY: check
check: lint test vuln ## run lint, tests, and the vulnerability check, as CI does

##@ local runs

.PHONY: eval
eval: ## evaluate the example policies against the example events
	go run ./cmd/devtool eval -presignup-policy examples/policies/presignup/domains.rego -events examples/events/presignup.json
	go run ./cmd/devtool eval -postconfirmation-policy examples/policies/postconfirmation/skip-clients.rego -events examples/events/postconfirmation.json
	go run ./cmd/devtool eval -preauthentication-policy examples/policies/preauthentication/skip-users.rego -events examples/events/preauthentication.json

.PHONY: run
run: ## run the example events through the whole function (dry run, uses .env)
	go run ./cmd/devtool run -events examples/events/presignup.json
	go run ./cmd/devtool run -events examples/events/postconfirmation.json
	go run ./cmd/devtool run -events examples/events/preauthentication.json
