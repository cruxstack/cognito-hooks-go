.PHONY: build-debug
build-debug:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "-s -w" -o dist/debug ./cmd/debug

.PHONY: debug
debug:
	go run ./cmd/debug -data ./fixtures/debug-data.json -policy ./fixtures/debug-policy.rego

.PHONY: test
test:
	go test ./internal/opa
