.PHONY: build vet fmt fmt-check lint test test-integration generate

GO ?= go
GOIMPORTS ?= goimports
GOLANGCI ?= golangci-lint
GOIMPORTS_VERSION ?= v0.47.0

build:
	$(GO) build ./...

vet:
	$(GO) vet ./...

fmt:
	go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) -l -w .

fmt-check:
	@out=$$(go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) -l .); \
	if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint:
	$(GOLANGCI) run

test:
	$(GO) test -race ./...

test-integration:
	$(GO) test -race -tags=integration ./...

generate:
	$(GO) generate ./...