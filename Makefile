.PHONY: build vet fmt fmt-check lint test test-integration generate

GO ?= go
GOIMPORTS ?= goimports
GOLANGCI ?= golangci-lint

build:
	$(GO) build ./...

vet:
	$(GO) vet ./...

fmt:
	$(GOIMPORTS) -l -w .

fmt-check:
	@out=$$($(GOIMPORTS) -l .); \
	if [ -n "$$out" ]; then \
		echo "unformatted files:"; echo "$$out"; exit 1; \
	fi

lint:
	$(GOLANGCI) run

test:
	$(GO) test -race ./...

test-integration:
	$(GO) test -race -tags=integration ./...

generate:
	$(GO) generate ./...