.PHONY: build vet fmt fmt-check lint test test-integration generate

GO ?= go
GOIMPORTS ?= goimports
GOLANGCI ?= golangci-lint
GOIMPORTS_VERSION ?= v0.47.0
DOCKLE_IMAGE ?= goodwithtech/dockle:latest
APP_IMAGE ?= kaspersky_test-app:dev

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

clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html *.prof
	go clean -testcache

deps:
	go mod tidy

dockle:
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		$(DOCKLE_IMAGE) --exit-code 1 --exit-level warn $(APP_IMAGE)