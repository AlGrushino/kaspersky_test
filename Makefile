# Makefile for the Information Exchange Service.
#
# Common workflows:
#   make up             start the service and PostgreSQL with Docker Compose
#   make test           run unit tests
#   make test.coverage  run tests with a coverage report
#   make help           list all available targets

.DEFAULT_GOAL := help
.PHONY: build run vet fmt fmt-check lint test test-integration \
	test.coverage test.html test.show generate up down clean deps dockle help

# Tool and artifact settings (override on the command line if needed).
GO ?= go
GOIMPORTS ?= goimports
GOLANGCI ?= golangci-lint
GOIMPORTS_VERSION ?= v0.47.0
DOCKLE_IMAGE ?= goodwithtech/dockle:latest
APP_IMAGE ?= kaspersky_test-app:dev
COVERAGE_FILE ?= coverage.out
COVERAGE_HTML ?= coverage.html

## Build and run

build: ## Build all Go packages
	$(GO) build ./...

run: ## Run the server locally (requires DATABASE_URL)
	$(GO) run ./cmd/server

up: ## Start the Docker Compose stack in the background
	docker compose up --build -d

down: ## Stop the Docker Compose stack
	docker compose down

## Code quality

vet: ## Run go vet
	$(GO) vet ./...

fmt: ## Format code with goimports
	go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) -l -w .

fmt-check: ## Check that code is formatted
	@out=$$(go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) -l .); \
	if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint: ## Run golangci-lint
	$(GOLANGCI) run

## Tests and coverage

test: ## Run unit tests with the race detector
	$(GO) test -race ./...

test-integration: ## Run integration tests (requires Docker)
	$(GO) test -race -tags=integration ./...

# Only pass packages that actually contain tests: collecting coverage for
# packages without test files triggers a broken covdata lookup in Go 1.26.0.
# -coverpkg=./... still instruments the whole module in the final report.
test.coverage: ## Run tests with a coverage report
	$(GO) test -v -coverprofile=$(COVERAGE_FILE) -coverpkg=./... \
		$$($(GO) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...)
	$(GO) tool cover -func=$(COVERAGE_FILE)

test.html: test.coverage ## Generate an HTML coverage report
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Отчёт: $(COVERAGE_HTML)"

test.show: test.html ## Show the HTML coverage report in a browser
	$(GO) tool cover -html=$(COVERAGE_FILE)

## Code generation and maintenance

generate: ## Generate Go code from the OpenAPI specification
	$(GO) generate ./...

clean: ## Remove coverage and test cache artifacts
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML) *.prof
	$(GO) clean -testcache

deps: ## Tidy Go module dependencies
	$(GO) mod tidy

dockle: ## Check the Docker image with Dockle
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		$(DOCKLE_IMAGE) --exit-code 1 --exit-level warn $(APP_IMAGE)

## Help

help: ## Show available commands
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
