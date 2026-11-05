.PHONY: build vet fmt lint test

build:
	go build ./...

vet:
	go vet ./...

fmt:
	goimports -l -w .

lint:
	golangci-lint run

# test:
# 	go test -race ./...