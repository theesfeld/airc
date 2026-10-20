.PHONY: test build

GO ?= go

test:
	CGO_ENABLED=0 $(GO) test ./...

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o airc ./cmd/airc
