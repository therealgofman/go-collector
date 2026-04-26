GO ?= go
PKGS := ./...
GOLANGCI_LINT_RUN := $(GO) run github.com/golangci/golangci-lint/cmd/golangci-lint@latest
GOPATH := $(CURDIR)/.cache/gopath
GOMODCACHE := $(CURDIR)/.cache/gomod
GOCACHE := $(CURDIR)/.cache/go-build
GOLANGCI_LINT_CACHE := $(CURDIR)/.cache/golangci-lint
BINARY_NAME ?= go-collector
BUILD_DIR ?= bin

.PHONY: fmt lint lint-fix build check

fmt:
	$(GO) fmt $(PKGS)

lint:
	GOPATH=$(GOPATH) GOMODCACHE=$(GOMODCACHE) GOCACHE=$(GOCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT_RUN) run

lint-fix:
	GOPATH=$(GOPATH) GOMODCACHE=$(GOMODCACHE) GOCACHE=$(GOCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOLANGCI_LINT_RUN) run --fix

build:
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) .

check: fmt lint build
