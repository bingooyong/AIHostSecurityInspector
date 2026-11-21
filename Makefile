GO ?= go
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BACKEND := $(REPO_ROOT)/backend
BUILD_DIR := $(REPO_ROOT)/build
VERSION ?= 0.1.0-dev
HOSTSEC_PKG := github.com/bingooyong/AIHostSecurityInspector/backend/internal/cli
GO_LDFLAGS := -buildid= -X $(HOSTSEC_PKG).Version=$(VERSION)
HOSTSEC_EVIDENCE_DIR ?= docs/05-testing/evidence/ci-local
export PATH := $(BUILD_DIR)/tools:$(PATH)
.PHONY: tools build test vet lint schema boundaries baseline layout integration check release sbom vuln
build:
	mkdir -p "$(BUILD_DIR)"
	$(GO) -C "$(BACKEND)" build -trimpath -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/hostsec" ./cmd/hostsec

test:
	$(GO) -C "$(BACKEND)" test -race -count=1 ./...

vet:
	$(GO) -C "$(BACKEND)" vet ./...

lint:
	cd "$(BACKEND)" && golangci-lint run ./...

schema: build
	python3 "$(REPO_ROOT)/scripts/integration.py"

boundaries:
	$(GO) -C "$(BACKEND)" run ./tools/check-boundaries

baseline:
	python3 "$(REPO_ROOT)/scripts/validate_baseline.py"

layout: build
	python3 "$(REPO_ROOT)/scripts/check_layout.py"

integration: schema

vuln:
	cd "$(BACKEND)" && govulncheck -show verbose ./...

sbom:
	mkdir -p "$(BUILD_DIR)"
	cd "$(BACKEND)" && cyclonedx-gomod mod -json -output "$(BUILD_DIR)/sbom.cdx.json"

release:
	python3 "$(REPO_ROOT)/scripts/build_release.py"

check:
	HOSTSEC_EVIDENCE_DIR="$(HOSTSEC_EVIDENCE_DIR)" python3 "$(REPO_ROOT)/scripts/verify.py"

# Repository-local tooling avoids replacing user-installed binaries.
# Pin the toolchain to backend/go.mod so golangci-lint is not built with an older Go than the module.
GO_MODULE_VERSION := $(shell awk '/^go /{print $$2; exit}' "$(BACKEND)/go.mod")
tools:
	mkdir -p "$(BUILD_DIR)/tools"
	GOBIN="$(BUILD_DIR)/tools" GOTOOLCHAIN=go$(GO_MODULE_VERSION) $(GO) -C "$(BACKEND)" install golang.org/x/vuln/cmd/govulncheck@v1.6.0
	GOBIN="$(BUILD_DIR)/tools" GOTOOLCHAIN=go$(GO_MODULE_VERSION) $(GO) -C "$(BACKEND)" install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
	GOBIN="$(BUILD_DIR)/tools" GOTOOLCHAIN=go$(GO_MODULE_VERSION) $(GO) -C "$(BACKEND)" install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
