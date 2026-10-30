# Daemonica – local, CI-agnostic build targets (SPEC §4.3).
SHELL       := /bin/bash
VERSION     ?= 0.1.0~rc3
ARCHES      ?= amd64 arm64
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
GO          ?= go
GOFLAGS_BUILD := -trimpath -buildvcs=false
LDFLAGS     := -s -w -buildid= -X main.version=$(VERSION)
SIGNED      ?= 0
SUFFIX      := $(if $(filter 1,$(SIGNED)),,-UNSIGNED-TESTONLY)

.PHONY: all deps lint test test-integration test-e2e sec build ui package sbom release clean fmt fuzz cover

all: lint test build

deps:
	$(GO) mod download
	@if [ -f web/package-lock.json ]; then cd web && npm ci --ignore-scripts; else echo "web/: no lockfile yet (frontend pending, see docs/STATUS.md)"; fi

fmt:
	gofmt -w cmd internal

lint:
	@test -z "$$(gofmt -l cmd internal)" || { echo "gofmt needed:"; gofmt -l cmd internal; exit 1; }
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null; then golangci-lint run ./...; else echo "SKIP golangci-lint (not installed)"; fi
	@if command -v shellcheck >/dev/null; then shellcheck packaging/maintainer-scripts/* scripts/*.sh; else echo "SKIP shellcheck (not installed)"; fi
	@if [ -f web/package.json ] && [ -d web/node_modules ]; then cd web && npx tsc --noEmit && npx eslint .; else echo "SKIP frontend lint (frontend pending)"; fi

test:
	CGO_ENABLED=1 $(GO) test -race -count=1 -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1

cover: test
	@$(GO) tool cover -func=coverage.out

fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzReadRequest -fuzztime=30s ./internal/rpc
	$(GO) test -run=^$$ -fuzz=FuzzUnit -fuzztime=30s ./internal/validate

test-integration:
	CGO_ENABLED=0 $(GO) test -count=1 -tags integration -v ./test/integration/

# Needs a freshly installed, not yet set up Daemonica on this host (root):
#   sudo make test-e2e E2E_USERS=alice,bob,carol
E2E_OUT ?= dist/e2e
test-e2e:
	node scripts/e2e/full.mjs $(E2E_OUT)

sec:
	@set -e; fail=0; \
	if command -v govulncheck >/dev/null; then govulncheck ./... || fail=1; else echo "SKIP govulncheck (not installed)"; fi; \
	if command -v osv-scanner >/dev/null; then osv-scanner scan source -r . || fail=1; else echo "SKIP osv-scanner (not installed)"; fi; \
	if command -v golangci-lint >/dev/null; then golangci-lint run --enable-only gosec ./... || fail=1; else echo "SKIP gosec (golangci-lint not installed)"; fi; \
	if command -v gitleaks >/dev/null; then gitleaks git --no-banner --redact . || fail=1; else echo "SKIP gitleaks (not installed)"; fi; \
	if [ -f web/package-lock.json ]; then (cd web && npm audit --omit=dev) || fail=1; fi; \
	scripts/check-secrets.sh || fail=1; \
	exit $$fail

ui:
	@if [ -f web/package.json ] && [ -d web/node_modules ]; then \
	  cd web && npm run build && rm -rf ../internal/web/ui/dist && cp -r dist ../internal/web/ui/dist; \
	else echo "SKIP ui build: frontend dependencies unavailable; embedding placeholder shell"; fi

build: ui
	@for a in $(ARCHES); do \
	  mkdir -p dist/$$a; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build $(GOFLAGS_BUILD) -ldflags "$(LDFLAGS)" -o dist/$$a/ ./cmd/... || exit 1; \
	done
	@ls -l dist/*/

package: build
	@for a in $(ARCHES); do scripts/build-deb.sh "$(VERSION)" "$$a" "$(SUFFIX)" || exit 1; done
	@cd dist && sha256sum *.deb > SHA256SUMS && cat SHA256SUMS

# CycloneDX SBOMs for the Go binaries and the bundled frontend (SPEC §4.3).
# Tools: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
#        npx @cyclonedx/cyclonedx-npm@4.0.0 (fetched on first use)
CYCLONEDX_GOMOD ?= $(shell command -v cyclonedx-gomod || echo $$($(GO) env GOPATH)/bin/cyclonedx-gomod)
sbom:
	@mkdir -p dist
	@test -x "$(CYCLONEDX_GOMOD)" || { echo "cyclonedx-gomod missing: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0"; exit 1; }
	"$(CYCLONEDX_GOMOD)" app -json -licenses -std -main cmd/daemonica-helper -output dist/sbom-daemonica-helper.cdx.json .
	"$(CYCLONEDX_GOMOD)" app -json -licenses -std -main cmd/daemonica-web -output dist/sbom-daemonica-web.cdx.json .
	"$(CYCLONEDX_GOMOD)" app -json -licenses -std -main cmd/daemonica-admin -output dist/sbom-daemonica-admin.cdx.json .
	cd web && npx -y @cyclonedx/cyclonedx-npm@4.0.0 --omit dev --output-format JSON --output-file ../dist/sbom-web.cdx.json
	@ls -l dist/sbom-*.cdx.json

release: lint test sec package sbom

clean:
	rm -rf dist coverage.out
