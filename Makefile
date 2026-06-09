BIN := $(CURDIR)/bin

# Project tools (golangci-lint, goreleaser) run through tools/go.mod so a
# contributor and a CI runner use byte-for-byte the same version. Never
# invoke them through an ambient PATH.
LINT       := go tool -modfile=tools/go.mod golangci-lint
GORELEASER := go tool -modfile=tools/go.mod goreleaser

# Minimum total statement coverage enforced by `make test-cover`. The
# legacy direct-opcode compiler that used to sit behind the SSA pipeline
# as a per-function fallback has been deleted; every emitted body now
# goes through SSA, so the threshold tracks the real per-statement
# coverage of the live codegen.
COVERAGE_THRESHOLD ?= 85

.PHONY: build test test-cover lint vet release release/check install/wat2wasm clean

# build compiles the wasm2go CLI into ./bin.
build: | $(BIN)
	go build -o $(BIN)/wasm2go ./cmd/wasm2go

$(BIN):
	@mkdir -p $(BIN)

# test runs the full suite with the race detector.
test:
	go test -race -timeout 20m ./...

# test-cover runs the suite with coverage and fails if total statement
# coverage drops below COVERAGE_THRESHOLD.
#
# `-coverpkg=./...` measures cross-package coverage: a statement in
# package A is counted as covered when any test (in A or anywhere
# else) executes it. The default per-package mode would only credit
# tests inside the package itself, which under-reports packages like
# internal/asmgen and internal/lower that are exercised primarily
# through integration tests in internal/codegen.
test-cover:
	go test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {print $$3}' | tr -d '%'); \
	awk -v t="$$total" -v th="$(COVERAGE_THRESHOLD)" 'BEGIN { \
		if (t + 0 < th + 0) { printf "coverage %s%% is below the %s%% threshold\n", t, th; exit 1 } \
		printf "coverage %s%% meets the %s%% threshold\n", t, th }'

vet:
	go vet ./...

# lint runs golangci-lint, pinned via tools/go.mod.
lint:
	$(LINT) run ./...

# release publishes a tagged release through GoReleaser.
release:
	$(GORELEASER) release --clean

# release/check validates the GoReleaser configuration and runs a
# publish-free dry-run build. The release-test workflow runs this.
release/check:
	$(GORELEASER) check
	$(GORELEASER) release --snapshot --clean --skip=publish

# install/wat2wasm installs the wat2wasm CLI (from WebAssembly's wabt
# toolkit), which the test suite uses to compile testdata/*.wat into
# wasm on demand. Detects the host platform and dispatches to the
# matching package manager; no-op if wat2wasm is already on PATH.
install/wat2wasm:
	@if command -v wat2wasm >/dev/null 2>&1; then \
		echo "wat2wasm already installed: $$(wat2wasm --version 2>&1 | head -1)"; \
	elif [ "$$(uname -s)" = "Darwin" ]; then \
		brew install wabt; \
	elif [ "$$(uname -s)" = "Linux" ]; then \
		if command -v apt-get >/dev/null 2>&1; then \
			set -e; $(if_sudo) apt-get update; $(if_sudo) apt-get install -y wabt; \
		elif command -v dnf >/dev/null 2>&1; then \
			set -e; $(if_sudo) dnf install -y wabt; \
		elif command -v pacman >/dev/null 2>&1; then \
			set -e; $(if_sudo) pacman -S --noconfirm wabt; \
		elif command -v apk >/dev/null 2>&1; then \
			set -e; $(if_sudo) apk add --no-cache wabt; \
		else \
			echo "no supported Linux package manager (apt-get/dnf/pacman/apk) found; install wabt manually" >&2; exit 1; \
		fi; \
	else \
		echo "unsupported platform $$(uname -s); install wabt from https://github.com/WebAssembly/wabt" >&2; exit 1; \
	fi

# if_sudo expands to `sudo` when sudo is on PATH, otherwise nothing — so
# the install recipe works both as a regular user (sudo prefix) and as
# root inside a container (no prefix needed).
if_sudo = $$(command -v sudo >/dev/null 2>&1 && echo sudo || true)

clean:
	rm -rf $(BIN) coverage.out dist
