# Clearance — Makefile
# ---------------------------------------------------------------------------
# Targets are the ones named by the frozen plan:
#   PLAN/01-ARCHITECTURE/10-repo-structure.md §5
#   PLAN/05-INFRASTRUCTURE/01-build-and-release.md §2
# plus `guard` and `dogfood` (03-ci-cd-pipeline.md §2.1, §2.11).
#
# Runs in Git Bash on Windows (the founder's machine) and on Linux/macOS CI.
# Recipe lines MUST begin with a real TAB — do not expand them to spaces.
# ---------------------------------------------------------------------------

# Use bash so the recipe shell is identical on Windows (Git Bash) and Linux/macOS.
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

# Prefer `go` from PATH; override with `make GO=/path/to/go`.
GO ?= go

# Reproducible builds: never mutate the module graph implicitly
# (05-INFRASTRUCTURE/01-build-and-release.md §4).
GOFLAGS ?= -mod=readonly
export GOFLAGS

GOLANGCI_LINT ?= golangci-lint
GORELEASER    ?= goreleaser

BINARY        := clearance
CORPUS_BINARY := corpus-build

# .exe on Windows, empty elsewhere. Used so `make build`/`make dogfood` work
# unmodified in Git Bash.
ifeq ($(OS),Windows_NT)
EXE := .exe
else
EXE :=
endif

# Version metadata baked into the binary. Falls back to sane values when the
# source is a tarball without git.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# Where the binary came from. It is reported as `build_provenance` in every
# verdict, so a release that says "local" is a trust defect, not a cosmetic one.
PROVENANCE ?= local

# The stamped symbols live in internal/cli, not in package main — that is where
# Version/Commit/Provenance are declared and where VersionLine reads them.
#
# These lines said `-X main.version=...` until 23 Sep 2026. `-X` naming a symbol
# that does not exist is silently ignored by the linker: no error, no warning,
# and every build — local, goreleaser, and CI — reported
# 0.0.0-dev / unknown / local. A stamp that cannot fail is the same class of
# defect as a guard that cannot fail.
CLI_PKG := github.com/clearance-dev/clearance/internal/cli

# The corpus public key that verifies the signed corpus bundle (INV-9).
#
# This is the PUBLIC half, and committing it is deliberate: it is not a secret,
# and it is what lets CI stamp the same key the maintainer signed with without
# CI ever holding the private half. The private key is offline and is never read
# by this Makefile except by the `corpus-sign` and `corpus-dist` targets, which a
# human runs by hand on a machine that is not a build server
# (03-SECURITY/03-supply-chain-integrity.md §3.1).
#
# It lives in a file rather than inline so the key can be rotated without
# editing build scripts, and so a reviewer can see the key change in the diff.
CORPUS_PKG         := github.com/clearance-dev/clearance/internal/corpus
CORPUS_PUBKEY_FILE := corpus-public-key.hex
CORPUS_PUBKEY      ?= $(shell tr -d ' \t\r\n' < $(CORPUS_PUBKEY_FILE) 2>/dev/null)

# `-buildid=` is the main source of build non-determinism
# (05-INFRASTRUCTURE/01-build-and-release.md §4).
LDFLAGS := -s -w -buildid= \
           -X $(CLI_PKG).Version=$(VERSION) \
           -X $(CLI_PKG).Commit=$(COMMIT) \
           -X $(CLI_PKG).Provenance=$(PROVENANCE)

# Stamp the corpus key only when there is one.
#
# `-X` sets a string variable, and an EMPTY value is not the same as no value:
# it would overwrite the all-zero sentinel with "", and PublicKey rejects that on
# length before it can report "no key configured" — so a build with an empty key
# file would fail with a confusing length error instead of the honest
# E-INT-005. Worse, the two failures are indistinguishable in a release: both
# refuse every corpus. Only stamp when the file yielded something.
ifneq ($(CORPUS_PUBKEY),)
LDFLAGS += -X $(CORPUS_PKG).devPublicKeyHex=$(CORPUS_PUBKEY)
endif

# The guard tests — the ten invariants plus the privacy/security spine.
# Kept in one place so `make guard` and CI cannot drift
# (00-START-HERE/04-principles-invariants.md §2,
#  05-INFRASTRUCTURE/03-ci-cd-pipeline.md §2.1).
GUARD_INVARIANTS := TestNoUncitedFinding|TestLowConfidenceNeverBlocks|TestNoExecInScanner|TestScannerNeverEscapesRoot|TestEveryErrorCodeIsDocumented|TestVerdictDeterminism|TestUnknownNeverDefaultsToShip|TestConfidenceUpgradeRequiresCorrection|TestUnsignedCorpusRejected|TestYAMLTagRCE|TestBillionLaughs|TestManifestBomb|TestEvaluateRefusesAFindingItCannotCite|TestScannerNeverNamesANonProgram
GUARD_SECURITY   := TestNoUnexpectedEgress|TestNoEnvContentsInOutput|TestNoAbsolutePathsInOutput|TestMCPRefusesEscapePath

# The build-integrity guards, and the meta-guards that keep the three lists
# honest — in both directions. A `-X` link-time stamp naming a symbol that does
# not exist is ignored silently by the linker, so TestEveryStampedSymbolExists
# and TestCorpusPublicKeyIsStampable are the only thing that can tell a build
# which stamps its version from one that merely looks like it does.
# TestEveryGuardTestNamedInTheMakefileExists catches a name pointing at nothing;
# TestNoGuardIsLeftOutOfTheGate catches the reverse, a real guard no name points
# at. Both directions are needed: two guards had been written, reviewed and
# documented while `make guard` never ran them.
GUARD_BUILD      := TestEveryGuardTestNamedInTheMakefileExists|TestEveryRunNameExists|TestNoGuardIsLeftOutOfTheGate|TestBenchmarkSuiteIsNotEmpty|TestEveryStampedSymbolExists|TestCorpusPublicKeyIsStampable

# The corpus-integrity guards: is the data the engine reads sound? Separate from
# the two groups above because a failure here is an edit to a YAML file, not a
# code review.
GUARD_CORPUS     := TestFixtures|TestEveryTrapIsEitherFiredByAFixtureOrListed|TestEveryDegradeCodeIsEitherFiredByAFixtureOrListed|TestEveryTerritoryGateIsEitherEvaluatedOrAcknowledged|TestEveryGraphKindIsEitherProducedByAFixtureOrAcknowledged|TestCorpusPredicatesTypecheck|TestObligationVocabularyMatchesTheSpec|TestEveryObligationKindInTheCorpusIsKnown|TestObligationValidatorRefusesATypo|TestFixActionValidatorRefusesATypo|TestEveryGraphScopedTrapHasAnEngineCheck|TestTrapScopeValidatorRefusesATypo|TestCorpusNoticeCodesMatchTheirDeclaredMeaning|TestShippedBundleIsACurrentCompileOfTheSource

.DEFAULT_GOAL := help
.PHONY: help guard test lint arch fixtures corpus corpus-verify corpus-sign \
        corpus-dist corpus-dist-check build release vulncheck dogfood bench

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' \
		|| true

# `-count=1` on every invocation. It defeats the test cache, so a guard can never
# pass on a stale cached result. The CI `guard` job used to carry this property
# itself, in a step that passed a hand-written name list — and two of the three
# alternatives in that list matched nothing, so the step ran 1 test out of 106
# while exiting 0. The property lives here now, next to the names, where it
# cannot drift from them.
guard: ## Run the invariant + security + build-integrity + corpus guards (the gate; runs first)
	$(GO) test ./internal/... -run '$(GUARD_INVARIANTS)' -count=1
	$(GO) test ./internal/... -run '$(GUARD_SECURITY)' -count=1
	$(GO) test ./internal/... -run '$(GUARD_BUILD)' -count=1
	$(GO) test ./internal/... -run '$(GUARD_CORPUS)' -count=1

arch: ## Run the import-graph layering test alone
	$(GO) test ./internal -run TestArchitectureLayering

test: guard arch ## go test ./... with -race + coverage, after guard and arch
	$(GO) test ./... -race -coverprofile=cover.out

# golangci-lint enforces the import-level bans via depguard (.golangci.yml).
# The grep below catches what depguard cannot: direct yaml/json *decoder calls*
# anywhere in internal/ that bypass safeyaml/safejson, a `net/http` import in any
# file other than the single network client, and any file-*reading* call
# (including read-mode `os.OpenFile`) outside internal/safefs. Mirrors the
# `banned-imports` CI job so a local `make lint` gives the same verdict as CI.
#
# These rules constrain the SHIPPED PRODUCT's runtime, so `*_test.go` is
# excluded — and until it was, this target could not pass at all. The guards are
# themselves Go programs that must read the tree: internal/arch_test.go parses
# every file's imports, so it necessarily calls os.ReadDir/os.ReadFile, and it
# necessarily contains the string "net/http" because that is what it searches
# for. Grepping it back up made `make lint` fail on its own gate — a gate that
# cannot pass is not a gate, it is a habit of ignoring lint.
#
# Excluding tests does not weaken the rules, because the structural form of both
# is enforced on test files too by internal/arch_test.go, which walks every .go
# file and excludes only itself (see `self` in that file). What is lost is the
# grep over test scaffolding, which was never the thing being protected.
lint: ## golangci-lint (incl. depguard) + the custom banned-import lint
	$(GOLANGCI_LINT) run ./...
	@fail=0; \
	if grep -rInE '"(os/exec|syscall|plugin)"' internal/scanner --include='*.go'; then \
		echo "ERROR: internal/scanner must not import os/exec, syscall or plugin (INV-3 / C1)"; \
		fail=1; \
	fi; \
	for f in $$(grep -rIl '"net/http"' internal --include='*.go' --exclude='*_test.go' || true); do \
		if [ "$$f" != "internal/cli/netclient.go" ]; then \
			echo "ERROR: net/http is only allowed in internal/cli/netclient.go (C4): $$f"; \
			fail=1; \
		fi; \
	done; \
	if grep -rInE '\b(yaml|json)\.(Unmarshal|NewDecoder)\b' internal --include='*.go' --exclude='*_test.go' \
		| grep -v '^internal/safeyaml/' | grep -v '^internal/safejson/'; then \
		echo "ERROR: direct yaml/json decoding is banned in internal/ — use safeyaml/safejson (INV-10 / C2)"; \
		fail=1; \
	fi; \
	if grep -rInE '\b(os\.Open|os\.ReadFile|os\.ReadDir|ioutil\.ReadFile)\s*\(' internal --include='*.go' --exclude='*_test.go' \
		| grep -v '^internal/safefs/'; then \
		echo "ERROR: one function opens files — os.Open/os.ReadFile/os.ReadDir are banned outside internal/safefs (INV-4 / C3)"; \
		fail=1; \
	fi; \
	if grep -rInE 'os\.OpenFile\s*\([^)]*os\.O_RDONLY' internal --include='*.go' --exclude='*_test.go' \
		| grep -v '^internal/safefs/'; then \
		echo "ERROR: read-mode os.OpenFile is banned outside internal/safefs (INV-4 / C3); writing output is allowed"; \
		fail=1; \
	fi; \
	exit $$fail

fixtures: ## Verify every fixture produces the verdict it declares
	$(GO) test ./internal/... -run 'TestFixtures'
	$(GO) test ./internal/... -run 'TestEveryTrapIsEitherFiredByAFixtureOrListed'

# Compiles corpus/*.yml -> corpus.json. The compiled corpus is a signed JSON
# bundle, not an embedded database: an embedded DB would need CGO or a
# third-party driver, either of which breaks ADR-001's single-static-binary /
# zero-dependency promise. No key required. `--compile` is the corpus-build CLI
# contract (05-INFRASTRUCTURE/03 §2.7).
corpus: ## Compile corpus/*.yml -> corpus.json (unsigned)
	$(GO) run ./corpus-build --compile --out corpus.json

corpus-verify: ## Run every corpus validation rule (schema, citations, no-silent-upgrade)
	$(GO) run ./corpus-build --validate
	$(GO) test ./internal/... -run 'TestCorpusPredicatesTypecheck|TestConfidenceUpgradeRequiresCorrection'

# The corpus release version, stamped into every verdict as `meta.corpus_version`.
#
# There is deliberately NO default, for the same reason CORPUS_KEY has no default
# path: a default is a decision nobody made. This used to be
# `$(shell date -u +%Y.%m.%d)`, which meant `make corpus-dist` silently stamped a
# version that no runbook step had chosen. The consequences were quiet and real:
# RUNBOOK 2 step 4 ("Bump CORPUS_VERSION") was skippable, two bundles with
# *different* content built on the same day got the *same* version, and one
# unchanged bundle got a new version every day. A version that names content
# cannot be derived from the calendar.
#
# Bump it deliberately — PATCH for a correction, MINOR for a new licence, trap,
# ToS entry or obligation, MAJOR for a schema change
# (07-OPERATIONS/03-runbooks.md RUNBOOK 2 step 4). The corpus ships independently
# of the binary (07-OPERATIONS/04-release-process.md §1), so the version has to
# be readable on its own, away from any binary version beside it.
CORPUS_VERSION ?=

# Requires the OFFLINE Ed25519 key. NEVER run this in CI
# (03-SECURITY/03-supply-chain-integrity.md §3.1).
#
# CORPUS_KEY names a FILE, and there is deliberately no default path — a default
# is a path somebody leaves lying around (see corpus-build's usage text).
#
# This target used to print "Signing requires the OFFLINE key" and then invoke
# the signer anyway with no --key, so it failed every time and told nobody why.
# It now refuses up front and names the thing it is missing.
corpus-sign: ## Sign corpus.json with the offline key: make corpus-sign CORPUS_KEY=<file>
	@test -n "$(CORPUS_KEY)" || { \
		echo "corpus-sign: CORPUS_KEY is not set, and signing is the one step that needs it."; \
		echo "  usage: make corpus-sign CORPUS_KEY=/path/to/corpus-signing.key"; \
		echo "  That file holds the OFFLINE Ed25519 private key. CI must never hold it."; \
		exit 2; \
	}
	$(GO) run ./corpus-build --sign --in corpus.json --out corpus.json.sig --key $(CORPUS_KEY)

# Build the three artefacts a release ships: the payload, its manifest and the
# signature. corpus-dist/ is what `.goreleaser.yml` copies into the archive
# beside the binary, and what a human attaches to the draft release.
#
# It is deliberately NOT the `corpus/` YAML source tree. A release must ship the
# compiled, signed bundle and not the raw YAML: YAML cannot be signed, and
# `clearance check` refuses an unverifiable bundle (INV-9). Shipping the source
# tree would ship a corpus the binary is required to reject — which is exactly
# the state this project was in until the loader was wired to the bundle.
corpus-dist: ## Compile + sign the corpus into ./corpus-dist (needs CORPUS_KEY and CORPUS_VERSION)
	@test -n "$(CORPUS_KEY)" || { \
		echo "corpus-dist: CORPUS_KEY is not set."; \
		echo "  usage: make corpus-dist CORPUS_KEY=/path/to/corpus-signing.key CORPUS_VERSION=<version>"; \
		exit 2; \
	}
	@test -n "$(CORPUS_VERSION)" || { \
		echo "corpus-dist: CORPUS_VERSION is not set."; \
		echo "  usage: make corpus-dist CORPUS_KEY=/path/to/corpus-signing.key CORPUS_VERSION=<version>"; \
		echo "  The version is stamped into every verdict as meta.corpus_version, so it"; \
		echo "  names the CONTENT of this bundle and cannot be derived from today's date."; \
		echo "  Bump it deliberately: PATCH a correction, MINOR a new entry"; \
		echo "  (07-OPERATIONS/03-runbooks.md RUNBOOK 2 step 4)."; \
		exit 2; \
	}
	rm -rf corpus-dist
	mkdir -p corpus-dist
	$(GO) run ./corpus-build --compile --out corpus-dist/corpus.json --version $(CORPUS_VERSION)
	$(GO) run ./corpus-build --sign --in corpus-dist/corpus.json --out corpus-dist/corpus.json.sig --key $(CORPUS_KEY)
	@echo ""
	@echo "corpus-dist/ is built and signed. Verify it before it ships:"
	@echo "  make build && CLEARANCE_CORPUS=corpus-dist ./$(BINARY)$(EXE) corpus verify"
	@echo ""
	@echo "  The corpus is named by the CLEARANCE_CORPUS environment variable."
	@echo "  \`corpus verify\` does not take a --corpus flag: runCorpus resolves the"
	@echo "  corpus itself, so the flag would be ignored and the command would fail"
	@echo "  with E-CORPUS-001 against the default path. This hint printed that"
	@echo "  broken invocation until it was run instead of trusted."

# Check that corpus-dist/ is a current, complete, signed bundle.
#
# This is the SAME script the release pre-flight runs, deliberately: a release
# check that exists in two places is a check that eventually disagrees with
# itself, and the copy nobody runs is the one that is wrong. It exists as a
# target as well as a CI step because the founder needs to be able to run it
# before tagging, not discover the problem after.
#
# It exists at all because corpus-dist/ is git-ignored, so it is invisible to
# review, and the pre-flight verified only that the three files EXISTED. A bundle
# compiled before a corpus edit therefore passed every gate and shipped — which
# is exactly what happened on 25 Sep 2026. See tools/check-corpus-dist.sh.
corpus-dist-check: ## Verify corpus-dist/ is current, complete and signed
	@GO=$(GO) bash tools/check-corpus-dist.sh

build: ## Build the static host binary (CGO_ENABLED=0, -trimpath)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)$(EXE) ./cmd/clearance

release: ## Cross-compile the 6 release targets via goreleaser
	$(GORELEASER) release --clean

vulncheck: ## Run govulncheck on the module
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# There is deliberately NO `conformance` target here.
#
# PLAN/01-ARCHITECTURE/10-repo-structure.md §5 lists `make conformance`, and the
# target existed — running `go test ./... -run TestConformance`. No such test
# was ever written, no `conformance/` directory exists, and corpus/fingerprints/
# is empty with nothing reading it. So the target printed `ok` and exited 0
# while running nothing at all, which is the failure mode this repository keeps
# rediscovering: a name in a build script is a claim, and nothing checks the
# claim unless a test does.
#
# It was removed rather than left failing. A target that always fails trains
# people to ignore `make`, which is how `make lint` stayed broken long enough
# for nobody to notice. The gap is tracked in LOGS.md §6 instead, where gaps
# belong. Restore the target when the vectors exist.

dogfood: build ## Run clearance check . on Clearance itself (must pass)
	./$(BINARY)$(EXE) check . --fail-on BLOCK

bench: ## Run the benchmark suite
	$(GO) test ./... -run '^$$' -bench . -benchmem
