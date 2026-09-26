# Clearance — Makefile
# ---------------------------------------------------------------------------
# The target set is frozen: the ones below, plus `guard` and `dogfood`.
#
# Runs in Git Bash on Windows (the founder's machine) and on Linux/macOS CI.
# Recipe lines MUST begin with a real TAB — do not expand them to spaces.
# ---------------------------------------------------------------------------

# Use bash so the recipe shell is identical on Windows (Git Bash) and Linux/macOS.
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

# Prefer `go` from PATH; override with `make GO=/path/to/go`.
GO ?= go

# Reproducible builds: never mutate the module graph implicitly.
GOFLAGS ?= -mod=readonly
export GOFLAGS

# CI pins this in .github/workflows/ci.yml (golangci/golangci-lint-action@v6,
# version: v1.62.2) and .golangci.yml is written for that v1.x schema. Installing
# @latest here will eventually give you a v2 line whose schema this file does not
# match, and `make lint` will fail on the config rather than on the code.
GOLANGCI_LINT ?= golangci-lint
GORELEASER    ?= goreleaser

# Pinned, on purpose. This was `@latest` and it stopped working: x/vuln@latest
# (v1.8.0) requires go >= 1.26.0, so `make vulncheck` failed on the tool rather
# than on the code, silently reporting nothing at all. That is the defect this
# repository keeps re-finding — a gate that cannot run is a gate that passes.
# v1.1.4 is the newest release that runs on the go 1.23 toolchain this module
# targets (go.mod). Bump it together with GOTOOLCHAIN, not separately.
GOVULNCHECK   ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4

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
# human runs by hand on a machine that is not a build server.
#
# It lives in a file rather than inline so the key can be rotated without
# editing build scripts, and so a reviewer can see the key change in the diff.
CORPUS_PKG         := github.com/clearance-dev/clearance/internal/corpus
CORPUS_PUBKEY_FILE := corpus-public-key.hex
CORPUS_PUBKEY      ?= $(shell tr -d ' \t\r\n' < $(CORPUS_PUBKEY_FILE) 2>/dev/null)

# `-buildid=` is the main source of build non-determinism.
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
# Kept in one place so `make guard` and CI cannot drift.
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
GUARD_BUILD      := TestEveryGuardTestNamedInTheMakefileExists|TestEveryRunNameExists|TestNoGuardIsLeftOutOfTheGate|TestBenchmarkSuiteIsNotEmpty|TestEveryStampedSymbolExists|TestCorpusPublicKeyIsStampable|TestOurOwnScriptsNameNoThirdPartyProgram|TestQuotedCommandSubstitutionIsSplit|TestShellFunctionNamesAreNotPrograms|TestEveryGoTestInvocationIsUncached

# The corpus-integrity guards: is the data the engine reads sound? Separate from
# the two groups above because a failure here is an edit to a YAML file, not a
# code review.
GUARD_CORPUS     := TestFixtures|TestEveryTrapIsEitherFiredByAFixtureOrListed|TestEveryDegradeCodeIsEitherFiredByAFixtureOrListed|TestEveryTerritoryGateIsEitherEvaluatedOrAcknowledged|TestEveryGraphKindIsEitherProducedByAFixtureOrAcknowledged|TestCorpusPredicatesTypecheck|TestObligationVocabularyMatchesTheSpec|TestEveryObligationKindInTheCorpusIsKnown|TestObligationValidatorRefusesATypo|TestFixActionValidatorRefusesATypo|TestEveryGraphScopedTrapHasAnEngineCheck|TestTrapScopeValidatorRefusesATypo|TestCorpusNoticeCodesMatchTheirDeclaredMeaning|TestShippedBundleIsACurrentCompileOfTheSource

.DEFAULT_GOAL := help
.PHONY: help guard test lint arch fixtures corpus corpus-verify \
        corpus-verify-bundle corpus-sign \
        corpus-dist corpus-dist-check build release vulncheck dogfood bench \
        ship-check

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
	$(GO) test ./internal -run TestArchitectureLayering -count=1

# -count=1, and it is not optional here either. Without it Go replays a cached
# PASS, so `make test` could report green without executing a single test — the
# same defect `make fixtures` had, in the target whose whole job is to run the
# suite. It also fails the project's own acceptance rule, which asks for the
# suite green "with -count=1 (and -race)". Both are now true.
test: guard arch ## go test ./... with -race + coverage, after guard and arch
	$(GO) test ./... -race -count=1 -coverprofile=cover.out

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

# -count=1 on both, for the same reason `guard` carries it: without it Go replays
# a cached result, and this target's green was observed to be a cache hit rather
# than a run. A target that can pass without executing the tests it names is the
# failure shape this repository exists to prevent.
fixtures: ## Verify every fixture produces the verdict it declares
	$(GO) test ./internal/... -run 'TestFixtures' -count=1
	$(GO) test ./internal/... -run 'TestEveryTrapIsEitherFiredByAFixtureOrListed' -count=1

# Compiles corpus/*.yml -> corpus.json. The compiled corpus is a signed JSON
# bundle, not an embedded database: an embedded DB would need CGO or a
# third-party driver, either of which breaks ADR-001's single-static-binary /
# zero-dependency promise. No key required. `--compile` is the corpus-build CLI
# contract.
corpus: ## Compile corpus/*.yml -> corpus.json (unsigned)
	$(GO) run ./corpus-build --compile --out corpus.json

corpus-verify: ## Run every corpus validation rule (schema, citations, no-silent-upgrade)
	$(GO) run ./corpus-build --validate
	$(GO) test ./internal/... -run 'TestCorpusPredicatesTypecheck|TestConfidenceUpgradeRequiresCorrection' -count=1

# Verify the STAGED bundle with the shipped binary. This is the acceptance step
# for the corpus bundle, and it depends on `build` on purpose.
#
# The dependency is the whole point. `go build ./cmd/clearance` writes clearance.exe
# into this directory and carries NO -X public-key stamp, so building the main
# package after `make build` leaves behind a binary that refuses every bundle with
# E-INT-005, "no corpus public key embedded" — whose recovery text says
# "Reinstall" and sends the reader somewhere useless. Observed this session, and
# then measured: stamped 7,076,352 bytes / verify EXIT 0 against unstamped
# 10,160,640 bytes / verify EXIT 4.
#
# `go build ./...` is NOT the trigger, and an earlier version of this comment said
# it was. With more than one package Go discards the outputs, so the stamped
# binary survives; only a single-main-package build overwrites it.
#
# This is the sixth appearance of the stamp trap in this repository's history —
# four silent `-X` typos, then `TestEveryStampedSymbolExists`. The first five
# were fixed by making the stamp checkable. This one is fixed by making the
# order a dependency rather than a sentence in a runbook.
corpus-verify-bundle: build ## Verify corpus-dist/ with a freshly-built stamped binary
	CLEARANCE_CORPUS=corpus-dist ./$(BINARY)$(EXE) corpus verify

# The corpus release version, stamped into every verdict as `meta.corpus_version`.
#
# There is deliberately NO default, for the same reason CORPUS_KEY has no default
# path: a default is a decision nobody made. This used to be
# `$(shell date -u +%Y.%m.%d)`, which meant `make corpus-dist` silently stamped a
# version that no step had chosen. The consequences were quiet and real:
# the version bump was skippable, two bundles with
# *different* content built on the same day got the *same* version, and one
# unchanged bundle got a new version every day. A version that names content
# cannot be derived from the calendar.
#
# Bump it deliberately — PATCH for a correction, MINOR for a new licence, trap,
# ToS entry or obligation, MAJOR for a schema change. The corpus ships
# independently of the binary, so the version has to
# be readable on its own, away from any binary version beside it.
CORPUS_VERSION ?=

# Requires the OFFLINE Ed25519 key. NEVER run this in CI.
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
		echo "  Bump it deliberately: PATCH a correction, MINOR a new entry."; \
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

# NOTE: this is the only build that stamps the corpus public key. Building the
# main package directly — `go build ./cmd/clearance`, which is what a developer
# naturally types — writes the same filename into this directory WITHOUT the
# stamp, and a binary without it refuses every bundle with E-INT-005.
#
# Measured, so the next reader does not have to guess:
#   make build                -> 7,076,352 bytes, stripped, verify EXIT 0
#   go build ./cmd/clearance  -> 10,160,640 bytes, unstripped, verify EXIT 4
#   go build ./...            -> harmless: with multiple packages Go discards
#                                the outputs, and the stamped binary survives
#
# So the trigger is a single-main-package build, not `./...`. If you have built
# the main package since the last `make build`, re-run it before verifying a
# corpus — or just use `make corpus-verify-bundle`, which enforces the order.
build: ## Build the static host binary (CGO_ENABLED=0, -trimpath)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)$(EXE) ./cmd/clearance

release: ## Cross-compile the 6 release targets via goreleaser
	$(GORELEASER) release --clean

vulncheck: ## Run govulncheck on the module (pinned; see GOVULNCHECK above)
	$(GO) run $(GOVULNCHECK) ./...

# There is deliberately NO `conformance` target here.
#
# `make conformance` was specified, and the
# target existed — running `go test ./... -run TestConformance`. No such test
# was ever written, no `conformance/` directory exists, and corpus/fingerprints/
# is empty with nothing reading it. So the target printed `ok` and exited 0
# while running nothing at all, which is the failure mode this repository keeps
# rediscovering: a name in a build script is a claim, and nothing checks the
# claim unless a test does.
#
# It was removed rather than left failing. A target that always fails trains
# people to ignore `make`, which is how `make lint` stayed broken long enough
# for nobody to notice. The gap is tracked rather than hidden, and the target is
# restored when the vectors exist.

dogfood: build ## Run clearance check . on Clearance itself (must pass)
	./$(BINARY)$(EXE) check . --fail-on BLOCK

# Refuse to ship content that leaks internal planning. Reads the CONTENTS of
# every shipped file, not just its path, because the first push passed a path
# check and was wrong: the staged README.md was a planning overview — an
# internal roadmap and a commercial posture — not a product README. A path
# check sees a file named README.md; it does not read it.
#
# Run with no argument it scans the working tree, so a scrub can be verified
# before it is committed rather than discovered after it is pushed.
ship-check: ## Refuse to ship content that leaks the plan (contents, not paths)
	bash tools/check-ship-content.sh

bench: ## Run the benchmark suite
	$(GO) test ./... -run '^$$' -bench . -benchmem -count=1
