# Clearance — Makefile
# ---------------------------------------------------------------------------
# The target set is frozen. The ones a reader of the published repository can
# use are below; the maintainer-only ones — the corpus toolchain, `dogfood`,
# `ship-check` — are in tools/maintainer.mk, included at the bottom of this
# file when tools/ is present. The split is by dependency, not by taste: the
# header of that file says which dependency puts a target there.
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

# CI pins the exact release in .github/workflows/ci.yml
# (golangci/golangci-lint-action@v8, version: v2.14.0) and .golangci.yml is
# written for that v2 schema. Install that release rather than whatever
# `@latest` resolves to: a future schema would fail on this file's config, and
# a config failure reads like a code failure while telling you nothing about
# the code.
GOLANGCI_LINT ?= golangci-lint
GORELEASER    ?= goreleaser

# Pinned, on purpose. This was `@latest` and it stopped working: x/vuln@latest
# (v1.8.0) requires go >= 1.26.0, so `make vulncheck` failed on the tool rather
# than on the code, silently reporting nothing at all. That is the defect this
# repository keeps re-finding — a gate that cannot run is a gate that passes.
# v1.1.4 is verified to run on the toolchain this module targets (go.mod,
# go1.25.13). Moving the pin means re-running `make vulncheck`: the failure mode
# above is silent, so the pin is worth only what the last run proved.
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
.PHONY: help guard test lint arch fixtures build release vulncheck dogfood bench

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
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

# CORPUS_PUBKEY is passed through the environment because goreleaser's ldflags
# are its own: the LDFLAGS variable above reaches `go build`, and goreleaser
# never runs `go build` through this Makefile. That gap was the bug — `make
# build` stamped the corpus key and `make release` did not, so every archive the
# release pipeline produced carried the all-zero sentinel, refused every signed
# corpus with E-INT-005, and reported success. See .goreleaser.yml.
#
# The fail-closed check lives in the goreleaser `before.hooks`, not here, so a
# release run from CI is checked by the same code as one run by hand.
release: ## Cross-compile the 6 release targets via goreleaser
	CORPUS_PUBKEY='$(CORPUS_PUBKEY)' $(GORELEASER) release --clean

vulncheck: ## Run govulncheck on the module (pinned; see GOVULNCHECK above)
	$(GO) run $(GOVULNCHECK) ./...

# Dogfooding is the doctrine this project is built on — the tool must pass its
# own check honestly — and NOTICE says so. It is a PUBLIC target, and it was
# briefly moved into tools/maintainer.mk on the belief that `clearance check .`
# needs a signed bundle. It does not, and the belief was falsified by running it:
# with the corpus at `corpus/` unsigned, the scan completed and exited 0 with
# BLOCKERS: 0. Everything it needs ships — the corpus YAML, clearance.config.yml,
# and the binary this target builds.
#
# `--fail-on BLOCK` is the doctrine made checkable: a condition is acceptable, a
# blocker is not.
dogfood: build ## Run clearance check . on Clearance itself (must pass)
	./$(BINARY)$(EXE) check . --fail-on BLOCK

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

bench: ## Run the benchmark suite
	$(GO) test ./... -run '^$$' -bench . -benchmem -count=1

# ---------------------------------------------------------------------------
# The maintainer-only targets.
#
# `-include` ignores a missing file, which is exactly what the published
# distribution needs: it ships without tools/ and therefore without this
# fragment, and the Makefile above stays complete for everything a reader of the
# public repository can do.
#
# That same silence is how a typo would hide, so tools/ is the marker instead.
# Where tools/ is present — every maintainer checkout — the fragment is required,
# and its absence is a hard error rather than a Makefile that quietly lost eight
# targets. This is the same rule, with the same marker, as guardMaintainerPath in
# internal/guard_helpers_test.go.
# ---------------------------------------------------------------------------
ifneq ($(wildcard tools),)
ifeq ($(wildcard tools/maintainer.mk),)
$(error tools/ is present but tools/maintainer.mk is missing. This is the maintainer tree — the published distribution ships without tools/ at all — so the maintainer targets must be here. Restore the file, or remove tools/ if this really is a distribution.)
endif
endif
-include tools/maintainer.mk
